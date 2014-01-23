#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/icl/interval_map.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <cxxgen/tokens.hpp>
#include <cxxgen/cxx_compiler.hpp>
#include <dwarfpp/lib.hpp>
#include <fileno.hpp>

#include "helpers.hpp"
#include "uniqtypes.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::multimap;
using std::make_shared;
using std::ios;
using std::ifstream;
using std::dynamic_pointer_cast;
using boost::optional;
using std::ostringstream;
using std::set;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::member_die;
using dwarf::core::with_data_members_die;
using dwarf::core::variable_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;

using dwarf::lib::Dwarf_Off;

using dwarf::tool::abstract_c_compiler;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

static int debug_out = 1;

int main(int argc, char **argv)
{
	/* From stdin we read a sequence of symbol names that have been output by 
	 * the following OCaml code. 
            let symnameFromString s ts = begin
                let rec definingFile t = match t with 
                  TSComp(isSpecial, name, attrs) -> begin try
                      let l = NamedTypeMap.find name !namedTypesMap in l.file 
                      with Not_found -> output_string Pervasives.stderr ("missing decl for " ^ name ^ "\n"); "" (* raise Not_found *)
                  end
                | TSEnum(name, attrs) -> begin try
                      let l = NamedTypeMap.find name !namedTypesMap in l.file 
                      with Not_found -> output_string Pervasives.stderr ("missing decl for " ^ name ^ "\n"); "" (* raise Not_found *)
                  end
                | TSPtr(tsig, attrs) -> definingFile tsig
                | _ -> ""
                in
                let defining_filestr = definingFile ts
                in 
                let header_insert = Str.global_replace (Str.regexp "[. /-]") "_" defining_filestr in
                let ptr_replaced = Str.global_replace (Str.regexp "\\^") "__PTR_"  (Str.global_replace (Str.regexp "[. /-]") "_" s) in
                (* HACK: using escaped brackets in the regexp doesn't seem to work for replacing, 
                   so just use two dots. Will need to change this if we start to include function
                   argument types in function typestrings. *)
                let ptr_and_fun_replaced = Str.global_replace (Str.regexp "..=>") "__FUN_" ptr_replaced in
                "__uniqtype_" ^ "" ^ "_" ^ ptr_and_fun_replaced
              end in
              let symname = symnameFromString typeStr concreteType in
	 
	   We need to look through the DWARF types in the object file, 
	   generating and emitting the corresponding uniqtype record in each case, 
	   then running the compiler/linker/objcopy to 
	   - compile the emitted uniqtype record into a temporary .o file
	   - *rename* the referenced uniqtype into the actual one used (i.e. with the infix code)
	   - define and localise the original symbol name along the way
	   
	   cc -c -o /tmp/....o generated.c 
	   objcopy --redefine-sym blah file.o
	   ld -r -o file.o file.o /tmp/....o
	   
	   CHECK that the old symname is no longer present after redefine-sym!
	   
	*/
	
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	std::ifstream infstream(argv[1]);
	if (!infstream) 
	{
		cerr << "Could not open file " << argv[1] << endl;
		exit(1);
	}
	
	if (getenv("DUMPTYPES_DEBUG"))
	{
		debug_out = atoi(getenv("DUMPTYPES_DEBUG"));
	}
	
	using core::root_die;

	root_die r(fileno(infstream));
	
	multimap<string, iterator_df<type_die> > types_by_uniqtype_name;
	/* First we look through the whole file and index its types by their uniqtype name. */
	for (iterator_df<> i = r.begin(); i != r.end(); ++i)
	{
		if (i.is_a<type_die>())
		{
			opt<string> opt_name = i.name_here(); // for debugging
			if (opt_name)
			{
				string name = *opt_name;
				assert(name != "");
			}
			
			auto t = i.as_a<type_die>();
			assert(t.is_real_die_position());
			auto concrete_t = t->get_concrete_type();
			pair<string, string> uniqtype_name_pair;
			
			// handle void case specially
			if (!concrete_t.is_real_die_position())
			{
				uniqtype_name_pair = make_pair("", "void");
			}
			else
			{
				uniqtype_name_pair = key_from_type(t);
			}
			
			auto symname = mangle_typename(make_pair("", uniqtype_name_pair.second));

			types_by_uniqtype_name.insert(make_pair(symname, concrete_t));
			
// 			/* Also add aliases? NO. Our CIL shouldn't generate these. */
// 			for (const char **const *p_equiv = &abstract_c_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
// 			{
// 				for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
// 				{
// 					if (uniqtype_name_pair.second == string(*p_el))
// 					{
// 						/* We've matched an element in the equivalence class, so
// 						 * - add one multimap entry for every *other* item; 
// 						 * - quit the loop. */
// 						 
// 						for (const char **p_other_el = p_equiv[0]; *p_other_el != NULL; ++p_other_el)
// 						{
// 							if (string(*p_other_el) == string(*p_el)) continue;
// 							
// 							types_by_uniqtype_name.insert(
// 								make_pair(
// 									mangle_typename(make_pair("", string(*p_other_el))),
// 									concrete_t
// 								)
// 							);
// 						}
// 						
// 						// quit this loop
// 						break;
// 					}
// 				}
// 			}
		}
	}
	
	// FIXME: escape single quotes
	FILE *in = popen((string("nm -fposix -u '") + argv[1]
	 + "' | sed -r 's/[[:blank:]]*U[[:blank:]]*$//' | grep __uniqtype").c_str(), "r");
	assert(in);
	
	int ret;
	char *line = NULL;
	size_t line_len;
	/* Now popen our input, read lines and match them against the map we just built. */
	master_relation_t master_relation;
	multimap<string, string> aliases_needed;
	while (ret = getline(&line, &line_len, in), ret > 0)
	{
		string key(line);
		// trim the newline, if any
		boost::trim(key);
		auto found_pair = types_by_uniqtype_name.equal_range(key);
		unsigned found_count = srk31::count(found_pair.first, found_pair.second);
		
		switch (found_count)
		{
			case 0:
				cerr << "Found no match for " << key << endl;
				/* HACK around CIL brokenness: if we contain the string 
				 *     "__FUN_FROM___FUN_TO_" 
				 * then match against
				 *     "__FUN_FROM___VA___FUN_TO_" 
				 * since CIL typesigs don't distinguish between 
				 * "no specified parameters"        e.g. int f() 
				 * and "specified as no parameters" e.g. int f(void)
				  */
				{
					string search_expr = "__FUN_FROM___FUN_TO_";
					string replace_expr = "__FUN_FROM___VA___FUN_TO_";
					string::size_type pos = key.find(search_expr);
					if (pos != string::npos)
					{
						string substitute_key = key;
						substitute_key.replace(pos, search_expr.size(), replace_expr);
						
						auto found_retry_pair = types_by_uniqtype_name.equal_range(substitute_key);
						if (found_retry_pair.first != found_retry_pair.second)
						{
							cerr << "Working around CIL bug by substituting " << substitute_key << endl;
							auto name_pair = transitively_add_type(found_retry_pair.first->second, master_relation).second;
							
							substitute_key.replace(0, string("__uniqtype_").size(), "__uniqtype_" + name_pair.first);
							string orig_key_symname = key;
							orig_key_symname.replace(0, string("__uniqtype_").size(), "__uniqtype_" + name_pair.first);
							
							aliases_needed.insert(make_pair(orig_key_symname, substitute_key));
							break;
						}
					}
				}
				cerr << "Defined are: ";
				for (auto i_tname = types_by_uniqtype_name.begin(); i_tname != types_by_uniqtype_name.end(); ++i_tname)
				{
					if (i_tname != types_by_uniqtype_name.begin()) cerr << ", ";
					cerr << i_tname->first;
				}
				cerr << endl;
				exit(1);
				break;
			case 1: 
				// cout << "Found match for " << key << ": " << found_pair.first->second << endl;
				transitively_add_type(found_pair.first->second, master_relation);
				break;
			
			default: 
				cerr << "Found multiple matches (" << found_count << ") for " << key << ": " << endl;
				auto first_found = found_pair.first;
				multimap<unsigned, decltype(found_pair.first)> by_code;
				while (found_pair.first != found_pair.second)
				{
					auto code = type_summary_code(found_pair.first->second);
					by_code.insert(make_pair(code, found_pair.first));
					cerr << "\t" << (found_pair.first++)->second << " (code: " << code << ")" << endl;
				}
				/* Do they all seem to be identical? */
				auto range_equal_to_first = by_code.equal_range(type_summary_code(first_found->second));
				if (srk31::count(range_equal_to_first.first, range_equal_to_first.second))
				{
					cerr << "They all seem to be identical (code " << type_summary_code(first_found->second) 
						<< ") so proceeding." << endl;
					transitively_add_type(first_found->second, master_relation);
				}
				else 
				{
					cerr << "Not identical, so not proceeding." << endl;
					exit(1);
				}
		}
	
	continue_loop:
		free(line);
		line = NULL;
	}
	
	fclose(in);

	// write the types to stdout
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	write_master_relation(master_relation, r, cout, cerr, false /* emit_void */, 
		names_emitted, types_by_name);
	
	// also write the aliases, for CIL workaround;
	for (auto i_pair = aliases_needed.begin(); i_pair != aliases_needed.end(); ++i_pair)
	{
		cout << "extern struct rec " << i_pair->first << " __attribute__((alias(\"" << i_pair->second << "\")));"
			<< endl;
	}

	return 0;
}
