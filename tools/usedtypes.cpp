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
using dwarf::core::base_type_die;
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
	/* First we look through the whole file and index its types by their *codeless*
	 * *canonical* uniqtype name, i.e. we blank out the first element of the name pair. */
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
				uniqtype_name_pair = canonical_key_from_type(t);
			}

			/* CIL/trumptr will only generate references to aliases in the case of 
			 * base types. We need to handle these here. What should happen? 
			 * 
			 * - we will see references looking like __uniqtype__signed_char
			 * - we want to link in two things:
			 *    1. the nameless __uniqtype_<code>_ definition of this base type
			 *    2. the alias    __uniqtype_<code>_signed_char from the usual alias handling
			 * - we do this by indexing all our types by a *codeless* version of their
			 *   name, then matching our inputs lines against that.
			 * - the input lines will have signed_char instead of ""
			 * - ... so that's what we need to put in our index.
			 * */
			
			string canonical_or_base_typename = uniqtype_name_pair.second;
			if (canonical_or_base_typename == "")
			{
				assert(concrete_t.is_a<base_type_die>());
				// if the base type has no name, this DWARF type is useless to us
				if (!concrete_t.name_here()) continue;
				canonical_or_base_typename = *concrete_t.name_here();
			}
			string codeless_symname = mangle_typename(make_pair("", canonical_or_base_typename));

			types_by_uniqtype_name.insert(make_pair(codeless_symname, concrete_t));

			/* Special handling for base types: also add them by the name in which they 
			 * appear in the DWARF, *and* by their C-canonical name. Our CIL frontend
			 * doesn't know the exact bit-widths so must use the latter. */
			if (concrete_t.is_a<base_type_die>() && concrete_t.name_here())
			{
				types_by_uniqtype_name.insert(
					make_pair(
						mangle_typename(make_pair("", *concrete_t.name_here())), 
						concrete_t
					)
				);
				const char **equiv = abstract_c_compiler::get_equivalence_class_ptr(concrete_t.name_here()->c_str());
				if (equiv)
				{
					types_by_uniqtype_name.insert(
						make_pair(
							mangle_typename(make_pair("", equiv[0])), 
							concrete_t
						)
					);
				}
			}
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
	multimap<string, pair<string, string> > aliases_needed;
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
				 * and "specified as no parameters" e.g. int f(void).
				 * 
				 * This will ensure that some type gets emitted, such that we
				 * can bind up the UNDefined uniqtype to it. 
				 * BUT
				 * We will emit it under its rightful name, so the reference
				 * won't get bound just like that. Previously we dealt with
				 * this by creating an alias, but in fact we need to emit
				 * the uniqtype *again* under the correct section name. 
				 * Otherwise the name we want might get eliminated by COMDAT
				 * if a non-worked-around section appears in the same link.
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
							
							string orig_substitute_key = substitute_key;
							
							substitute_key.replace(0, string("__uniqtype_").size(), "__uniqtype_" + name_pair.first);
							
							string orig_key_symname = key;
							orig_key_symname.replace(0, string("__uniqtype_").size(), "__uniqtype_" + name_pair.first);
							
							aliases_needed.insert(make_pair(orig_key_symname, make_pair(orig_substitute_key, substitute_key)));
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
					cerr << "\t" << (found_pair.first++)->second << " (code: " 
						<< summary_code_to_string(code) 
						<< ")" << endl;
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
			// end case default
		}
	
	continue_loop:
		free(line);
		line = NULL;
	}
	
	fclose(in);

	// write the types to stdout
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	map< iterator_df<type_die>, set<string> > names_by_type;
	write_master_relation(master_relation, r, cout, cerr, false /* emit_void */, true, 
		names_emitted, types_by_name);
	
	// for CIL workaround: for each alias, write a one-element master relation
	// defining it under the alias name (do *not* use the other name at all!)
	for (auto i_pair = aliases_needed.begin(); i_pair != aliases_needed.end(); ++i_pair)
	{
		//cout << "extern struct rec " << i_pair->first << " __attribute__((alias(\"" << i_pair->second << "\")));"
		// 	<< endl;
		
		// i_pair is (orig_key_symname, (orig_substitute_key, substitute_key_with_typecode))
		// and we need to look up in types_by_uniqtype_name by orig_substitute_key
		
		auto found = types_by_uniqtype_name.equal_range(i_pair->second.first);
		assert(found.first != found.second || (cerr << i_pair->second.first << endl, false));
		
		master_relation_t tmp_master_relation;
		string unmangled_name = i_pair->first;
		unmangled_name.replace(0, string("__uniqtype_........_").size(), "");
		string insert = i_pair->first.substr(string("__uniqtype_").size(), 8);
		tmp_master_relation.insert(make_pair(make_pair(insert, unmangled_name), found.first->second));
		
		set<string> tmp_names_emitted;
		map<string, set< iterator_df<type_die> > > tmp_types_by_name;
		write_master_relation(tmp_master_relation, r, cout, cerr, false /* emit_void */, false, 
			tmp_names_emitted, tmp_types_by_name);
	}

	return 0;
}
