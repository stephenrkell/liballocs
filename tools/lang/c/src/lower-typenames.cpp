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

//#include <allocs/uniqtypes.hpp>
#include "uniqtypes.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::ios;
using std::ifstream;
using std::dynamic_pointer_cast;
using boost::optional;
using std::ostringstream;
using std::set;
using std::pair;
using std::make_pair;
using std::multimap;
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
using dwarf::core::base_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;
using dwarf::core::subroutine_type_die;
using dwarf::core::formal_parameter_die;

using dwarf::lib::Dwarf_Off;
using dwarf::tool::abstract_c_compiler;

using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;


int main(int argc, char **argv)
{
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	std::ifstream infstream(argv[1]);
	using core::root_die;
	root_die r(fileno(infstream));
	
	/* We read things like  __uniqtype__signed_char, __uniqtype____PTR_signed_char
	 * 
	 * and rewrite them in language-independent form. 
	 * 
	 * First build a map of all names of all types that we might see. 
	 * Then look up the names as they come in, and write them out with their *canonical*
	 * name.
	 * 
	 * Note that the "list of all names" is all the *possible* names, not all the 
	 * aliases we're actually committing to generating. 
	 * 
	 * Note also that currently, this is completely language-independent! 
	 * The C-specific twist that we add is to expand all the base type synonyms too. 
	 * HOW can we adapt the code in helpers.cpp 
	 */
	
	multimap<string, iterator_df<type_die> > types_by_name;
	map<string, iterator_df<type_die> > types_by_canonical_name;
	map<string, string> canonical_names_by_name;
	
	struct all_names_for_type_including_c_synonyms_t : all_names_for_type_t
	{
		all_names_for_type_including_c_synonyms_t()
		{
			auto super = base_type_case;
			base_type_case = [super](iterator_df<base_type_die> base_t) -> deque<string> {
				deque<string> l = super(base_t);
				// append any absent synonyms from the C type equivalence class
				const char **equiv_class = nullptr;
				set<string> c_synonyms; // things in the equiv class *and* in l
				for (auto i_l = l.begin(); i_l != l.end(); ++i_l)
				{
					const char **cur_equiv_class
					 = abstract_c_compiler::get_equivalence_class_ptr(i_l->c_str());
					if (cur_equiv_class)
					{
						// assert that we only see the same equivalence class
						assert(!equiv_class || cur_equiv_class == equiv_class);
						if (!equiv_class) equiv_class = cur_equiv_class;
						c_synonyms.insert(*i_l);
					}
				}
				if (equiv_class)
				{
					// add the things in the equiv class and not in l
					for (const char **i_equiv = equiv_class; 
						*i_equiv != NULL;
						++i_equiv)
					{
						if (std::find(l.begin(), l.end(), *i_equiv) == l.end())
						{
							l.push_back(*i_equiv);
							break; // HACK: after adding one thing!
							// this is because the space gets very very large
						}
					}
				}
				
				return l;
			};
		}
	
	} all_names_for_type_including_c_synonyms;
	
	/* Read each type and record its names. */
	for (iterator_df<> i = r.begin(); i != r.end(); ++i)
	{
		if (i.is_a<type_die>())
		{
			auto t = i.as_a<type_die>();
			deque<string> all_names = all_names_for_type_including_c_synonyms(t);
			
			cerr << "Names for type " << *i << ": " << endl;
			assert(all_names.size() > 0);
			string canonical_name = mangle_string(*all_names.begin());
			for (auto i_name = all_names.begin(); i_name != all_names.end(); ++i_name)
			{
				if (i_name != all_names.begin()) cerr << ", "; else cerr << "(canonical) ";
				cerr << mangle_string(*i_name);
				types_by_name.insert(make_pair(mangle_string(*i_name), t));
				canonical_names_by_name.insert(make_pair(mangle_string(*i_name), canonical_name));
			}
			cerr << endl;

			if (t && t == t->get_concrete_type())
			{
				auto ret = types_by_canonical_name.insert(make_pair(canonical_name, t));
				// assert that a new element was inserted
				// BUT in the case of base types or their compounds, we might get multiples
				if (!ret.second)
				{
					cerr << "Warning: duplicate canonical type (" << canonical_name << ") " 
						<< t->summary()
						<< " (first seen was " << ret.first->second->summary()
						<< ")" << endl;
				}
			}
		}
	}
	
	/* Read typenames from the file and print their canonical names. */
	// FIXME: escape single quotes
	FILE *in = popen((string("nm -fposix -u '") + argv[1]
	 + "' | sed -r 's/[[:blank:]]*U[[:blank:]]*$//' | grep __uniqtype__ | sed 's/__uniqtype__//'").c_str(), "r");
	assert(in);
	
	int ret;
	char *line = NULL;
	size_t line_len;
	/* Now popen our input, read lines and match them against the map we just built. */
	while (ret = getline(&line, &line_len, in), ret > 0)
	{
		string key(line);
		// trim the newline, if any
		boost::trim(key);
		auto found_pair = types_by_name.equal_range(key);
		unsigned found_count = srk31::count(found_pair.first, found_pair.second);
		
		switch (found_count)
		{
			case 0:
				cerr << "Found no match for " << key << endl;
				cerr << "Defined are: ";
				for (auto i_tname = types_by_name.begin(); i_tname != types_by_name.end(); ++i_tname)
				{
					if (i_tname != types_by_name.begin()) cerr << ", ";
					cerr << i_tname->first;
				}
				cerr << endl;
				exit(1);
				break;
			print_it:
			case 1: 
				assert(canonical_names_by_name.find(found_pair.first->first) != canonical_names_by_name.end());
				cout << key << "\t" << canonical_names_by_name[found_pair.first->first] << endl;
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
					goto print_it;
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

	return 0;
}
