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
	optional<string> cu_name;
	optional<string> cu_comp_dir;
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	if (argc > 2 && strlen(argv[2]) > 0)
	{
		cu_name = argv[2];
	}
	if (argc > 3 && strlen(argv[3]) > 0)
	{
		cu_comp_dir = argv[3];
	}
	std::ifstream infstream(argv[1]);
	assert(infstream);
	using core::root_die;
	root_die r(fileno(infstream));
	
	/* We read things like  __uniqtype__signed_char, __uniqtype____PTR_signed_char
	 * 
	 * and rewrite them in language-independent form. 
	 * 
	 * Expanding all possible names of complex types (like function pointers with
	 * many args) becomes intractable. So instead, we focus on the fragments: 
	 * 
	 * for each base type in the DWARF, print out a pair
	 * <C name, canonical name>
	 * 
	 * and use this to grep for symbol names containing the C name.
	 */

	auto cu_seq = r.begin().children_here().subseq_of<compile_unit_die>();
	for (auto i_cu = cu_seq.first; i_cu != cu_seq.second; ++i_cu)
	{	
		// if we were passed a cu_name or comp_dir and they don't match, skip it
		if (cu_name && *i_cu->get_name() != *cu_name) continue;
		if (cu_comp_dir && i_cu->get_comp_dir()  && *i_cu->get_comp_dir() != *cu_comp_dir) continue;

		auto i_next_cu = i_cu; ++i_next_cu;

		for (iterator_df<> i = i_cu; i != i_next_cu; ++i)
		{
			if (i.is_a<base_type_die>() && i.name_here())
			{
				const char **equiv = abstract_c_compiler::get_equivalence_class_ptr(i.name_here()->c_str());

				if (equiv)
				{
					cout << mangle_string(equiv[0]) 
						<< "\t" 
						<< mangle_string(i.as_a<base_type_die>()->get_canonical_name())
						<< endl;
				}

			}
		}
	}
	return 0;
}
