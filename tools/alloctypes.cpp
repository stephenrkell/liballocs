/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */
 
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
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <cxxgen/tokens.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/frame.hpp>
#include <dwarfpp/regs.hpp>
#include <fileno.hpp>

#include "stickyroot.hpp"
#include "uniqtypes.hpp"
#include "allocsites-info.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
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
using dwarf::core::program_element_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;

using namespace dwarf::lib;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

static int debug_out = 1;

using dwarf::lib::Dwarf_Off;
using dwarf::lib::Dwarf_Addr;
using dwarf::lib::Dwarf_Signed;
using dwarf::lib::Dwarf_Unsigned;

using namespace allocs::tool;

int main(int argc, char **argv)
{
	/* We open the file named by argv[1] and dump its DWARF types. */ 
	
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
	
	if (getenv("ALLOCTYPES_DEBUG"))
	{
		debug_out = atoi(getenv("ALLOCTYPES_DEBUG"));
	}
	
	using core::root_die;
	int fd = fileno(infstream);
	shared_ptr<sticky_root_die> p_root = sticky_root_die::create(fd);
	if (!p_root) { std::cerr << "Error opening file" << std::endl; return 1; }
	sticky_root_die& root = *p_root;
	assert(&root.get_frame_section());
	
	/* Do we have an allocsites file for this object? If so, we incorporate its 
	 * synthetic data types. */
	auto allocsites = read_allocsites_for_binary(argv[1]);
	allocsites_relation_t allocsites_relation;
	multimap<string, iterator_df<type_die> > types_by_codeless_name;
	//set< pair<string, string> > to_generate_array0;
	if (allocsites)
	{
		/* rewrite the allocsites we were passed */
		merge_and_rewrite_synthetic_data_types(root, *allocsites);
	}
	get_types_by_codeless_uniqtype_name(types_by_codeless_name,
		root.begin(), root.end());
	if (allocsites)
	{
		make_allocsites_relation(allocsites_relation, *allocsites, types_by_codeless_name, root);
		cerr << "Allocsites relation contains " << allocsites_relation.size() << " data types." << endl;
	}

	cout << "#include \"uniqtype-defs.h\"\n\n";
	// write a forward declaration for every uniqtype we need
	set<string> names_emitted;
	/* As a pre-pass, remember any ARR names we need. These need special handling,
	 * as flexible arrays with their make_precise members set. */
	map<string, pair<string, string> > arr0_needed_by_allocsites;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		auto objname = i_site->second.first.first;
		auto file_addr = i_site->second.first.second;
		string element_name_used_code = i_site->second.first.first;
		string element_name_used_ident = i_site->second.first.second;
		bool declare_as_array0 = DECLARE_AS_ARRAY0(i_site->second.second);
		
		if (declare_as_array0)
		{
			/* Remember for later that we need to actually define the __ARR_ type. */
			string element_mangled_name = mangle_typename(make_pair(element_name_used_code, element_name_used_ident));
			cout << "/* Allocation site type needed: ARR of " 
				<< element_mangled_name
				<< " */" << endl;
			
			string codeless_array_name = string("__ARR_") + element_name_used_ident;
			string mangled_codeless_array_name
			 = mangle_typename(make_pair(string(""), codeless_array_name));
			arr0_needed_by_allocsites.insert(
				make_pair(mangled_codeless_array_name, 
					make_pair(element_mangled_name, codeless_array_name)
				)
			);
			
			// /* forward-declare it right now; we'll define it after everything else */
			// cout << "extern struct uniqtype " << mangled_codeless_array_name << ";" << endl;
			// /* pretend we've already emitted it... */
			// names_emitted.insert(mangled_codeless_array_name);
		}
		// always extern-declare the element type
		cout << "extern struct uniqtype " << mangle_typename(i_site->second.first) << ";" << endl;

		// FIXME: the synthetic ones  actually need emitting.
		if (i_site->second.second.is_synthetic)
		{
			// oh dear. how do we get the DWARF type?
			// we need to emit a uniqtype from the dwarfidl'd DIEs
			cerr << "Warning: (FIXME) not passed any DWARF info for synthetic alloc type "
				<< mangle_typename(i_site->second.first) << endl;
		}
	}

	// now write those pesky ARR ones -- any that we didn't emit earlier
	for (auto i_mangled_name = arr0_needed_by_allocsites.begin();
		i_mangled_name != arr0_needed_by_allocsites.end();
		++i_mangled_name)
	{
		const string& mangled_codeless_array_name = i_mangled_name->first;
		const string& element_mangled_name = i_mangled_name->second.first;
		const string& codeless_array_name = i_mangled_name->second.second;
		if (names_emitted.find(mangled_codeless_array_name) == names_emitted.end())
		{
			write_uniqtype_section_decl(cout, mangled_codeless_array_name);
			write_uniqtype_open_flex_array(cout,
				mangled_codeless_array_name,
				/* array_codeless_name.second */ i_mangled_name->second.second
			);
			write_uniqtype_related_array_element_type(cout,
				i_mangled_name->second.first // i.e. the element type
			);
			write_uniqtype_close(cout, mangled_codeless_array_name);
		}
	}
	
	cerr << "Allocsites relation has " << allocsites_relation.size() << " members." << endl;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		auto objname = i_site->second.first.first;
		auto file_addr = i_site->second.first.second;
		string name_used_code = i_site->second.first.first;
		string name_used_ident = i_site->second.first.second;
		auto& alloc = i_site->second.second;
		bool declare_as_array0 = DECLARE_AS_ARRAY0(i_site->second.second);

		if (!declare_as_array0)
		{
			cout << "/* Allocation site type not needing ARR type: " 
				<< i_site->second.first.second
				<< " */" << endl;
		}
		else cout << "/* We should have emitted a type of this name earlier: "
			<< name_used_ident << " */" << endl;
	}

	return 0;
}
