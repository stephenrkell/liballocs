/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <memory>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
// #include <regex> // broken in GNU libstdc++!
//#include <boost/filesystem.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <fileno.hpp>

#include "helpers.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::multimap;
using std::ios;
using std::ifstream;
using std::unique_ptr;
using boost::optional;
using std::ostringstream;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::root_die;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::pointer_type_die;
using dwarf::tool::abstract_c_compiler;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

int main(int argc, char **argv)
{
	/* We read from stdin lines such as those output by dumpallocs,
	 * prefixed by their filename. Actually they will have been 
	 * stored in .allocsites files. */ 
	std::shared_ptr<ifstream> p_in;
	if (argc > 1) 
	{
		p_in = std::make_shared<ifstream>(argv[1]);
		if (!*p_in) 
		{
			cerr << "Could not open file " << argv[1] << endl;
			return 1;
		}
	}
	std::istream& in = p_in ? *p_in : cin;
	
	allocsites_relation_t allocsites_relation;
	
	/* We want the helper to make a root_die for us, based on the first 
	 * allocsite. How? Read them all, then merge the synthetics and 
	 * rewrite. */
	vector<allocsite> allocsites_to_add = read_allocsites(in);
	cerr << "Found " << allocsites_to_add.size() << " allocation sites" << endl;
	unique_ptr<root_die> p_root;

	if (allocsites_to_add.size() > 0)
	{
		pair< unique_ptr<root_die>, unique_ptr<ifstream> > pair = make_root_die_and_merge_synthetics(allocsites_to_add);
		unique_ptr<root_die> p_root = std::move(pair.first);
		
		multimap<string, iterator_df<type_die> > types_by_codeless_name;
		get_types_by_codeless_uniqtype_name(types_by_codeless_name,
			p_root->begin(), p_root->end());
		
		make_allocsites_relation(allocsites_relation, allocsites_to_add, types_by_codeless_name, *p_root);
	}	
	
	// FIXME: make this configurable. Right now we don't need it -- dumptypes has done it
#if 0
	cout << "struct allocsite_entry\n\
{ \n\
	void *next; \n\
	void *prev; \n\
	void *allocsite; \n\
	struct uniqtype *uniqtype; \n\
};\n";
#endif

	// extern-declare the uniqtypes
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		if (i_site->second.second /* declare as array */)
		{
			pair<string, string> array_name =
				make_pair(string(""), string("__ARR_") + i_site->second.first.second);
			cout << "extern struct uniqtype " << mangle_typename(array_name) << ";" << endl;
		}
		else
		{
			cout << "extern struct uniqtype " << mangle_typename(i_site->second.first) << ";" << endl;
		}
	}

	cout << "struct allocsite_entry allocsites[] = {" << endl;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		if (i_site != allocsites_relation.begin()) cout << ",";
		
		cout << "\n\t/* allocsite info for " << i_site->first.first << "+"
			<< std::hex << "0x" << i_site->first.second << std::dec << " */";
		cout << "\n\t{ (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + 0x" << std::hex << i_site->first.second << std::dec << "UL, " 
			<< "&";
		
		if (i_site->second.second /* declare as array */)
		{
			pair<string, string> array_name =
				make_pair(string(""), string("__ARR_") + i_site->second.first.second);
			cout << mangle_typename(array_name);
		}
		else
		{
			cout << mangle_typename(i_site->second.first);
		}
		cout << " }";
	}
	// output a null terminator entry
	if (allocsites_relation.size() > 0) cout << ",";
	cout << "\n\t{ (void*)0, (void*)0, (void*)0, (struct uniqtype *)0 }";
	
	// close the list
	cout << "\n};\n";
	
	return 0;
}	
