#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <memory>
#include <utility>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>
// #include <regex> // broken in GNU libstdc++!
//#include <boost/filesystem.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <fileno.hpp>

#include "allocsites-info.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::map;
using std::multimap;
using std::ios;
using std::ifstream;
using std::unique_ptr;
using std::pair;
using std::make_pair;
using std::vector;
using boost::optional;
using std::ostringstream;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

using namespace allocs::tool;

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

	cout << "#include \"allocmeta-defs.h\"\n\n";

	// extern-declare the uniqtypes as weak! we might still want typeless alloc site info
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
			cout << "extern struct uniqtype " << mangle_typename(i_site->second.first) << " __attribute__((weak));" << endl;
		}
	}

	cout << "struct allocsite_entry allocsites[] = {" << endl;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		if (i_site != allocsites_relation.begin()) cout << ",";
		
		cout << "\n\t/* allocsite info for " << i_site->first.first << "+"
			<< std::hex << "0x" << i_site->first.second << std::dec << " */";
		cout << "\n\t{ 0x" << std::hex << i_site->first.second << std::dec << "UL, " 
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
	// close the list
	cout << "\n};\n";
	
	return 0;
}	
