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
	 * stored in .allocs files. */
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
	vector<allocsite> allocsites = read_allocsites(in);
	cerr << "Found " << allocsites.size() << " allocation sites" << endl;
	if (allocsites.size() == 0) return 0;
	/* HACK: get the objname from the first entry; we assume it's the same for all entries. */
	string seen_objname = allocsites.begin()->objname;
	auto p_objfile = std::unique_ptr<std::ifstream>(new std::ifstream(seen_objname));
	if (!*p_objfile) { cerr << "Could not open "<< seen_objname << std::endl; return 1; }
	unique_ptr<root_die> p_root = std::unique_ptr<root_die>(new root_die(fileno(*p_objfile)));
	assert(p_root);
	/* rewrite the allocsites we were passed */
	vector<iterator_df<type_die>> types_created
	 = ensure_needed_types_and_assign_to_allocsites(*p_root, allocsites);
	std::sort(allocsites.begin(), allocsites.end(), [](const allocsite& a1, const allocsite& a2) {
		return make_pair(a1.objname, a1.file_addr) < make_pair(a2.objname, a2.file_addr);
	});
	cout << "#include \"allocmeta-defs.h\"\n\n";
	// extern-declare the uniqtypes as weak! we might still want typeless alloc site info
	for (auto i_a = allocsites.begin(); i_a != allocsites.end(); ++i_a)
	{
		emit_extern_declaration(cout, initial_key_for_type(i_a->found_type), true);
	}
	cout << "struct allocsite_entry allocsites[] = {" << endl;
	for (auto i_a = allocsites.begin(); i_a != allocsites.end(); ++i_a)
	{
		if (i_a != allocsites.begin()) cout << ",";
		
		cout << "\n\t/* allocsite info for " << i_a->objname << "+"
			<< std::hex << "0x" << i_a->file_addr << std::dec << " */";
		cout << "\n\t{ 0x" << std::hex << i_a->file_addr << std::dec << "UL, "
			<< "&" << mangle_typename(initial_key_for_type(i_a->found_type));
		cout << " }";
	}
	// close the list
	cout << "\n};\n";
	return 0;
}	
