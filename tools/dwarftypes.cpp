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

/* At a high level, what we do is simply output a uniqtype for every
 * DWARF type we find. However, it's not actually quite that simple.
 * We sometimes emit types that are not really in the DWARF, such as
 * signedness complements.
 * And we sometimes want to refer to types that we won't emit,
 * for example, the type of void.
 * We rely on these being included in the -roottypes.o that is
 * also linked in.
 * To avoid complexity from tracking whether we have or haven't
 * emitted a thing we depend on,
 * what order things are emitted,
 * and also to avoid hard prevention of emitting something twice,
 * we do the following.
 * 
 * 1. anything that we reference, extern-declare before we reference
 *    it.
 * 2. anything we define, #ifdef-protect it so that if it's already
 *    defined, we don't define it again.
 *
 * So far, so standard. For signedness complements, we use a quick
 * check of which complements we reference, and then when we get to
 * the end, output any we haven't output yet.
 * For codeless aliases, we run a shell script over the combined metadata
 * output afterwards, and ld -r --defsym the aliases into existence.
 * That's all done in Makefile.meta. */

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
	
	if (getenv("DWARFTYPES_DEBUG"))
	{
		debug_out = atoi(getenv("DWARFTYPES_DEBUG"));
	}
	
	using core::root_die;
	int fd = fileno(infstream);
	shared_ptr<sticky_root_die> p_root = sticky_root_die::create(fd);
	if (!p_root) { std::cerr << "Error opening file" << std::endl; return 1; }
	sticky_root_die& root = *p_root;
	assert(&root.get_frame_section());
	master_relation_t master_relation;
	make_exhaustive_master_relation(master_relation, root.begin(), root.end());
	cerr << "Master relation contains " << master_relation.size() << " data types." << endl;
	// write a forward declaration for every uniqtype we need
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	cout << "#include \"uniqtype-defs.h\"\n\n";
	write_master_relation(master_relation, cout, cerr,
		names_emitted, types_by_name, /* emit_codeless_alises */ true);
	// HACK: we emit codeless aliases here, but better if it were a wrapper shell
	// script on the -meta.so afterwards, because types don't only come from dwarftypes.

	// success! 
	return 0;
}
