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
#include <boost/filesystem.hpp>
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

static set<uniqued_name>
get_names_depended_on(vector<allocsite>::const_iterator begin, vector<allocsite>::const_iterator end)
{
	set<uniqued_name> retval;
	for (auto i_a = begin; i_a != end; ++i_a)
	{
		auto& initial_t = i_a->found_type;
		walk_type(initial_t, iterator_base::END,
		[&retval](iterator_df<type_die> t, iterator_df<program_element_die> reason) -> bool {
			/* NOTE: we will get called for every type, including void.
			 * Our job is to decide whether we depend on this type,
			 * and whether we need to recurse. */
			if (reason.is_a<member_die>())
			{
				auto memb = reason.as_a<member_die>();
				if (memb->get_declaration() && *memb->get_declaration()
					 && memb->get_external() && *memb->get_external())
				{
					// static member vars don't get added nor recursed on
					return false;
				}
				assert(memb->get_type() != iterator_base::END);
				if (memb->get_type()->get_concrete_type() == t.parent().as_a<type_die>())
				{
					/* directly recursive type?! */
					assert(false);
				}
			}
			if (t && t != t->get_concrete_type()) return true; // don't add anything, but keep going
			// we need this one
			auto p = retval.insert(canonical_key_for_type(t));
			if (!p.second) return false; // we've already added it; stop now
			return true; // keep going
		});
	}
	return retval;
}

int main(int argc, char **argv)
{
	/* We open the file named by argv[1] and dump its DWARF types. */ 
	
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	boost::filesystem::path argv1(argv[1]);
	std::ifstream infstream(argv1.c_str());
	if (!infstream) 
	{
		cerr << "Could not open file " << argv1 << endl;
		exit(1);
	}
	
	if (getenv("ALLOCTYPES_DEBUG"))
	{
		debug_out = atoi(getenv("ALLOCTYPES_DEBUG"));
	}
	
	using core::root_die;
	int fd = fileno(infstream);
	shared_ptr<sticky_root_die> p_root = sticky_root_die::create(fd,
		argv1.is_absolute() ? argv1.string() : boost::filesystem::absolute(argv1).string());
	if (!p_root) { std::cerr << "Error opening file" << std::endl; return 1; }
	sticky_root_die& root = *p_root;
	
	/* Do we have an allocsites file for this object? If so, we incorporate its 
	 * synthetic data types. ALSO treat arr0 as synthetic (FIXME) */
	auto allocsites = read_allocsites_for_binary(argv1.string());
	//set< pair<string, string> > to_generate_array0;
	if (!allocsites) { cerr << "Error: no allocation sites for " << std::endl; return 1; }
	/* rewrite the allocsites we were passed */
	vector<iterator_df<type_die> > created_types = ensure_needed_types_and_assign_to_allocsites(root, *allocsites);
	cerr << "Processing " << allocsites->size() << " allocation sites." << endl;

	cout << "#include \"uniqtype-defs.h\"\n\n";
	/* Write any necessary forward declarations. That means
	 * anything that an emitted type might reference.
	 * This can include things we created, and things we didn't.
	 *  */
	set<uniqued_name> dependencies = get_names_depended_on(allocsites->begin(), allocsites->end());
	for (auto i_n = dependencies.begin(); i_n != dependencies.end(); ++i_n)
	{
		emit_extern_declaration(cout, *i_n, false);
	}
	master_relation_t needed;
	for (auto i_t = created_types.begin(); i_t != created_types.end(); ++i_t)
	{
		// we need to emit a uniqtype from the dwarfidl'd DIEs
		add_type_if_absent(*i_t, needed);
	}
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	write_master_relation(needed, std::cout, std::cerr,
		names_emitted, types_by_name,
		/* emit_codeless_aliases */ true,
		/* emit_subobject_names */ true);

	return 0;
}
