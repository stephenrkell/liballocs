/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */

#include <fcntl.h>
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
	dwarf::core::in_memory_root_die root;
	auto dummy_cu = root.make_new(root.begin(), DW_TAG_compile_unit);

	if (getenv("PERVASIVE_TYPES_DEBUG"))
	{
		debug_out = atoi(getenv("PERVASIVE_TYPES_DEBUG"));
	}

	/* Ensure we have all the things we need in the DWARF.
	 * We need to output
	 * - void
	 * - uninterpreted byte
	 * - generic pointer
	 * - unbounded array of uninterpreted_byte
	 */
	iterator_df<type_die> uninterpreted_byte_t = get_or_create_uninterpreted_byte_type(root);
	iterator_df<type_die> generic_pointer_t = get_or_create_generic_pointer_type(root);
	iterator_df<type_die> array_of_uninterpreted_byte_t
	 = get_or_create_array_of_uninterpreted_byte_type(root);
	master_relation_t pervasives_master_relation;
	add_type(uninterpreted_byte_t, pervasives_master_relation);
	//add_type(generic_pointer_t, pervasives_master_relation);
	// we have to do a hacked add-type to set the name
	// We also need to ensure it comes out generic. We have hacked
	// uniqtypes.cpp so that this happens, but a nicer solution would
	// be better. Our old hand-written version also had only one related[] entry,
	// and used __liballocs_make_precise_identity as the make_precise, but
	// I'm not sure why
	uniqued_name n = canonical_key_for_type(generic_pointer_t);
	n.second = "__EXISTS1___PTR__1";
	pervasives_master_relation[n] = generic_pointer_t;

	add_type(array_of_uninterpreted_byte_t, pervasives_master_relation);

	cout << "#include \"uniqtype-defs.h\"\n\n";
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	/* For __uniqtype____EXISTS1___PTR__1, we need two hacks:
	 * to set the genericity to 1, and the indir level to 0 (generic pointers
	 * shouldn't be dereferenced before they are specialized into something non-generic). */
	write_master_relation(pervasives_master_relation,
		std::cout, std::cerr,
		names_emitted,
		types_by_name,
		/* emit_codeless_aliases */ true,
		/* emit_subobject_names */ true);

	/* DWARF doesn't reify void, but we do. So output a rec for void. */
	cout << "\n/* uniqtype for void */\n";
	write_uniqtype_section_decl(cout, "__uniqtype__void");
	string mangled_name = mangle_typename(make_pair(string(""), string("void")));
	cout << "const char *" << mangled_name
			<< "_subobj_names[] "
			<< " __attribute__((section (\".data.__uniqtype__void"
			   << ", \\\"awG\\\", @progbits, __uniqtype__void"  << ", comdat#\")))"
			<< "= { (void*)0 };\n";
	write_uniqtype_open_void(cout,
		mangled_name,
		"void",
		string("void")
	);
	write_uniqtype_related_dummy(cout);
	write_uniqtype_close(cout, mangled_name);

	return 0;
}
