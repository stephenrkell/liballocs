#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <cmath>

#include <boost/algorithm/string.hpp>
#include <srk31/indenting_ostream.hpp>
#include "dwarfidl/cxx_model.hpp"
#include "dwarfidl/dwarfidl_cxx_target.hpp"
#include <dwarfidl/dwarf_interface_walk.hpp>
#include <srk31/algorithm.hpp>
#include "stickyroot.hpp"
#include "uniqtypes.hpp"

using namespace srk31;
using namespace dwarf;
using namespace dwarf::lib;
using std::vector;
using std::set;
using std::map;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::ostringstream;
using std::istringstream;
using std::stack;
using std::deque;
using boost::optional;
using namespace dwarf::lib;
using dwarf::core::iterator_base;
using dwarf::core::root_die;
using dwarf::core::abstract_die;
using dwarf::core::program_element_die;
using dwarf::core::with_static_location_die;
using dwarf::core::variable_die;
using dwarf::core::type_die;
using dwarf::core::type_set;
using dwarf::core::base_type_die;
using dwarf::core::pointer_type_die;
using dwarf::core::subprogram_die;
using dwarf::tool::gather_interface_dies;
using dwarf::core::iterator_df;
using dwarf::spec::opt;

using namespace allocs::tool;

int main(int argc, char **argv)
{
	using dwarf::tool::dwarfidl_cxx_target;
	// open the file passed in on the command-line
	assert(argc > 1);
	FILE* f = fopen(argv[1], "r");
	
	// construct a dwarf::file
	struct root_die_with_sticky_types : public root_die
	{
		using root_die::root_die;
		
		bool is_sticky(const abstract_die& d)
		{
			return /* d.get_spec(*this).tag_is_type(d.get_tag())
				|| */this->root_die::is_sticky(d);
		}
	} r(fileno(f));
	vector<string> compiler_argv = dwarf::tool::cxx_compiler::default_compiler_argv(true);
	compiler_argv.push_back("-fno-eliminate-unused-debug-types");
	compiler_argv.push_back("-fno-eliminate-unused-debug-symbols");
	indenting_ostream& s = srk31::indenting_cout;
	dwarfidl_cxx_target target(" uintptr_t", s, compiler_argv);

	/* If the user gives us a list of function names on stdin, we use that. */
	using std::cin;
	std::istream& in = /* p_in ? *p_in :*/ cin;
	/* populate the subprogram and types lists. */
	char buf[4096];
	set<string> element_names;
	map<string, iterator_base> named_element_dies;
	while (in.getline(buf, sizeof buf - 1))
	{
		element_names.insert(buf);
	}
	cerr << "Received " << element_names.size() << " element names" << endl;
	/* FIXME: we really need to receive <name, address> pairs,
	 * in order to handle aliases correctly. If we equal_range
	 * on the address, the first of each range gets output as a
	 * definition and the rest as an aliased decl. But how do we
	 * stringify the alias decl correctly? */

	auto pred = [element_names, &named_element_dies](const iterator_base& i) {
		/* This is the basic test for whether an interface element is of 
		 * interest. For us, it's just whether it's a visible subprogram or variable
		 * in our list. Or, if our list is empty, it's any subprogram. Variables too!*/
		auto i_pe = i.as_a<program_element_die>();
		auto found_element_name = element_names.end();
		boost::icl::interval_map<Dwarf_Addr, Dwarf_Unsigned /*dummy*/> found_intervals;
		bool retval;
		if (i_pe && i_pe.name_here()
			&& ((i_pe.is_a<variable_die>() && i_pe.as_a<variable_die>()->has_static_storage())
				|| (i_pe.is_a<subprogram_die>()
					/* extern declarations of subprogram DIEs do not always have arg/ret type
					 * info, at least coming out of GCC. */
					&& !(i_pe.as_a<subprogram_die>()->get_declaration() &&
							*i_pe.as_a<subprogram_die>()->get_declaration()
						  && i_pe.as_a<subprogram_die>()->get_external() &&
							*i_pe.as_a<subprogram_die>()->get_declaration()
						)
					)
				)
			&& (!i_pe->get_visibility() || *i_pe->get_visibility() == DW_VIS_exported)
			&& element_names.find(*i_pe.name_here()) != element_names.end()
			)
		{
			return true;
		} else return false;
	};
	set<pair<dwarfidl_cxx_target::emit_kind, iterator_base>,
		dwarfidl_cxx_target::compare_with_type_equality > to_output;
	auto seq = r.visible_named_grandchildren();
	bool seen_size_t = false; // HACK for debugging
	for (auto i_el = seq.first; i_el != seq.second; ++i_el)
	{
		if (pred(i_el)) // is it a visible subprogram or variable?
		{
			named_element_dies.insert(make_pair(*i_el.name_here(), i_el));
		}
	}
	// now we have uniqued by name
	for (auto i_pair = named_element_dies.begin(); i_pair != named_element_dies.end(); ++i_pair)
	{
		auto retpair = to_output.insert(
			make_pair(dwarf::tool::dwarfidl_cxx_target::EMIT_DEF, i_pair->second)
		);
	}
	map<pair<dwarfidl_cxx_target::emit_kind, iterator_base>, string,
		dwarfidl_cxx_target::compare_with_type_equality > output_fragments;
	multimap< pair<dwarfidl_cxx_target::emit_kind, iterator_base>,
		pair<dwarfidl_cxx_target::emit_kind, iterator_base>,
		dwarfidl_cxx_target::compare_with_type_equality > order_constraints;
	/* where do we actually generate the output strings? during transitively_close */
	target.transitively_close(to_output,
		target.get_default_referencer(),
		output_fragments,
		order_constraints
	);
	cerr << "Generated " << output_fragments.size() << " output fragments." << endl;
	for (auto i_frag = output_fragments.begin(); i_frag != output_fragments.end(); ++i_frag)
	{
		cerr << i_frag->first.first << " of " << i_frag->first.second << endl;
	}
	cerr << "=========================================" << endl;

	target.write_ordered_output(output_fragments, order_constraints);

	return 0;
}
