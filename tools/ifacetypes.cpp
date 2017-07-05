#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <cmath>

#include <boost/algorithm/string.hpp>
#include <srk31/indenting_ostream.hpp>
#include <dwarfidl/dwarf_interface_walk.hpp>
#include <srk31/algorithm.hpp>
#include "helpers.hpp"
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
using dwarf::core::variable_die;
using dwarf::core::type_die;
using dwarf::core::type_set;
using dwarf::core::subprogram_die;
using dwarf::tool::gather_interface_dies;
using dwarf::core::iterator_df;

int main(int argc, char **argv)
{
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
	
	/* If the user gives us a list of function names on stdin, we use that. */
	using std::cin;
	std::istream& in = /* p_in ? *p_in :*/ cin;
	/* populate the subprogram and types lists. */
	char buf[4096];
	set<string> element_names;
	map<string, iterator_base> named_element_dies;
	while (in.getline(buf, sizeof buf - 1))
	{
		/* Find a toplevel grandchild that is a subprogram of this name. */
		element_names.insert(buf);
	}

	set<iterator_base> dies;
	type_set types;
	gather_interface_dies(r, dies, types, [element_names, &named_element_dies](const iterator_base& i){
		/* This is the basic test for whether an interface element is of 
		 * interest. For us, it's just whether it's a visible subprogram or variable
		 * in our list. Or, if our list is empty, it's any subprogram. Variables too!*/
		auto i_pe = i.as_a<program_element_die>();
		if (i_pe && i_pe.name_here()
			&& ((i_pe.is_a<variable_die>() && i_pe.as_a<variable_die>()->has_static_storage())
				|| i_pe.is_a<subprogram_die>())
			&& (!i_pe->get_visibility() || *i_pe->get_visibility() == DW_VIS_exported)
			&& (
				element_names.size() == 0 
				|| element_names.find(*i_pe.name_here()) != element_names.end()))
		{
			if (element_names.size() == 0)
			{
				return true;
			}
			else if (element_names.find(*i_pe.name_here()) != element_names.end())
			{
				named_element_dies[*i_pe.name_here()] = i;
				return true;
			} else return false;
		} else return false;
	});
	
	/* Now build a master relation and emit it. */
	master_relation_t master_relation;
	for (auto i_t = types.begin(); i_t != types.end(); ++i_t)
	{
		master_relation.insert(
			make_pair(
				canonical_key_for_type(*i_t), 
				*i_t ? (*i_t)->get_concrete_type() : *i_t
			)
		);
	}
	set<string> names_emitted;
	
	map<string, set< iterator_df<type_die> > > types_by_name;
	map< iterator_df<type_die>, set<string> > names_by_type;
	write_master_relation(master_relation, cout, cerr, true /* emit_void */, true, 
		names_emitted, types_by_name, true);
	
	/* Also write a mapping from the named elements the user requested 
	 * to their uniqtypes. */
	for (auto i_el = element_names.begin(); i_el != element_names.end(); ++i_el)
	{
		string name = *i_el;
		iterator_base i = named_element_dies[name];
		if (!i)
		{
			cerr << "Warning: did not find an element named " << name << "; skipping." << endl;
			continue;
		}
		type_set::iterator  found;
		if (i.is_a<type_die>()) found = types.find(i);
		else if (i.is_a<dwarf::core::with_type_describing_layout_die>())
		{
			auto t = i.as_a<dwarf::core::with_type_describing_layout_die>()->find_type();
			found = types.find(t);
		}
		else
		{
			cerr << "Warning: " << i << " is not a subprogram, type or a variable having a type." 
				<< endl;
			continue;
		}
		/* The type in the relation is the one in the type set, concretified. */
		if (found == types.end())
		{
			cerr << "Warning: didn't find match for " << name << " in gathered types." << endl;
			continue;
		}
		cout << "struct uniqtype *__ifacetype_" << name
			<< " = &";
		iterator_df<type_die> t = *found;
		iterator_df<type_die> concrete_t = t ? t->get_concrete_type() : t;
		auto mangled_name = mangle_typename(canonical_key_for_type(concrete_t));
		cout << mangled_name;
		cout << ";" << endl;
	}

	return 0;
}
