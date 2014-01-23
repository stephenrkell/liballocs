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
#include <dwarfpp/lib.hpp>
#include <fileno.hpp>

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
using std::pair;
using std::make_pair;
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
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;
using dwarf::core::subroutine_type_die;
using dwarf::core::formal_parameter_die;

using dwarf::lib::Dwarf_Off;

using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;


uniqued_name add_type(iterator_df<type_die> t, master_relation_t& r)
{
	auto result = add_type_if_absent(t, r);
	return result.second;
}
pair<bool, uniqued_name> add_type_if_absent(iterator_df<type_die> t, master_relation_t& r)
{
	if (t != t->get_concrete_type()) return make_pair(false, make_pair("", "")); // only add concretes
	
	if (t == iterator_base::END) return make_pair(false, make_pair("", ""));
	
	/* If it's a base type, we might not have a decl_file, */
	if (!t->get_decl_file() || *t->get_decl_file() == 0)
	{
		if (t.tag_here() != DW_TAG_base_type
		 && t.tag_here() != DW_TAG_pointer_type
		 && t.tag_here() != DW_TAG_reference_type
		 && t.tag_here() != DW_TAG_rvalue_reference_type
		 && t.tag_here() != DW_TAG_array_type
		 && t.tag_here() != DW_TAG_subroutine_type)
		{
			cerr << "Warning: skipping non-base non-pointer non-array non-subroutine type described by " << *t //
			//if (t.name_here()) cerr << t.name_here();
			//else cerr << "(unknown, offset: " << std::hex << t.offset_here() << std::dec << ")";
			/*cerr */ << " because no file is recorded for its definition." << endl;
			return make_pair(false, make_pair("", ""));
		}
		// else it's a base type, so we go with the blank type
		// FIXME: should canonicalise base types here
		// (to the same as the ikind/fkinds come out from Cil.Pretty)
	}
	uniqued_name n = key_from_type(t);
	
	smatch m;
	bool already_present = r.find(n) != r.end();
	if (already_present
		&& t.tag_here() != DW_TAG_base_type
		&& !regex_match(n.second, m, regex(".*__(PTR|REF|RR|ARR[0-9]+)_.*")))
	{
		cerr << "warning: non-base non-pointer non-array type named " << n.second << " already exists!" << endl;
	}
	r[n] = t;
	return make_pair(!already_present, n);
}

pair<bool, uniqued_name> transitively_add_type(iterator_df<type_die> t, master_relation_t& r)
{
	auto result = add_type_if_absent(t, r);
	/* Now recurse on referenced type, IFF this was newly added */
	if (!result.first) return result;
	if (t.is_a<with_data_members_die>()) 
	{
		auto member_children = t.as_a<with_data_members_die>().children().subseq_of<member_die>();
		for (auto i_child = member_children.first;
			i_child != member_children.second; ++i_child)
		{
			// skip "declared", "external" members, i.e. static member vars
			if (i_child->get_declaration() && *i_child->get_declaration()
			 && i_child->get_external() && *i_child->get_external())
			{
				continue;
			}

			assert(i_child->get_type() != iterator_base::END);
			if (i_child->get_type()->get_concrete_type() == t) 
			{
				cout << "Found directly recursive data type: "
					<< t
					<< " contains member "
					<< i_child.base().base()
					<< " of type "
					<< i_child->get_type()->get_concrete_type()
					<< " which equals " 
					<< t
					<< endl;
				assert(false);
			}
			transitively_add_type(i_child->get_type()->get_concrete_type(), r);
		}
	}
	else if (t.is_a<array_type_die>())
	{
		auto opt_el_t = t.as_a<array_type_die>()->ultimate_element_type();
		if (opt_el_t) transitively_add_type(opt_el_t->get_concrete_type(), r);
	}
	else if (t.is_a<subroutine_type_die>())
	{
		auto opt_ret_t = t.as_a<subroutine_type_die>()->get_type();
		if (opt_ret_t) transitively_add_type(opt_ret_t, r);
		
		auto member_fps = t.as_a<subroutine_type_die>().children().subseq_of<formal_parameter_die>();
		for (auto i_fp = member_fps.first; i_fp != member_fps.second; ++i_fp)
		{
			transitively_add_type(i_fp->get_type(), r);
		}
	}
	else if (t.is_a<address_holding_type_die>())
	{
		auto opt_target_t = t.as_a<address_holding_type_die>()->get_type();
		if (opt_target_t) transitively_add_type(opt_target_t, r);
	}
	
	return make_pair(true, result.second);
}

void make_exhaustive_master_relation(master_relation_t& rel, 
	dwarf::core::iterator_df<> begin, 
	dwarf::core::iterator_df<> end)
{
	lib::Dwarf_Off previous_offset = 0UL;
	for (iterator_df<> i = begin; i != end; ++i)
	{
		assert(i.offset_here() >= previous_offset); // == for initial case, > afterwards
		if (i.is_a<type_die>())
		{
			// add it to the relation
			opt<string> opt_name = i.name_here(); // for debugging
			if (opt_name)
			{
				string name = *opt_name;
				assert(name != "");
				if (name == "abstract_def")
				{
					assert(true); // for debugging
				}
			}
			add_type(i.as_a<type_die>(), rel);
		}
		previous_offset = i.offset_here();
	}
}	

void write_master_relation(master_relation_t& r, dwarf::core::root_die& root, 
	std::ostream& out, std::ostream& err, bool emit_void, 
	std::set<std::string>& names_emitted,
	std::map<std::string, std::set< dwarf::core::iterator_df<dwarf::core::type_die> > >& types_by_name)
{
	cout << "struct rec \n\
{ \n\
	const char *name; \n\
	short pos_maxoff; \n\
	short neg_maxoff; \n\
	unsigned nmemb:12;         // 12 bits -- number of `contained's\n\
	unsigned is_array:1;       // 1 bit\n\
	unsigned array_len:19;\n\
	struct { \n\
		signed offset; \n\
		struct rec *ptr; \n\
	} contained[]; \n\
};\n";
	if (emit_void)
	{
		/* DWARF doesn't reify void, but we do. So output a rec for void first of all. */
		out << "\n/* uniqtype for void */\n";
		out << "struct rec " << mangle_typename(make_pair(string(""), string("void")))
			<< " __attribute__((section (\".data.__uniqtype__void, \\\"awG\\\", @progbits, __uniqtype__void, comdat#\")))"
			<< " = {\n\t\"" << "void" << "\",\n\t"
			<< "0" << " /* pos_maxoff (void) */,\n\t"
			<< "0" << " /* neg_maxoff (void) */,\n\t"
			<< "0" << " /* nmemb (void) */,\n\t"
			<< "0" << " /* is_array (void) */,\n\t"
			<< "0" << " /* array_len (void) */,\n\t"
			<< "/* contained */ { }\n};\n";
	}
	
	for (auto i_pair = r.begin(); i_pair != r.end(); ++i_pair)
	{
		string s = mangle_typename(i_pair->first);
		names_emitted.insert(s);
		types_by_name[i_pair->first.second].insert(i_pair->second);
		out << "extern struct rec " << s << ";" << endl;
	}

	for (auto i_vert = r.begin(); i_vert != r.end(); ++i_vert)
	{
		auto opt_sz = i_vert->second->calculate_byte_size();
		if (!opt_sz)
		{
			// we have an incomplete type
			err << "Warning: type " 
				<< i_vert->first.second
				<< " is incomplete, treated as zero-size." << endl;
		}
		if (i_vert->first.second == string("void"))
		{
			err << "Warning: skipping explicitly declared void type from CU "
				<< *i_vert->second.enclosing_cu().name_here()
				<< endl;
			continue;
		}
		
		out << "\n/* uniqtype for " << i_vert->first.second 
			<< " defined in " << i_vert->first.first << " */\n";
		auto members = i_vert->second.children().subseq_of<member_die>();
		std::vector< iterator_base > real_members;
		std::vector< Dwarf_Unsigned > real_member_offsets;
		for (auto i_edge = members.first; i_edge != members.second; ++i_edge)
		{
			/* if we don't have a byte offset, skip it */
			opt<Dwarf_Unsigned> opt_offset = i_edge->byte_offset_in_enclosing_type(root);
			if (!opt_offset) continue;
			else
			{ 
				real_members.push_back(i_edge.base().base()); 
				real_member_offsets.push_back(*opt_offset);
			}
		}		
		unsigned members_count = real_members.size();
		unsigned array_len;
		if  (i_vert->second.is_a<array_type_die>())
		{
			auto opt_array_len = i_vert->second.as_a<array_type_die>()->element_count(root);
			if (opt_array_len) array_len = *opt_array_len;
			else array_len = 0;
		} else array_len = 0;
		string mangled_name = mangle_typename(i_vert->first);
		out << "struct rec " << mangle_typename(i_vert->first)
			<< " __attribute__((section (\"" << ".data." << mangled_name << ", \\\"awG\\\", @progbits, " << mangled_name << ", comdat#\")))"
			<< " = {\n\t\"" << i_vert->first.second << "\",\n\t"
			<< (opt_sz ? *opt_sz : 0) << " /* pos_maxoff " << (opt_sz ? "" : "(incomplete) ") << "*/,\n\t"
			<< "0 /* neg_maxoff */,\n\t"
			<< (i_vert->second.is_a<array_type_die>() ? 1 : members_count) << " /* nmemb */,\n\t"
			<< (i_vert->second.is_a<array_type_die>() ? "1" : "0") << " /* is_array */,\n\t"
			<< array_len << " /* array_len */,\n\t"
			<< /* contained[0] */ "/* contained */ {\n\t\t";

		if (i_vert->second.is_a<array_type_die>())
		{
			// array: write a single entry, for the element type
			/* begin the struct */
			out << "{ ";

			// compute offset

			out << "0, ";

			// compute and print destination name
			auto k = key_from_type(i_vert->second.as_a<array_type_die>()->get_type());
			/* FIXME: do multidimensional arrays get handled okay like this? 
			 * I reckon so, but am not yet sure. */
			string mangled_name = mangle_typename(k);
			out << "&" << mangled_name;

			// end the struct
			out << " }";
		}
		else // non-array -- use real members
		{
			unsigned i_membernum = 0;
			std::set<lib::Dwarf_Unsigned> used_offsets;
			opt<iterator_base> first_with_byte_offset;
			auto i_off = real_member_offsets.begin();
			for (auto i_i_edge = real_members.begin(); i_i_edge != real_members.end(); ++i_i_edge, ++i_membernum, ++i_off)
			{
				auto i_edge = i_i_edge->as_a<member_die>();

				/* if we're not the first, write a comma */
				if (i_i_edge != real_members.begin()) out << ",\n\t\t";

				/* begin the struct */
				out << "{ ";

				// compute offset

				out << *i_off << ", ";

				// compute and print destination name
				auto k = key_from_type(i_edge->get_type());
				string mangled_name = mangle_typename(k);
				if (names_emitted.find(mangled_name) == names_emitted.end())
				{
					out << "Type " << i_edge->get_type()
						<< ", concretely " << i_edge->get_type()->get_concrete_type()
						<< " was not emitted previously." << endl;
					for (auto i_name = names_emitted.begin(); i_name != names_emitted.end(); ++i_name)
					{
						if (i_name->substr(i_name->length() - k.second.length()) == k.second)
						{
							out << "Possible near-miss: " << *i_name << endl;
						}
					}
					assert(false);
				}
				out << "&" << mangled_name;

				// end the struct
				out << " }";
			}
		}
		
		out << "\n\t}"; /* end contained */
		out << "\n};\n"; /* end struct rec */
	}

}
