#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <cstdlib>
#include <cstddef>
#include <memory>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/icl/interval_map.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <cxxgen/tokens.hpp>
#include <cxxgen/cxx_compiler.hpp>
#include <dwarfpp/lib.hpp>
#include <fileno.hpp>

#include "uniqtypes.hpp"
#include "uniqtype.h" /* for UNIQTYPE_DECL which we stringify */

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
using dwarf::core::type_describing_subprogram_die;
using dwarf::core::program_element_die;
using dwarf::core::compile_unit_die;
using dwarf::core::member_die;
using dwarf::core::with_data_members_die;
using dwarf::core::variable_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::base_type_die;
using dwarf::core::enumeration_type_die;
using dwarf::core::subrange_type_die;
using dwarf::core::array_type_die;
using dwarf::core::string_type_die;
using dwarf::core::type_chain_die;
using dwarf::core::subroutine_type_die;
using dwarf::core::formal_parameter_die;

using dwarf::lib::Dwarf_Off;

using dwarf::tool::abstract_c_compiler;

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
	if (t && t != t->get_concrete_type())
	{
		// add the concrete
		auto concrete_t = t->get_concrete_type();
		auto ret = add_concrete_type_if_absent(concrete_t, r);
		// add the alias, if we have a name
		if (t.name_here())
		{
			add_alias_if_absent(*name_for_type_die(t), concrete_t, r);
		}
		return ret;
	}
	else if (t.is_a<base_type_die>())
	{
		/* Base types are a bit like non-concretes. */
		// add the concrete
		auto concrete_t = t->get_concrete_type();
		auto ret = add_concrete_type_if_absent(concrete_t, r);
		// add the alias, if we have a name
		if (t.name_here())
		{
			add_alias_if_absent(*name_for_type_die(t), concrete_t, r);
			/* HACK: for good measure, also ensure that we add the 
			 * canonical C name, if the name we have is in some equivalence class. */
			const char **c_equiv_class = abstract_c_compiler::get_equivalence_class_ptr(
				name_for_type_die(t)->c_str());
			if (c_equiv_class)
			{
				add_alias_if_absent(c_equiv_class[0], concrete_t, r);
			}
		}
		return ret;
	}
	else return add_concrete_type_if_absent(t, r);
}
void add_alias_if_absent(const string& s, iterator_df<type_die> concrete_t, master_relation_t& r)
{
	// HACK: don't alias void (we can't use iterators-to-void-type as indexes)
	if (!concrete_t) return;
	
	/* HACK: since in C, "struct X" and "X" are distinct, but we don't distinguish them, 
	 * we also need to ignore this kind of alias here. Be careful about base types though: 
	 * we *do* need their actual-name aliases. */
	if (!concrete_t.is_a<base_type_die>() 
		&& concrete_t.name_here() && s == *name_for_type_die(concrete_t)) return;
	
	r.aliases[concrete_t].insert(s);
}
pair<bool, uniqued_name> add_concrete_type_if_absent(iterator_df<type_die> t, master_relation_t& r)
{
	// we might get called on to add void
	if (t == iterator_base::END)
	{
		return make_pair(false, make_pair("", ""));
	}

	assert(t == t->get_concrete_type());

	
// 	/* If it's a base type, we might not have a decl_file, */
// 	if (!t->get_decl_file() || *t->get_decl_file() == 0)
// 	{
// 		if (t.tag_here() != DW_TAG_base_type
// 		 && t.tag_here() != DW_TAG_pointer_type
// 		 && t.tag_here() != DW_TAG_reference_type
// 		 && t.tag_here() != DW_TAG_rvalue_reference_type
// 		 && t.tag_here() != DW_TAG_array_type
// 		 && t.tag_here() != DW_TAG_subroutine_type)
// 		{
// 			cerr << "Warning: skipping non-base non-pointer non-array non-subroutine type described by " << *t //
// 			//if (t.name_here()) cerr << t.name_here();
// 			//else cerr << "(unknown, offset: " << std::hex << t.offset_here() << std::dec << ")";
// 			/*cerr */ << " because no file is recorded for its definition." << endl;
// 			return make_pair(false, make_pair("", ""));
// 		}
// 		// else it's a base type, so we go with the blank type
// 		// FIXME: should canonicalise base types here
// 		// (to the same as the ikind/fkinds come out from Cil.Pretty)
// 	}

	uniqued_name n = canonical_key_from_type(t);
	
	smatch m;
	bool already_present = r.find(n) != r.end();
	if (already_present
		&& t.tag_here() != DW_TAG_base_type
		&& !regex_match(n.second, m, regex(".*__(PTR|REF|FUN|RR|ARR[0-9]+)_.*")))
	{
		cerr << "warning: non-base non-pointer non-array non-function type named " << n.second << " already exists!" << endl;
	}
	r[n] = t;
	return make_pair(!already_present, n);
}

pair<bool, uniqued_name> transitively_add_type(iterator_df<type_die> toplevel_t, master_relation_t& r)
{
	pair<bool, uniqued_name> result;
	
	walk_type(toplevel_t, iterator_base::END, 
		[&r, &result, toplevel_t](iterator_df<type_die> t, iterator_df<program_element_die> reason) -> bool {
		/* NOTE: we will get called for every type, including void. 
		 * Our job is to decide whether we need to add_type_if_absent, 
		 * and whether we need to recurse. */

		cerr << "Walking: " << t << endl;
		
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
				cout << "Found directly recursive data type: "
					<< t
					<< " contains member "
					<< memb
					<< " of type "
					<< memb->get_type()->get_concrete_type()
					<< " which equals " 
					<< t.parent()
					<< endl;
				assert(false);
			}
		}
		
		if (t && t != t->get_concrete_type()) return true; // don't add anything, but keep going
		auto p = add_type_if_absent(t, r);
		if (!p.first) return false; // we've already added it; stop now
		
		// the result of the calling function is the toplevel case of the walk
		if (t == toplevel_t) result = p;
		
		return true; // keep going
	});
	
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
			opt<string> opt_name = !i.is_a<subprogram_die>() ? i.name_here() : opt<string>(); // for debugging
			if (opt_name)
			{
				string name = *opt_name;
				assert(name != "");
			}
			add_type(i.as_a<type_die>(), rel);
		}
		previous_offset = i.offset_here();
	}
}	
string ensure_contained_length(const string& mangled_name, unsigned contained_length)
{
	ostringstream s;
	s << "__asm__(\".size " << mangled_name << ", "
		<< (offsetof(uniqtype, related) + contained_length * sizeof (uniqtype_rel_info))
		<< "\");" << endl;
	
	return s.str();
}
void write_master_relation(master_relation_t& r, dwarf::core::root_die& root, 
	std::ostream& out, std::ostream& err, bool emit_void, bool emit_struct_def, 
	std::set< std::string >& names_emitted,
	std::map< std::string, std::set< dwarf::core::iterator_df<dwarf::core::type_die> > >& types_by_name,
	bool emit_codeless_aliases,
	bool emit_subobject_names /* = false */)
{
	/* Keep in sync with liballocs_private.h! */
	if (emit_struct_def) cout << UNIQTYPE_DECLSTR;

	std::map< std::string, std::set< pair<string, string> > > name_pairs_by_name;
	
	/* Note the very nasty hack with __attribute__((section (...))): 
	 * we embed a '#' into the section string, after adding our own
	 * assembler-level flags and attributes. This causes the compiler-
	 * -generated flags and attributes to be ignored, because the '#' 
	 * comments them out. Without this trick, there is no way of supplying
	 * our own section flags and attributes to override the compiler. */
	if (emit_void)
	{
		/* DWARF doesn't reify void, but we do. So output a rec for void first of all.
		 * We make it void so that multiple definitions in the same final link do not
		 * cause a problem. */
		out << "\n/* uniqtype for void */\n";
		if (emit_subobject_names)
		{
			out << "const char *" << mangle_typename(make_pair(string(""), string("void")))
				<< "_subobj_names[] "
				<< " __attribute__((section (\".data.__uniqtype__void, \\\"awG\\\", @progbits, __uniqtype__void, comdat#\")))"
				<< "= { (void*)0 };\n";
		}
		
		string mangled_name = mangle_typename(make_pair(string(""), string("void")));
		write_uniqtype_open_void(out,
			mangled_name,
			"void",
			string("void")
		);
		write_uniqtype_close(out, mangled_name);
	}
	else // always declare it, at least, with weak attribute
	{
		out << "extern struct uniqtype " << mangle_typename(make_pair(string(""), string("void")))
			<< " __attribute__((weak));" << endl;
	}
	
	/* The complement relation among signed and unsigned integer types. */
	map<unsigned, map<bool, set< master_relation_t::value_type > > > integer_base_types_by_size_and_signedness;
	auto needs_complement = [](iterator_df<base_type_die> base_t) {
		return base_t->get_encoding() == DW_ATE_signed
			 || base_t->get_encoding() == DW_ATE_unsigned;
	};
		
	/* Emit forward declarations, building the complement relation as we go. */
	for (auto i_pair = r.begin(); i_pair != r.end(); ++i_pair)
	{
		auto name = i_pair->first;
		string s = mangle_typename(name);
		names_emitted.insert(s);
		iterator_df<type_die> t = i_pair->second;
		if (t && t != t->get_concrete_type())
		{
			cerr << "Warning: master relation contained non-concrete: " << t << endl;
		}
		types_by_name[name.second].insert(t);
		name_pairs_by_name[name.second].insert(name);
		if (t.is_a<base_type_die>())
		{
			/* Are we an integer? */
			auto base_t = t.as_a<base_type_die>();
			if (needs_complement(base_t))
			{
				unsigned size = *base_t->get_byte_size();
				bool signedness = (base_t->get_encoding() == DW_ATE_signed);

				// HACK: for now, skip weird cases with bit size/offset
				if ((base_t->get_bit_offset() && *base_t->get_bit_offset() != 0) || 
					(base_t->get_bit_size() && *base_t->get_bit_size() != 8 * size))
				{
					continue;
				}

				integer_base_types_by_size_and_signedness[size][signedness].insert(*i_pair);
			}
		}
		
		out << "extern struct uniqtype " << s;
		// incompletes are weak-ref'd
		if (i_pair->first.first == "")
		{
			out << " __attribute__((weak))";
		}
		out << ";" << endl;

	}
	/* Declare any signedness-complement base types that we didn't see. 
	 * We will emit these specially. */
	set< iterator_df<base_type_die> > synthesise_complements;
	for (auto i_size = integer_base_types_by_size_and_signedness.begin(); 
		i_size != integer_base_types_by_size_and_signedness.end(); ++i_size)
	{
		auto& by_signedness = i_size->second;
		
		/* We should never have nominally-distinct, definitionally-equivalent 
		 * base types. Different names should be aliases, only. */
		assert(by_signedness[false].size() <= 1);
		assert(by_signedness[true].size() <= 1);
		iterator_df<base_type_die> have_unsigned = iterator_base::END;
		if (by_signedness[false].size() == 1) have_unsigned = by_signedness[false].begin()->second.as_a<base_type_die>();
		iterator_df<base_type_die> have_signed = iterator_base::END;
		if (by_signedness[true].size() == 1) have_signed = by_signedness[true].begin()->second.as_a<base_type_die>();
		
		// if we don't have either, how did we get here?
		assert(have_unsigned || have_signed);
		
		if (!have_unsigned || !have_signed) // the "count == 1" case
		{
			// we have to synthesise the other-signedness version
			cerr << "We have " 
				<< (have_signed ? have_signed : have_unsigned)
				<< " but not its complement, so will synthesise it." << endl;
				
			synthesise_complements.insert(have_signed ? have_signed : have_unsigned);
		}
		// else the "count == 2" case: no need to synthesise
	}
	// declare any synthetic complements
	for (auto i_need_comp = synthesise_complements.begin(); 
		i_need_comp != synthesise_complements.end(); 
		++i_need_comp)
	{
		// compute and print complement name
		auto k = make_pair(
			summary_code_to_string(
				signedness_complement_type_summary_code(
					*i_need_comp
				)
			),
			name_for_complement_base_type(*i_need_comp)
		);
		string s = mangle_typename(k);

		out << "extern struct uniqtype " << s << " __attribute__((weak)); "
			<< "/* synthetic signedness complement of " << name_for_base_type(*i_need_comp) 
			<< " */" << endl;
	}

	/* Output the canonical definitions. */
	for (auto i_vert = r.begin(); i_vert != r.end(); ++i_vert)
	{
		if (i_vert->first.second == string("void"))
		{
			if (i_vert->second) err << "Warning: skipping explicitly declared void type from CU "
				<< *i_vert->second.enclosing_cu().name_here()
				<< endl;
			continue;
		}
		auto opt_sz = i_vert->second->calculate_byte_size();
		
		out << "\n/* uniqtype for \"" << i_vert->first.second 
			<< "\" with summary code " << i_vert->first.first << " */\n";
		std::vector< iterator_base > real_members;
		std::vector< Dwarf_Unsigned > real_member_offsets;
		std::vector< iterator_base > fp_types;
		if (i_vert->second.is_a<type_describing_subprogram_die>())
		{
			auto fps = i_vert->second.children().subseq_of<formal_parameter_die>();
			for (auto i_edge = fps.first; i_edge != fps.second; ++i_edge)
			{
				fp_types.push_back(i_edge->find_type()); 
			}
		}
		else
		{
			auto members = i_vert->second.children().subseq_of<member_die>();
			for (auto i_edge = members.first; i_edge != members.second; ++i_edge)
			{
				/* if we don't have a byte offset, skip it ( -- it's a static var?) */
				opt<Dwarf_Unsigned> opt_offset = i_edge->byte_offset_in_enclosing_type(false /* true */);
				if (!opt_offset) continue;
				else
				{ 
					real_members.push_back(i_edge.base().base()); 
					real_member_offsets.push_back(*opt_offset);
				}
			}
		}
		unsigned members_count = real_members.size();
		unsigned array_len;
		if  (i_vert->second.is_a<array_type_die>())
		{
			auto opt_array_len = i_vert->second.as_a<array_type_die>()->element_count();
			if (opt_array_len) array_len = *opt_array_len;
			else array_len = 0;
		} 
		else if  (i_vert->second.is_a<string_type_die>())
		{
			auto opt_fixed_size = i_vert->second.as_a<string_type_die>()->fixed_length_in_bytes();
			if (opt_fixed_size) array_len = *opt_fixed_size;
			else array_len = 0;
		}
		else if (i_vert->second.is_a<type_describing_subprogram_die>())
		{
			/* use array len to encode the number of fps */
			array_len = fp_types.size();
		} 
		else if (i_vert->second.is_a<address_holding_type_die>())
		{
			/* HACK HACK HACK: encode the type's pointerness into array_len. 
			 * We should rationalise struct uniqtype to require less of this
			 * sort of thing. */
			array_len = /* MAGIC_LENGTH_POINTER */(1u << 19) - 1u;
		} else array_len = 0;
		string mangled_name = mangle_typename(i_vert->first);
		
		/* Our last chance to skip things we don't want to emit. 
		 * NOTE that for incompletes, we distinguish "flexible", "opaque" and "undefined" types
		 * (FIXME: actually use this terminology consistently).
		 * 
		 * "flexible" means it has some defined members, but no length; pos_maxoff will be -1. 
		 * "opaque" is things like functions which deliberately have no length nor contents;
		        pos_maxoff will be 0.
		 * "undefined" is structs that are declared but not defined. *Usually* the intention
		 * here is the same as for "opaque"... HMM.
		 */
		if (i_vert->second.is_a<with_data_members_die>() && real_members.size() == 0 && !opt_sz)
		{
			// we have an incomplete type -- skip it!
			err << "Warning: with-data-members type " 
				<< i_vert->first.second
				<< " is incomplete, skipping." << endl;
			out << "/* skipped -- incomplete */" << endl;
			continue;
		}
		/* We can also be *variable-length*. In this case we output a pos_maxoff of -1
		 * i.e. maximum-unsigned-value. */
		
		if (emit_subobject_names)
		{
			out << "const char *" << mangled_name << "_subobj_names[] "
				<< " __attribute__((weak,section (\".data." << mangled_name 
					<< ", \\\"awG\\\", @progbits, " << mangled_name << ", comdat#\")))";
				if (i_vert->second.is_a<with_data_members_die>())
				{
					out << " = { ";
					unsigned num = 0;
					for (auto i_i_edge = real_members.begin(); i_i_edge != real_members.end(); ++i_i_edge, ++num)
					{
						auto i_edge = i_i_edge->as_a<member_die>();
						
						if (i_edge.name_here())
						{
							string name = *i_edge.name_here();
							out << "\"" << name << "\"";
						}
						else
						{
							/* FIXME: do something nicer */
							out << "\"_" << num << "\"";
						}
						/* always output a comma */
						out << ", ";
					}
					out << "(void*)0 };\n";
				}
				else
				{
					out << "= { (void*)0 };\n";
				}
		}
		
		unsigned contained_length = 1;
		if (i_vert->second.is_a<array_type_die>())
		{
			write_uniqtype_open_array(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				array_len
			);
			
			// compute and print destination name
			auto k = canonical_key_from_type(i_vert->second.as_a<array_type_die>()->get_type());
			/* FIXME: do multidimensional arrays get handled okay like this? 
			 * I reckon so, but am not yet sure. */
			string mangled_name = mangle_typename(k);
			write_uniqtype_related_array_element_type(out,
				mangled_name
			);
		}
		else if (i_vert->second.is_a<string_type_die>())
		{
			write_uniqtype_open_array(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				array_len
			);
			/* FIXME */
			write_uniqtype_related_array_element_type(out, string("__uniqtype__unsigned_char$8"));
		}
		else if (i_vert->second.is_a<address_holding_type_die>())
		{
			write_uniqtype_open_address(out,
				mangled_name,
				i_vert->first.second,
				sizeof (void*) /* FIXME */,
				0 /* FIXME */,
				0 /* FIXME */,
				0 /* FIXME */
			);
			// compute and print destination name
			auto k = canonical_key_from_type(i_vert->second.as_a<address_holding_type_die>()->get_type());
			string mangled_name = mangle_typename(k);
			write_uniqtype_related_pointee_type(out, mangled_name);
		}
		else if (i_vert->second.is_a<type_describing_subprogram_die>())
		{
			write_uniqtype_open_subprogram(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				members_count,
				1,
				0 /* FIXME */,
				0 /* FIXME */
			);
			/* Output the return type and argument types. We always output
			 * a return type, even if it's &__uniqtype__void. */
			auto return_type = i_vert->second.as_a<type_describing_subprogram_die>()->find_type();
			write_uniqtype_related_subprogram_return_type(out,
				true, mangle_typename(canonical_key_from_type(return_type)));
			
			for (auto i_t = fp_types.begin(); i_t != fp_types.end(); ++i_t)
			{
				write_uniqtype_related_subprogram_argument_type(out,
					mangle_typename(canonical_key_from_type(*i_t))
				);
				
				++contained_length;
			}
		}
		else if (i_vert->second.is_a<subrange_type_die>()) // FIXME
		{
			write_uniqtype_open_base(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				i_vert->second.as_a<subrange_type_die>()->find_type().as_a<base_type_die>()->
					get_encoding(),
				0 /* FIXME */,
				0 /* FIXME */,
				0 /* FIXME */,
				0 /* FIXME */
			);
			write_uniqtype_related_dummy(out);
		}

		else if (i_vert->second.is_a<base_type_die>())
		{
			write_uniqtype_open_base(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				i_vert->second.as_a<base_type_die>()->get_encoding(),
				0 /* FIXME */,
				0 /* FIXME */,
				0 /* FIXME */,
				0 /* FIXME */
			);
		
			if (needs_complement(i_vert->second.as_a<base_type_die>()))
			{
				// compute and print complement name
				auto k = make_pair(
					summary_code_to_string(
						signedness_complement_type_summary_code(
							i_vert->second
						)
					),
					name_for_complement_base_type(i_vert->second)
				);
				string mangled_name = mangle_typename(k);
				write_uniqtype_related_signedness_complement_type(out, mangled_name);
			}
			else write_uniqtype_related_dummy(out);
		}
		else if (i_vert->second.is_a<enumeration_type_die>())
		{
			write_uniqtype_open_enumeration(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */
			);
			write_uniqtype_related_dummy(out); /* FIXME */
		}
		else if (!i_vert->second)
		{
			write_uniqtype_open_void(out,
				mangled_name,
				i_vert->first.second
			);
			write_uniqtype_related_dummy(out);
		}
		else if (i_vert->second.is_a<with_data_members_die>())
		{
			write_uniqtype_open_composite(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				members_count,
				false
			);
			unsigned i_membernum = 0;
			std::set<lib::Dwarf_Unsigned> used_offsets;
			opt<iterator_base> first_with_byte_offset;
			auto i_off = real_member_offsets.begin();
			
			// we *always* output at least one array element
			contained_length = 0;
			for (auto i_i_edge = real_members.begin(); i_i_edge != real_members.end(); ++i_i_edge, ++i_membernum, ++i_off)
			{
				++contained_length;
				auto i_edge = i_i_edge->as_a<member_die>();
				auto k = canonical_key_from_type(i_edge->get_type());
				string mangled_name = mangle_typename(k);
				if (names_emitted.find(mangled_name) == names_emitted.end())
				{
					out << "Type named " << mangled_name << ", " << i_edge->get_type()
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

				write_uniqtype_related_contained_member_type(out,
					i_i_edge == real_members.begin(),
					*i_off,
					mangled_name);
			}
		}
		else
		{
			cerr << "Saw a type of tag: " <<
				i_vert->second.spec_here().tag_lookup(
					i_vert->second.tag_here()
				)
				<< endl;
			assert(false);
		}
		
		write_uniqtype_close(out, mangled_name, contained_length);
		
		/* Output a synthetic complement if we need one. */
		if (synthesise_complements.find(i_vert->second) != synthesise_complements.end())
		{
			out << "\n/* synthesised signedness-complement type for \"" << i_vert->first.second 
				<< "\" */\n";
			// compute and print complement name
			string complement_summary_code_string = summary_code_to_string(
				signedness_complement_type_summary_code(
					i_vert->second
				)
			);
			auto k = make_pair(
				complement_summary_code_string,
				name_for_complement_base_type(i_vert->second)
			);
			string compl_name = mangle_typename(k);
			
			write_uniqtype_open_base(out, 
				compl_name,
				k.second,
				(opt_sz ? *opt_sz : 0),
				(i_vert->second.as_a<base_type_die>()->get_encoding() == DW_ATE_unsigned) ? 
					DW_ATE_signed : 
					(i_vert->second.as_a<base_type_die>()->get_encoding() == DW_ATE_signed) ? 
					DW_ATE_unsigned :
					i_vert->second.as_a<base_type_die>()->get_encoding(),
				0, /* FIXME */
				0, /* FIXME */
				0, /* FIXME */
				0) /* FIXME */;
			write_uniqtype_related_signedness_complement_type(out,
				mangled_name
			);
			write_uniqtype_close(out, compl_name, 1);
			
			/* If our actual type has a C-style name, output a C-style alias for the 
			 * complement we just output. FIXME: how *should* this work? Who consumes 
			 * these aliases? Is it only our sloppy-dumptypes test case, i.e. typename-
			 * -based client code that expects C-style names? 
			 * 
			 * In general we want to factor this into a pair of extra phases in allocscc:
			 * one which "lowers" trumptr-generated typenames into canonical
			 * language-independent ones, 
			 * and one which "re-aliases them" in language-dependent form. We could use
			 * this to support e.g. Fortran at the same time as C, etc..
			 * BUT NOTE that the "language-dependent" form is, in general, both language-
			 * and *compiler*-dependent, i.e. more than one base type might be "unsigned long"
			 * depending on compiler flags etc.. So it's not as simple as re-aliasing them.
			 * The typestr APIs need to be sensitive to the *caller* (e.g. an alias for 
			 * "unsigned_long" might meaningfully exist in a caller's typeobj, but not globally
			 * since multiple distinct "unsigned long"s are defined across the whole program). 
			 * A simple re-aliasing pass on a per-typeobj basis is "good enough" for now though. 
			 * (The case of multiple distinct definitions in the same dynamic object is rare.)
			 * */
			if (i_vert->second.name_here())
			{
				const char **equiv = abstract_c_compiler::get_equivalence_class_ptr(
					name_for_type_die(i_vert->second)->c_str());
				if (equiv)
				{
					bool is_unsigned = (string(equiv[0]).find("unsigned") != string::npos);
					// we are iterating through an array of pointer to equiv class
					const char ** const* found_equiv = std::find(
						abstract_c_compiler::base_typename_equivs,
						abstract_c_compiler::base_typename_equivs_end,
						equiv
					);
					assert(found_equiv);
					// equiv classes are {s, u, s, u, ...}
					const char **compl_equiv = is_unsigned ? found_equiv[-1]  : found_equiv[+1];
					auto complement_name_pair = make_pair(complement_summary_code_string, compl_equiv[0]);
					out << "extern struct uniqtype " << mangle_typename(complement_name_pair)
						<< " __attribute__((weak,alias(\"" << mangle_typename(k) << "\")));" << endl;
					name_pairs_by_name[compl_equiv[0]].insert(complement_name_pair);
				}
			}
		}
		
		/* Output any (typedef-or-base-type) aliases for this type. */
		for (auto i_alias = r.aliases[i_vert->second].begin(); 
			i_alias != r.aliases[i_vert->second].end();
			++i_alias)
		{
			out << "extern struct uniqtype " << mangle_typename(make_pair(i_vert->first.first, *i_alias)) 
				<< " __attribute__((weak,alias(\"" << mangle_typename(i_vert->first) << "\")));" << endl;
			types_by_name[*i_alias].insert(i_vert->second);
			name_pairs_by_name[*i_alias].insert(i_vert->first);
		}
	}
	
	/* Codeless aliases: linker aliases for any concrete typenames *or* typedef names 
	 * that were uniquely defined. */
	if (emit_codeless_aliases)
	{
		out << "/* Begin codeless (__uniqtype__<typename>) aliases. */" << endl;
		for (auto i_by_name_pair = name_pairs_by_name.begin(); i_by_name_pair != name_pairs_by_name.end();
			++i_by_name_pair)
		{
			if (i_by_name_pair->second.size() == 1)
			{
				/* This name only denotes one type, so we can alias it if it's complete. */
				auto full_name_pair = *i_by_name_pair->second.begin();
				if (full_name_pair.first != "")
				{
					string full_name = mangle_typename(full_name_pair);
					pair<string, string> abbrev_name_pair = make_pair("", i_by_name_pair->first);
					string abbrev_name = mangle_typename(abbrev_name_pair);
					out << "extern struct uniqtype " << abbrev_name << " __attribute__((weak, alias(\""
						<< cxxgen::escape(full_name) << "\")));" << endl;
				}
			}
			else
			{
				out << "/* Not aliasing \"" << i_by_name_pair->first << "\"; set is {\n";
				for (auto i_t = i_by_name_pair->second.begin(); i_t != i_by_name_pair->second.end(); ++i_t)
				{
					if (i_t != i_by_name_pair->second.begin()) cout << ",\n";
					out << "\t" << mangle_typename(*i_t);
				}

				out << "\n} */" << endl;
			}
		}
	}
}

static void write_uniqtype_open_generic(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff
	)
{
	o << "struct uniqtype " << mangled_typename
		<< " __attribute__((section (\".data." << mangled_typename 
			<< ", \\\"awG\\\", @progbits, " << mangled_typename 
			<< ", comdat#\")))"
		<< " = {\n\t" 
		<< "{ 0, 0, 0 },\n\t"
		//<< "\"" << unmangled_typename << "\",\n\t"
		<< pos_maxoff << " /* pos_maxoff */,\n\t";
}

void write_uniqtype_open_void(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, 0);
	o << "{ _void: { VOID } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_array(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned nelems,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ array: { 1, " << nelems << " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_address(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned indir_level,
    bool is_generic,
    unsigned log_min_align,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ address: { ADDRESS, " << indir_level << ", " << is_generic << ", " << log_min_align
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_base(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned enc,
    unsigned log_bit_size,
    signed bit_size_delta,
    unsigned log_bit_off,
    signed bit_off_delta,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ base: { BASE, " << enc
		<< ", " << log_bit_size
		<< ", " << bit_size_delta
		<< ", " << log_bit_off
		<< ", " << bit_off_delta
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_enumeration(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ enumeration: { ENUMERATION, 0, 0, 0 } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_composite(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned nmemb,
    bool not_simultaneous,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ composite: { COMPOSITE, " << nmemb
		<< ", " << not_simultaneous 
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_subprogram(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned narg,
    unsigned nret,
    bool is_va,
    unsigned cc,
    opt<const string&> maxoff_comment_str
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ subprogram: { SUBPROGRAM, " << narg 
		<< ", " << nret 
		<< ", " << is_va
		<< ", " << cc
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
	
}
void write_uniqtype_related_array_element_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename,
	opt<const string&> comment_str
    )
{
	/* begin the struct */
	o << "{ { t: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_pointee_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename,
	opt<const string&> comment_str
    )
{
	/* begin the struct */
	o << "{ { t: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_subprogram_argument_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename,
	opt<const string&> comment_str
    )
{
	o << ",\n\t\t";
	/* begin the struct */
	o << "{ { t: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_subprogram_return_type(std::ostream& o,
	bool is_first,
    opt<const string&> maybe_mangled_typename,
	opt<const string&> comment_str
    )
{
	if (!is_first) o << ",\n\t\t";
	/* begin the struct */
	o << "{ { t: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_contained_member_type(std::ostream& o,
    bool is_first,
	unsigned offset,
    opt<const string&> maybe_mangled_typename,
	opt<const string&> comment_str
    )
{
	if (!is_first) o << ",\n\t\t";
	/* begin the struct */
	o << "{ { memb: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << ", " << offset << ", 0, 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_signedness_complement_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename,
	opt<const string&> comment_str
    )
{
	/* begin the struct */
	o << "{ { t: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_dummy(std::ostream& o,
	opt<const string&> comment_str
    )
{
	/* begin the struct */
	o << "{ { t: { (void*) 0 } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}

void write_uniqtype_close(std::ostream& o, const string& mangled_name, opt<unsigned> n_contained)
{
	o << "\n\t}";
	o << "\n};\n";
	if (n_contained) o << ensure_contained_length(mangled_name, *n_contained);
}
