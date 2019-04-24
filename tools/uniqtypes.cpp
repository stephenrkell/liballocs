#include "uniqtype-defs.h" /* for UNIQTYPE_DECL which we stringify -- include first to avoid
                            * conflicting C++-linkage decls coming later from <c*> */
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <cstdlib>
#include <cstddef>
#include <memory>
#include <cmath>
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
#include "bitops.h"

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
using dwarf::core::unspecified_type_die;
using dwarf::core::formal_parameter_die;

using dwarf::lib::Dwarf_Off;

using dwarf::tool::abstract_c_compiler;

using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

/* Forward declaration of a local helper function */
static void write_uniqtype_open_generic(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    const string& pos_maxoff_str,
	bool use_section_group = true,
	bool make_weak_definition = false
	);

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
		if (t.name_here() && *t.name_here() != "__uninterpreted_byte"
			&& !t.as_a<base_type_die>()->is_bitfield_type())
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
		&& concrete_t.name_here()
		&& s == *name_for_type_die(concrete_t)) return;
	
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

	uniqued_name n = canonical_key_for_type(t);
	
	smatch m;
	bool already_present = r.find(n) != r.end();
	if (already_present
		&& t.tag_here() != DW_TAG_base_type
		&& !regex_match(n.second, m, regex(".*__(PTR|REF|FUN|RR|ARR[0-9]+)_.*")))
	{
		// cerr << "warning: non-base non-pointer non-array non-function type named " << n.second << " already exists!" << endl;
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
	bool done_some_output = false;
	for (iterator_df<> i = begin; i != end; ++i)
	{
		assert(i.offset_here() >= previous_offset); // == for initial case, > afterwards
		if (i.is_a<type_die>())
		{
			if (isatty(fileno(std::cerr)))
			{
				if (done_some_output) std::cerr << "\r";
				std::cerr << "Master relation: adding DIE at 0x" << std::hex << i.offset_here() << std::dec;
				done_some_output = true;
			}
			// add it to the relation
			opt<string> opt_name = !i.is_a<subprogram_die>() ? i.name_here() : opt<string>(); // for debugging
			if (opt_name)
			{
				string name = *opt_name;
				assert(name != "");
			}
			add_type(i.as_a<type_die>(), rel);
		}
		else if (i.is_a<member_die>())
		{
			/* If we have any of the bit attributes, we might induce another type.
			 * So add it. */
			auto memb = i.as_a<member_die>();
			if (memb->get_bit_size() || memb->get_bit_offset() || memb->get_data_bit_offset())
			{
				add_type(memb->find_or_create_type_handling_bitfields(), rel);
			}
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
static string attributes_for_uniqtype(const string& mangled_name, bool is_weak = false, bool include_section = true)
{
	std::ostringstream s;
	bool need_comma = false;
	bool need_termination = false;
	if (is_weak || include_section)
	{
		s << " __attribute__((";
		need_termination = true;
	}
	if (include_section)
	{
		if (need_comma) s << ",";
		s << "section (\".data." << mangled_name
			<< ", \\\"awG\\\", @progbits, " << mangled_name << ", comdat#\")";
		need_comma = true;
	}
	if (is_weak)
	{
		if (need_comma) s << ",";
		s << "weak";
		need_comma = true;
	}
	if (need_termination) s << ")) ";
	return s.str();
}
static void emit_weak_alias(std::ostream& out, const string& alias_name, const string& target_name, bool emit_section = true)
{
	out << "extern struct uniqtype " << alias_name
		<< " __attribute__((weak,alias(\"" << target_name << "\")";
	if (emit_section)
	{
		out << ",section(\".data." << target_name
			/* To satisfy gcc's "section of alias `...' must match section of its target",
			 * we rather we even have to match the escape-hatch cruft (although it gets
			 * discarded after gcc has done the check). */
			<< ", \\\"awG\\\", @progbits, " << target_name << ", comdat#"
			<< "\")";
	}
	out <<"));"
		<< endl;
}
void write_master_relation(master_relation_t& r, 
	std::ostream& out, std::ostream& err, bool emit_void, bool emit_struct_def,
	std::set< std::string >& names_emitted,
	std::map< std::string, std::set< dwarf::core::iterator_df<dwarf::core::type_die> > >& types_by_name,
	bool emit_codeless_aliases,
	bool emit_subobject_names /* = false */)
{
	/* Keep in sync with liballocs_private.h! */
	if (emit_struct_def) cout << UNIQTYPE_DECLSTR;

	std::map< std::string, std::set< pair<string, string> > > name_pairs_by_name;
	
	/* Some types are too obscure to be considered for the codeless
	 * alias thing. Specifically, this is bitfields: if we have a 
	 * bitfield type called "int", it should not prevent us choosing
	 * a generic alias "int". */
	std::map< std::string, std::set< string > > codeless_alias_blacklist;
	
	/* Note the very nasty hack with __attribute__((section (...))): 
	 * we embed a '#' into the section string, after adding our own
	 * assembler-level flags and attributes. This causes the compiler-
	 * -generated flags and attributes to be ignored, because the '#' 
	 * comments them out. Without this trick, there is no way of supplying
	 * our own section flags and attributes to override the compiler.
	 * FIXME: this works with gcc-generated assembly but not clang's.
	 * Borrow glibc's somewhat-portable way of doing this, if that fixes things.
	 * FIXME: fix the same thing elsewhere, too. */
	if (emit_void)
	{
		/* DWARF doesn't reify void, but we do. So output a rec for void first of all.
		 * We make it void so that multiple definitions in the same final link do not
		 * cause a problem. */
		auto emit_empty_subobject_names = [&out](const string& name) {
			out << "const char *" << mangle_typename(make_pair(string(""), name))
				<< "_subobj_names[] "
				<< " __attribute__((section (\".data.__uniqtype__" << name
					<< ", \\\"awG\\\", @progbits, __uniqtype__" << name << ", comdat#\")))"
				<< "= { (void*)0 };\n";
		};
		
		out << "\n/* uniqtype for void */\n";
		if (emit_subobject_names) emit_empty_subobject_names("void");
		string mangled_name = mangle_typename(make_pair(string(""), string("void")));
		write_uniqtype_open_void(out,
			mangled_name,
			"void",
			string("void")
		);
		write_uniqtype_related_dummy(out);
		write_uniqtype_close(out, mangled_name);
		
		/* We also now emit two further "special" types: the type of
		 * generic pointers, and the type of uninterpreted bytes. */
		out << "\n/* uniqtype for generic pointers */\n";
		if (emit_subobject_names) emit_empty_subobject_names("__EXISTS1___PTR__1");
		mangled_name = mangle_typename(make_pair(string(""), string("__EXISTS1___PTR__1")));
		/* How do we model a generic pointer? */
		write_uniqtype_open_generic(out,
			mangled_name,
			"__EXISTS1___PTR__1",
			"8" /* FIXME HACK FIXME HACK */
		);
		out << "{ address: { .kind = ADDRESS, .genericity = 1, .indir_level = 1 } },\n\t"
			<< "/* make_precise */ __liballocs_make_precise_identity, /* related */ {\n\t\t";
		write_uniqtype_related_dummy(out);
		write_uniqtype_close(out, mangled_name);
		
		out << "\n/* uniqtype for uninterpreted bytes */\n";
		if (emit_subobject_names) emit_empty_subobject_names("__uninterpreted_byte");
		mangled_name = mangle_typename(make_pair(string(""), string("__uninterpreted_byte")));
		write_uniqtype_open_generic(out,
			mangled_name,
			"__uninterpreted_byte",
			"1"
		);
		out << "{ base: { .kind = BASE, .enc = 0 /* no encoding */ } },\n\t"
			<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
		write_uniqtype_related_dummy(out);
		write_uniqtype_close(out, mangled_name);
		
	}
	else // always declare them, at least, with weak attribute
	{
		const char *raw_names[] = { "void", "__EXISTS1___PTR__1", "__uninterpreted_byte" };
		for (const char **p_n = &raw_names[0];
			p_n != raw_names + (sizeof raw_names / sizeof raw_names[0]);
			++p_n)
		{
			const char *n = *p_n;
			out << "extern struct uniqtype " << mangle_typename(make_pair(string(""), string(n)))
				<< " __attribute__((weak));" << endl;
		}
	}
	
	/* The complement relation among signed and unsigned integer types. */
	map<unsigned, map<bool, set< master_relation_t::value_type > > > integer_base_types_by_size_and_signedness;
	auto needs_complement = [](iterator_df<base_type_die> base_t) {
		return (base_t->get_encoding() == DW_ATE_signed
			 || base_t->get_encoding() == DW_ATE_unsigned)
			 && base_t->bit_size_and_offset().second == 0; 
			 /* HACK: only complement zero-off cases for now, since we don't track the 
			  * bit offset in the big _by_size_and_signedness map. */
	};
	auto avoid_aliasing_as = [&codeless_alias_blacklist](const string& alias,
		const string& codestring, iterator_df<type_die> t) {
		if (!t.is_a<base_type_die>()) return false;
		auto base_t = t.as_a<base_type_die>();
		/* Funky bitfield types are 
		 * too obscure to be considered for codeless aliasing. */
		return (base_t->bit_size_and_offset().second != 0
			|| base_t->bit_size_and_offset().first != 8 * (*base_t->calculate_byte_size()));
	};
	/* Emit forward declarations, building the complement relation as we go. */
	set<string> names_previously_emitted;
	for (auto i_pair = r.begin(); i_pair != r.end(); ++i_pair)
	{
		auto name = i_pair->first;
		string s = mangle_typename(name);
		bool not_previously_emitted = names_emitted.insert(s).second;
		if (!not_previously_emitted)
		{
			names_previously_emitted.insert(s);
			// don't skip the rest; complement stuff to do, and harmless to forward-decl it again
		}
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
				unsigned bit_size = base_t->bit_size_and_offset().first;
				bool signedness = (base_t->get_encoding() == DW_ATE_signed);

				// HACK: for now, skip weird cases with bit offset non-zero
				if (base_t->bit_size_and_offset().second == 0)
				{
					integer_base_types_by_size_and_signedness[bit_size][signedness].insert(*i_pair);
				}
			}
			if (avoid_aliasing_as(name.second, name.first, t))
			{
				codeless_alias_blacklist[name.second].insert(name.first);
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
			<< "/* synthetic signedness complement of " << (*i_need_comp)->get_canonical_name()
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
		string mangled_name = mangle_typename(i_vert->first);
		if (names_previously_emitted.find(mangled_name) != names_previously_emitted.end())
		{
			// we think we have done this one already, probably as an ARR0
			out << "\n/* We should have previously output a definition of uniqtype for \""
				<< i_vert->first.second 
				<< "\" with summary code " << i_vert->first.first << " */\n";
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
				opt<Dwarf_Unsigned> opt_offset = i_edge->byte_offset_in_enclosing_type(
					true /* assume packed -- needed for synthetic types' members */);
				if (!opt_offset)
				{
					err << "Warning: member " << i_edge.summary()
						<< " has no byte offset, so skipping" << std::endl;
					continue;
				}
				else
				{ 
					real_members.push_back(i_edge); 
					real_member_offsets.push_back(*opt_offset);
				}
			}
		}
		unsigned members_count = real_members.size();
		
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
		
		// we might not be incomplete, but be dependent on an incomplete somehow (e.g. points-to)
		bool dependent_on_incomplete = (i_vert->first.first == "");
		// AARGH. Functions don't count. If we're a pointer to a function, then
		
		/* We can also be *variable-length*. In this case we output a pos_maxoff of -1
		 * i.e. maximum-unsigned-value. */
		if (emit_subobject_names)
		{
			out << "const char *" << mangled_name << "_subobj_names[] ";
			out << attributes_for_uniqtype(mangled_name, /* weak */ true,
				/* include section */ !dependent_on_incomplete);
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
			unsigned array_len;
			auto opt_array_len = i_vert->second.as_a<array_type_die>()->element_count();
			if (opt_array_len) array_len = *opt_array_len;
			else array_len = 0;
			if (array_len > 0)
			{
				write_uniqtype_open_array(out,
					mangled_name,
					i_vert->first.second,
					(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
					array_len
				);
			}
			else
			{
				/* FIXME: we should really distinguish the other cases of zero/0-length
				 * arrays. For now, just assume that the memory-bounds flex treatment
				 * is appropriate.*/
				write_uniqtype_open_flex_array(out, mangled_name, i_vert->first.second,
					optional<string>());
			}
			
			// compute and print destination name
			auto k = canonical_key_for_type(i_vert->second.as_a<array_type_die>()->get_type());
			/* FIXME: do multidimensional arrays get handled okay like this? 
			 * I reckon so, but am not yet sure. */
			string mangled_name = mangle_typename(k);
			write_uniqtype_related_array_element_type(out,
				mangled_name
			);
		}
		else if (i_vert->second.is_a<string_type_die>())
		{
			auto opt_fixed_size = i_vert->second.as_a<string_type_die>()->fixed_length_in_bytes();
			write_uniqtype_open_array(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				(opt_fixed_size ? *opt_fixed_size : 0)
			);
			/* FIXME */
			write_uniqtype_related_array_element_type(out, string("__uniqtype__unsigned_char$8"));
		}
		else if (i_vert->second.is_a<address_holding_type_die>())
		{
			auto t = i_vert->second.as_a<address_holding_type_die>();
			pair<unsigned, iterator_df<type_die> > ultimate_pointee_pair
			 = t.as_a<address_holding_type_die>()->find_ultimate_reached_type();
			unsigned indir_level = ultimate_pointee_pair.first;
			auto ultimate_pointee = ultimate_pointee_pair.second;
			bool is_generic = t.enclosing_cu()->is_generic_pointee_type(ultimate_pointee);
			unsigned machine_word_size = t.enclosing_cu()->get_address_size();
			bool pointee_is_codeless = false;
			if (i_vert->first.first == "") // empty summary code means we point to incomplete
			{
				pointee_is_codeless = true;
				if (ultimate_pointee.is_a<with_data_members_die>())
				{
					assert(ultimate_pointee.as_a<with_data_members_die>()->get_declaration());
					assert(*ultimate_pointee.as_a<with_data_members_die>()->get_declaration());
				}
				else
				{
					assert(ultimate_pointee.is_a<unspecified_type_die>());
					// what to do now? it's like a pointer to a fresh opaque?
				}
				//{
				//	/* HMM. Why should we get codeless subprogram types? */
				//	assert(concrete_ultimate_t.is_a<type_describing_subprogram_die>());
				//}
			}
			write_uniqtype_open_address(out,
				mangled_name,
				i_vert->first.second,
				*t->calculate_byte_size(),
				is_generic ? 0 : indir_level,
				is_generic,
				ceil(log2(machine_word_size)), /* HMM -- may be wrong on some machines */
				optional<string>(),
				/* use_section_group */ !pointee_is_codeless,
				/* emit_weak_definition */ pointee_is_codeless
			);
			// compute and print destination name
			auto k1 = canonical_key_for_type(t->get_type());
			string mangled_name1 = mangle_typename(k1);
			write_uniqtype_related_pointee_type(out, mangled_name1);
			auto k2 = canonical_key_for_type(ultimate_pointee);
			string mangled_name2 = mangle_typename(k2);
			write_uniqtype_related_ultimate_pointee_type(out, mangled_name2);
		}
		else if (i_vert->second.is_a<type_describing_subprogram_die>())
		{
			write_uniqtype_open_subprogram(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				/* narg */ fp_types.size(),
				/* nret */ 1,
				/* is_va */ 0 /* FIXME */,
				/* cc */ 0 /* FIXME */
			);
			/* Output the return type and argument types. We always output
			 * a return type, even if it's &__uniqtype__void. */
			auto return_type = i_vert->second.as_a<type_describing_subprogram_die>()->find_type();
			write_uniqtype_related_subprogram_return_type(out,
				true, mangle_typename(canonical_key_for_type(return_type)));
			
			for (auto i_t = fp_types.begin(); i_t != fp_types.end(); ++i_t)
			{
				write_uniqtype_related_subprogram_argument_type(out,
					mangle_typename(canonical_key_for_type(*i_t))
				);
				
				++contained_length;
			}
		}
		else if (i_vert->second.is_a<subrange_type_die>()) // FIXME
		{
			auto base_t = i_vert->second.as_a<subrange_type_die>()->find_type();
			write_uniqtype_open_subrange(out,
				mangled_name,
				i_vert->first.second,
				(opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0)) /* pos_maxoff */,
				0 /* FIXME */,
				0 /* FIXME */
			);
			write_uniqtype_related_dummy(out);
		}
		else if (i_vert->second.is_a<base_type_die>())
		{
			auto bt = i_vert->second.as_a<base_type_die>();
			
			/* As of DWARF4, we're allowed to have *either* bit_size *or* byte_size,
			 * or alternatively, both! The "both" case is already handled, and so
			 * is the "bit size only", by calculate_byte_size.
			 * we need to handle the case where the byte size
			 * must be calculated from the bit size, as ceil (bit_size / 8). */
			
			unsigned byte_size = opt_sz ? (int) *opt_sz : (real_members.size() > 0 ? -1 : 0);
			pair<Dwarf_Unsigned, Dwarf_Unsigned> bit_size_and_offset = bt->bit_size_and_offset();
			unsigned bit_size = bit_size_and_offset.first;
			unsigned bit_offset = bit_size_and_offset.second;
			signed bit_size_delta = 8 * byte_size - bit_size;
			
			unsigned one_plus_log_to_use;
			signed diff_to_use;
			signed offset_to_use;
			
			if (bit_size_delta)
			{
				unsigned highest_po2_ordinal = 8 * sizeof (unsigned long) - nlz1(bit_size_delta) - 1;
				unsigned next_lower_po2 = (1u<<highest_po2_ordinal);
				unsigned next_higher_po2 = (1u<<(1+highest_po2_ordinal));
				signed diff_lower = bit_size_delta - next_lower_po2; // will be positive
				signed diff_higher = bit_size_delta - next_higher_po2; // will be negative
				
				
				if (diff_lower < 128)
				{
					/* Use this one */
					one_plus_log_to_use = 1 + highest_po2_ordinal;
					diff_to_use = diff_lower;
				}
				else if (diff_higher >= -128)
				{
					one_plus_log_to_use = 2 + highest_po2_ordinal;
					diff_to_use = diff_higher;
				}
				else /* we can't represent this */
				{
					cerr << "Warning: cannot represent bit size with delta " 
						<< bit_size_delta
						<< endl;
					one_plus_log_to_use = 0;
					diff_to_use = 0;
				}
			}
			else // it's just the 8 * byte size
			{
				one_plus_log_to_use = 0;
				diff_to_use = 0;
			}
			
			// same job for the bit offset
			signed bit_offset_to_use;
			// prefer positive bit offsets, but...
			// NOTE that this will only arise if/when we have absurdly wide integers
			if (bit_offset >= 512)
			{
				if (8 * byte_size - bit_offset < 512)
				{
					// i.e. negative means "from other end"
					bit_offset_to_use = -(8 * byte_size - bit_offset); 
				}
				else
				{
					// can't represent this
					cerr << "Warning: cannot represent bit offset  " 
						<< bit_offset
						<< endl;
					bit_offset_to_use = 0;
				}
			} else bit_offset_to_use = bit_offset;
				
			write_uniqtype_open_base(out,
				mangled_name,
				i_vert->first.second,
				byte_size /* pos_maxoff */,
				i_vert->second.as_a<base_type_die>()->get_encoding(),
				one_plus_log_to_use /* one_plus_log_bit_size_delta, up to 15 i.e. delta of up to 2^15 from implied bit size */,
				diff_to_use /* bit_size_delta_delta, up to +- 127 */,
				bit_offset_to_use /* bit_offset, up to +- 512 */
			);
		
			if (needs_complement(bt))
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
		else if (i_vert->second.is_a<unspecified_type_die>())
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
				auto k = canonical_key_for_type(i_edge->find_or_create_type_handling_bitfields());
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
			cerr << "Saw an unknown type of tag: " <<
				i_vert->second.spec_here().tag_lookup(
					i_vert->second.tag_here()
				)
				<< endl;
			// assert(false);
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
					emit_weak_alias(out, mangle_typename(complement_name_pair), /* existing name */ mangle_typename(k));
					name_pairs_by_name[compl_equiv[0]].insert(complement_name_pair);
					if (avoid_aliasing_as(compl_equiv[0], complement_name_pair.first,
						i_vert->second))
					{
						codeless_alias_blacklist[compl_equiv[0]].insert(complement_name_pair.first);
					}
				}
			}
		}
		
		/* Output any (typedef-or-base-type) aliases for this type. NOTE that here we are
		 * assuming that the canonical name for any base type (used above) is not the same as its
		 * programmatic name (aliased here). */
		for (auto i_alias = r.aliases[i_vert->second].begin(); 
			i_alias != r.aliases[i_vert->second].end();
			++i_alias)
		{
			emit_weak_alias(out, mangle_typename(make_pair(i_vert->first.first, *i_alias)), mangle_typename(i_vert->first), i_vert->first.first != "");
			types_by_name[*i_alias].insert(i_vert->second);
			name_pairs_by_name[*i_alias].insert(i_vert->first);
			if (avoid_aliasing_as(*i_alias, i_vert->first.first, i_vert->second))
			{
				codeless_alias_blacklist[*i_alias].insert(i_vert->first.first);
			}
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
			std::vector<const pair<string, string> *> aliases_to_consider;
			for (auto i = i_by_name_pair->second.begin(); i != i_by_name_pair->second.end();
				++i)
			{
				const string& codeful = i->first;
				if (codeless_alias_blacklist[i->second].find(codeful)
						== codeless_alias_blacklist[i->second].end())
				{
					aliases_to_consider.push_back(&*i);
				}
			}
			
			if (aliases_to_consider.size() == 1)
			{
				/* This name only denotes one type, so we can alias it if it's complete. */
				auto& full_name_pair = **aliases_to_consider.begin();
				if (full_name_pair.first != "")
				{
					string full_name = mangle_typename(full_name_pair);
					pair<string, string> abbrev_name_pair = make_pair("", i_by_name_pair->first);
					string abbrev_name = mangle_typename(abbrev_name_pair);
					emit_weak_alias(out, mangle_typename(abbrev_name_pair), cxxgen::escape(full_name));
				}
			}
			else
			{
				out << "/* Not aliasing \"" << i_by_name_pair->first << "\"; set is {\n";
				for (auto i_t = aliases_to_consider.begin(); i_t != aliases_to_consider.end(); ++i_t)
				{
					if (i_t != aliases_to_consider.begin()) cout << ",\n";
					out << "\t" << mangle_typename(**i_t);
				}

				out << "\n} */" << endl;
			}
		}
	}
}

static void write_uniqtype_open_generic(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	const string& pos_maxoff_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	o << "struct uniqtype " << mangled_typename
	  << attributes_for_uniqtype(mangled_typename, make_weak_definition, use_section_group)
	  << " = {\n\t"
	  << "{ 0, 0, 0 },\n\t"
	  << pos_maxoff_str << " /* pos_maxoff */,\n\t";
}

static void write_uniqtype_open_generic(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	unsigned pos_maxoff,
	bool use_section_group = true,
	bool make_weak_definition = false
	)
{
	std::ostringstream s; s << pos_maxoff;
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, s.str(),
		use_section_group, make_weak_definition);
}

void write_uniqtype_open_void(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	optional<string> maxoff_comment_str
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
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff);
	o << "{ array: { 1, " << nelems << " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_flex_array(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	std::ostringstream s; s << UNIQTYPE_POS_MAXOFF_UNBOUNDED;
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, s.str());
	o << "{ array: { 1, " << UNIQTYPE_ARRAY_LENGTH_UNBOUNDED << " } },\n\t"
		<< "/* make_precise */ __liballocs_make_array_precise_with_memory_bounds, /* related */ {\n\t\t";
}
void write_uniqtype_open_address(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	unsigned pos_maxoff,
	unsigned indir_level,
	bool is_generic,
	unsigned log_min_align,
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff,
		use_section_group, make_weak_definition);
	o << "{ address: { ADDRESS, " << indir_level << ", " << is_generic << ", " << log_min_align
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_base(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	unsigned pos_maxoff,
	unsigned enc,
	unsigned one_plus_log_bit_size_delta,
	signed bit_size_delta_delta,
	signed bit_off,
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff, use_section_group, make_weak_definition);
	o << "{ base: { BASE, " << enc
		<< ", " << one_plus_log_bit_size_delta
		<< ", " << bit_size_delta_delta
		<< ", " << bit_off
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_subrange(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	unsigned pos_maxoff,
	signed min,
	signed max,
	optional<string> comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff, use_section_group, make_weak_definition);
	o << "{ subrange: { SUBRANGE, " << min
		<< ", " << max
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_enumeration(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	unsigned pos_maxoff,
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff, use_section_group, make_weak_definition);
	o << "{ enumeration: { ENUMERATION, 0, 0, 0 } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
}
void write_uniqtype_open_composite(std::ostream& o,
	const string& mangled_typename,
	const string& unmangled_typename,
	unsigned pos_maxoff,
	unsigned nmemb,
	bool not_simultaneous,
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff, use_section_group, make_weak_definition);
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
	optional<string> maxoff_comment_str,
	bool use_section_group,
	bool make_weak_definition
	)
{
	write_uniqtype_open_generic(o, mangled_typename, unmangled_typename, pos_maxoff, use_section_group, make_weak_definition);
	o << "{ subprogram: { SUBPROGRAM, " << narg 
		<< ", " << nret 
		<< ", " << is_va
		<< ", " << cc
		<< " } },\n\t"
		<< "/* make_precise */ (void*)0, /* related */ {\n\t\t";
	
}
void write_uniqtype_related_array_element_type(std::ostream& o,
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
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
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
	)
{
	/* begin the struct */
	o << "{ { t: { ";
	if (maybe_mangled_typename) o << "&" << *maybe_mangled_typename;
	else o << "(void*) 0";
	o << " } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}
void write_uniqtype_related_ultimate_pointee_type(std::ostream& o,
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
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
void write_uniqtype_related_subprogram_argument_type(std::ostream& o,
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
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
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
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
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
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
	optional<string> maybe_mangled_typename,
	optional<string> comment_str
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
	optional<string> comment_str
	)
{
	/* begin the struct */
	o << "{ { t: { (void*) 0 } } }";
	if (comment_str) o << " /* " << *comment_str << " */ ";
}

void write_uniqtype_close(std::ostream& o, const string& mangled_name, optional<unsigned> n_contained)
{
	o << "\n\t}";
	o << "\n};\n";
	if (n_contained) o << ensure_contained_length(mangled_name, *n_contained);
}

static void for_each_uniqtype_reference_in(const string &filename,
	std::function<void(const string&)> f)
{
	FILE *in = popen((string("nm -fposix -u '") + filename
	 + "' | sed -r 's/[[:blank:]]*[Uw][[:blank:]]*$//' | grep __uniqtype").c_str(), "r");
	assert(in);
	
	int ret;
	char *line = NULL;
	size_t line_len;
	/* Now popen our input, read lines and match them against the map we just built. */
	while (ret = getline(&line, &line_len, in), ret > 0)
	{
		string key(line);
		// trim the newline, if any
		boost::trim(key);
		f(key);
		
		free(line);
		line = NULL;
	}
	fclose(in);
}
int dump_usedtypes(const vector<string>& fnames, std::ostream& out, std::ostream& err)
{
	using core::root_die;
	using std::unique_ptr;
	
	std::vector<std::unique_ptr<std::ifstream> > infstreams(fnames.size()); 
	std::vector<std::unique_ptr<root_die> > rs(fnames.size());
	
	/* The codeless map, alias map and and master relation are shared across 
	 * *all* files that we process. */
	multimap<string, iterator_df<type_die> > types_by_codeless_uniqtype_name;
	master_relation_t master_relation;
	multimap<string, pair<string, string> > aliases_needed;
	
	for (unsigned i = 0; i < fnames.size(); ++i)
	{
		const string& fname = fnames.at(i);
		infstreams[i] = std::move(unique_ptr<std::ifstream>(new std::ifstream(fname)));
		std::ifstream & infstream = *infstreams[i];
		if (!infstream) 
		{
			err << "Could not open file " << fname << endl;
			return 1;
		}

		rs[i] = std::move(unique_ptr<root_die>(new root_die(fileno(infstream))));
		root_die &r = *rs[i];
		get_types_by_codeless_uniqtype_name(types_by_codeless_uniqtype_name, 
			r.begin(), r.end());
		
		auto f = [&](const string& key) {
			// FIXME: escape single quotes
			auto found_pair = types_by_codeless_uniqtype_name.equal_range(key);
			unsigned found_count = srk31::count(found_pair.first, found_pair.second);
		
			switch (found_count)
			{
				case 0:
					err << "Found no match for " << key << endl;
					/* HACK around CIL brokenness: if we contain the string 
					 *     "__FUN_FROM___FUN_TO_" 
					 * then match against
					 *     "__FUN_FROM___VA___FUN_TO_" 
					 * since CIL typesigs don't distinguish between 
					 * "no specified parameters"        e.g. int f() 
					 * and "specified as no parameters" e.g. int f(void).
					 * 
					 * This will ensure that some type gets emitted, such that we
					 * can bind up the UNDefined uniqtype to it. 
					 * BUT
					 * We will emit it under its rightful name, so the reference
					 * won't get bound just like that. Previously we dealt with
					 * this by creating an alias, but in fact we need to emit
					 * the uniqtype *again* under the correct section name. 
					 * Otherwise the name we want might get eliminated by COMDAT
					 * if a non-worked-around section appears in the same link.
					 */
					{
						string search_expr = "__FUN_FROM___FUN_TO_";
						string replace_expr = "__FUN_FROM___VA___FUN_TO_";
						string::size_type pos = key.find(search_expr);
						if (pos != string::npos)
						{
							string substitute_key = key;
							substitute_key.replace(pos, search_expr.size(), replace_expr);

							auto found_retry_pair = types_by_codeless_uniqtype_name.equal_range(substitute_key);
							if (found_retry_pair.first != found_retry_pair.second)
							{
								err << "Working around CIL bug by substituting " << substitute_key << endl;
								auto name_pair = transitively_add_type(found_retry_pair.first->second, master_relation).second;

								string orig_substitute_key = substitute_key;

								substitute_key.replace(0, string("__uniqtype_").size(), "__uniqtype_" + name_pair.first);

								string orig_key_symname = key;
								orig_key_symname.replace(0, string("__uniqtype_").size(), "__uniqtype_" + name_pair.first);

								aliases_needed.insert(make_pair(orig_key_symname, make_pair(orig_substitute_key, substitute_key)));
								break;
							}
						}
					}
					err << "Defined are: ";
					for (auto i_tname = types_by_codeless_uniqtype_name.begin(); i_tname != types_by_codeless_uniqtype_name.end(); ++i_tname)
					{
						if (i_tname != types_by_codeless_uniqtype_name.begin()) err << ", ";
						err << i_tname->first;
					}
					err << endl;
					return 1;
				case 1: 
					// out << "Found match for " << key << ": " << found_pair.first->second << endl;
					transitively_add_type(found_pair.first->second, master_relation);
					break;

				default: 
					cerr << "Found multiple matches (" << found_count << ") for " << key << ": " << endl;
					auto first_found = found_pair.first;
					multimap<opt<uint32_t>, decltype(found_pair.first)> by_code;
					for (auto i_print = found_pair.first; i_print != found_pair.second; ++i_print)
					{
						auto code = type_summary_code(i_print->second);
						by_code.insert(make_pair(code, i_print));
						cerr << "\t" 
							<< i_print->second
							<< " (code: " 
							<< summary_code_to_string(code) 
							<< ")" << endl;
					}
					/* Do they all seem to be identical? */
					auto range_equal_to_first = by_code.equal_range(type_summary_code(first_found->second));
					if (srk31::count(range_equal_to_first.first, range_equal_to_first.second)
					 == found_count)
					{
						auto code = type_summary_code(first_found->second);
						cerr << "They all seem to be identical (code " 
							<< (code ? *code : -1)
							<< ") so proceeding." << endl;
						transitively_add_type(first_found->second, master_relation);
					}
					else 
					{
						cerr << "Not identical, so not proceeding." << endl;
						return 1;
					}
				// end case default
			}

		};
		
		for_each_uniqtype_reference_in(fname, f);
		
	} // end for each input file

	// write the types to stdout
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	map< iterator_df<type_die>, set<string> > names_by_type;
	write_master_relation(master_relation, out, cerr, true /* emit_void */, true, 
		names_emitted, types_by_name, true);
	
	// for CIL workaround: for each alias, write a one-element master relation
	// defining it under the alias name (do *not* use the other name at all!)
	for (auto i_pair = aliases_needed.begin(); i_pair != aliases_needed.end(); ++i_pair)
	{
		//out << "extern struct uniqtype " << i_pair->first << " __attribute__((alias(\"" << i_pair->second << "\")));"
		// 	<< endl;
		
		// i_pair is (orig_key_symname, (orig_substitute_key, substitute_key_with_typecode))
		// and we need to look up in types_by_uniqtype_name by orig_substitute_key
		
		auto found = types_by_codeless_uniqtype_name.equal_range(i_pair->second.first);
		assert(found.first != found.second || (cerr << i_pair->second.first << endl, false));
		
		master_relation_t tmp_master_relation;
		string unmangled_name = i_pair->first;
		unmangled_name.replace(0, string("__uniqtype_........_").size(), "");
		string insert = i_pair->first.substr(string("__uniqtype_").size(), 8);
		tmp_master_relation.insert(make_pair(make_pair(insert, unmangled_name), found.first->second));
		
		set<string> tmp_names_emitted;
		map<string, set< iterator_df<type_die> > > tmp_types_by_name;
		write_master_relation(tmp_master_relation, out, err, false /* emit_void */, false, 
			tmp_names_emitted, tmp_types_by_name, true);
	}
	
	return 0;
}
