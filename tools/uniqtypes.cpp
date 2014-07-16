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
#include <cxxgen/cxx_compiler.hpp>
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
using dwarf::core::type_describing_subprogram_die;
using dwarf::core::program_element_die;
using dwarf::core::compile_unit_die;
using dwarf::core::member_die;
using dwarf::core::with_data_members_die;
using dwarf::core::variable_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::base_type_die;
using dwarf::core::array_type_die;
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

void write_master_relation(master_relation_t& r, dwarf::core::root_die& root, 
	std::ostream& out, std::ostream& err, bool emit_void, bool emit_struct_def, 
	std::set< std::string >& names_emitted,
	std::map< std::string, std::set< dwarf::core::iterator_df<dwarf::core::type_die> > >& types_by_name,
	bool emit_codeless_aliases)
{
	/* Keep in sync with liballocs_private.h! */
	if (emit_struct_def) cout << "struct uniqtype_cache_word \n\
{\n\
	unsigned long addr:47;\n\
	unsigned flag:1;\n\
	unsigned bits:16;\n\
};\n\
\n\
struct uniqtype \n\
{ \n\
	struct uniqtype_cache_word cache_word; \n\
	const char *name; \n\
	unsigned short pos_maxoff; \n\
	unsigned short neg_maxoff; \n\
	unsigned nmemb:12;         // 12 bits -- number of `contained's\n\
	unsigned is_array:1;       // 1 bit\n\
	unsigned array_len:19;\n\
	struct contained { \n\
		signed offset; \n\
		struct uniqtype *ptr; \n\
	} contained[]; \n\
};\n";

	std::map< std::string, std::set< pair<string, string> > > name_pairs_by_name;
	
	/* Note the very nasty hack with __attribute__((section (...))): 
	 * we embed a '#' into the section string, after adding our own
	 * assembler-level flags and attributes. This causes the compiler-
	 * -generated flags and attributes to be ignored, because the '#' 
	 * comments them out. Without this trick, there is no way of supplying
	 * our own section flags and attributes to override the compiler. */
	if (emit_void)
	{
		/* DWARF doesn't reify void, but we do. So output a rec for void first of all. */
		out << "\n/* uniqtype for void */\n";
		out << "struct uniqtype " << mangle_typename(make_pair(string(""), string("void")))
			<< " __attribute__((section (\".data.__uniqtype__void, \\\"awG\\\", @progbits, __uniqtype__void, comdat#\")))"
			<< " = {\n\t" 
			<< "{ 0, 0, 0 },\n\t"
			<< "\"void\"" << ",\n\t"
			<< "0" << " /* pos_maxoff (void) */,\n\t"
			<< "0" << " /* neg_maxoff (void) */,\n\t"
			<< "0" << " /* nmemb (void) */,\n\t"
			<< "0" << " /* is_array (void) */,\n\t"
			<< "0" << " /* array_len (void) */,\n\t"
			<< "/* contained */ { }\n};\n";
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
		string s = mangle_typename(i_pair->first);
		names_emitted.insert(s);
		types_by_name[i_pair->first.second].insert(i_pair->second);
		name_pairs_by_name[i_pair->first.second].insert(i_pair->first);
		if (i_pair->second.is_a<base_type_die>())
		{
			/* Are we an integer? */
			auto base_t = i_pair->second.as_a<base_type_die>();
			if (needs_complement(base_t))
			{
				unsigned size = *base_t->get_byte_size();
				bool signedness = (base_t->get_encoding() == DW_ATE_signed);

				// HACK: for now, skip weird cases with bit size/offset
				if (base_t->get_bit_offset() != 0 || 
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

		out << "extern struct uniqtype " << s << ";" << endl;
	}

	/* Output the canonical definitions. */
	for (auto i_vert = r.begin(); i_vert != r.end(); ++i_vert)
	{
		if (i_vert->first.second == string("void"))
		{
			err << "Warning: skipping explicitly declared void type from CU "
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
				opt<Dwarf_Unsigned> opt_offset = i_edge->byte_offset_in_enclosing_type(root, true);
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
			auto opt_array_len = i_vert->second.as_a<array_type_die>()->element_count(root);
			if (opt_array_len) array_len = *opt_array_len;
			else array_len = 0;
		} else if (i_vert->second.is_a<type_describing_subprogram_die>())
		{
			/* use array len to encode the number of fps */
			array_len = fp_types.size();
		} else if (i_vert->second.is_a<address_holding_type_die>())
		{
			/* HACK HACK HACK: encode the type's pointerness into array_len. 
			 * We should rationalise struct uniqtype to require less of this
			 * sort of thing. */
			array_len = /* MAGIC_LENGTH_POINTER */(1u << 19) - 1u;
		} else array_len = 0;
		string mangled_name = mangle_typename(i_vert->first);
		
		/* Our last chance to skip things we don't want to emit. */
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
		
		out << "struct uniqtype " << mangled_name
			<< " __attribute__((section (\"" << ".data." << mangled_name << ", \\\"awG\\\", @progbits, " << mangled_name << ", comdat#\")))"
			<< " = {\n\t" 
			<< "{ 0, 0, 0 },\n\t"
			<< "\"" << i_vert->first.second << "\",\n\t"
			<< (opt_sz ? (int) *opt_sz : -1) << " /* pos_maxoff " << (opt_sz ? "" : "(incomplete) ") << "*/,\n\t"
			<< "0 /* neg_maxoff */,\n\t"
			<< (i_vert->second.is_a<array_type_die>() ? 1 : members_count) << " /* nmemb */,\n\t"
			<< (i_vert->second.is_a<array_type_die>() ? "1" : "0") << " /* is_array */,\n\t"
			<< array_len << " /* array_len */,\n\t"
			<< /* contained[0] */ "/* contained */ {\n\t\t";

		if (i_vert->second.is_a<array_type_die>())
		{
			// array: write a single entry, for the element type
			out << "{ " << "0, ";

			// compute and print destination name
			auto k = canonical_key_from_type(i_vert->second.as_a<array_type_die>()->get_type());
			/* FIXME: do multidimensional arrays get handled okay like this? 
			 * I reckon so, but am not yet sure. */
			string mangled_name = mangle_typename(k);
			out << "&" << mangled_name;

			// end the struct
			out << " }";
		}
		else if (i_vert->second.is_a<address_holding_type_die>())
		{
			// array: write a single entry, for the target type
			out << "{ " << "0, ";

			// compute and print destination name
			auto k = canonical_key_from_type(i_vert->second.as_a<address_holding_type_die>()->get_type());
			string mangled_name = mangle_typename(k);
			out << "&" << mangled_name;

			// end the struct
			out << " }";
		}
		else if (i_vert->second.is_a<type_describing_subprogram_die>())
		{
			/* Output the return type and argument types. We always output
			 * a return type, even if it's &__uniqtype__void. */
			auto return_type = i_vert->second.as_a<type_describing_subprogram_die>()->find_type();
			/* begin the struct */
			out << "{ ";
			out << "0, ";
			out << "&" << mangle_typename(canonical_key_from_type(return_type));

			// end the struct
			out << " }";
			
			for (auto i_t = fp_types.begin(); i_t != fp_types.end(); ++i_t)
			{
				/* always write a comma */
				out << ",\n\t\t";

				/* begin the struct */
				out << "{ ";
				out << "0, ";
				out << "&" << mangle_typename(canonical_key_from_type(*i_t));

				// end the struct
				out << " }";
			}
		}
		else // non-array non-subprogram -- use real members
		{
			unsigned i_membernum = 0;
			std::set<lib::Dwarf_Unsigned> used_offsets;
			opt<iterator_base> first_with_byte_offset;
			auto i_off = real_member_offsets.begin();
			
			// we *always* output at least one array element
			if (members_count > 0)
			{
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
					auto k = canonical_key_from_type(i_edge->get_type());
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
			else
			{
				/* If we're a base type having a signedness-complement, output
				 * that, else output a null. */
				/* begin the struct */
				out << "{ " << 0 << ", ";
				
				if (i_vert->second.is_a<base_type_die>() && 
					needs_complement(i_vert->second.as_a<base_type_die>()))
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
					out << "&" << mangled_name;
				}
				else out << "(void*) 0";

				// end the struct
				out << " }";
			}
		}
		
		out << "\n\t}"; /* end contained */
		out << "\n};\n"; /* end struct uniqtype */
		
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
			out << "struct uniqtype " << compl_name
				<< " __attribute__((section (\"" << ".data." << compl_name << ", \\\"awG\\\", @progbits, " << compl_name << ", comdat#\")))"
				<< " = {\n\t" 
				<< "{ 0, 0, 0 },\n\t"
				<< "\"" << k.second << "\",\n\t"
				<< (opt_sz ? *opt_sz : 0) << " /* pos_maxoff " << (opt_sz ? "" : "(incomplete) ") << "*/,\n\t"
				<< "0 /* neg_maxoff */,\n\t"
				<< "0 /* nmemb */,\n\t"
				<< "0 /* is_array */,\n\t"
				<< "0 /* array_len */,\n\t"
				<< /* contained[0] */ "/* contained */ {\n\t\t"
				<< "{ 0, &" << mangled_name
				<< " }";
			out << "\n\t}"; /* end contained */
			out << "\n};\n"; /* end struct uniqtype */
			
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
						<< " __attribute__((alias(\"" << mangle_typename(k) << "\")));" << endl;
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
				<< " __attribute__((alias(\"" << mangle_typename(i_vert->first) << "\")));" << endl;
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
