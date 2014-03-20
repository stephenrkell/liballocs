#include "helpers.hpp"

#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <srk31/algorithm.hpp>

using std::cerr;
using std::endl;
using std::ostringstream;
using std::string;
using std::deque;
using namespace dwarf::core;
using dwarf::tool::abstract_c_compiler;

string summary_code_to_string(uint32_t code)
{
	ostringstream summary_string_str;
	summary_string_str << std::hex << std::setfill('0') << std::setw(2 * sizeof code) << code 
		<< std::dec;
	return summary_string_str.str();
}
string 
name_for_complement_base_type(iterator_df<base_type_die> base_t)
{
	/* For base types, we use our own language-independent naming scheme. */
	ostringstream name;
	unsigned size = *base_t->get_byte_size();
	auto encoding = base_t->get_encoding();
	assert(encoding == DW_ATE_signed || encoding == DW_ATE_unsigned);
	// assert we're not a weird bitty case
	assert(base_t->get_bit_offset() == 0 && 
		(!base_t->get_bit_size() || *base_t->get_bit_size() == 8 * size));
	
	name << ((base_t->get_encoding() == DW_ATE_signed) ? "uint" : "int")
		<< "$" << (8 * *base_t->get_byte_size());

	return name.str();
}

string 
name_for_base_type(iterator_df<base_type_die> base_t)
{
	/* For base types, we use our own language-independent naming scheme. */
	ostringstream name;
	unsigned size = *base_t->get_byte_size();
	switch (base_t->get_encoding())
	{
		case DW_ATE_signed:
			name << "int";
			break;
		case DW_ATE_unsigned: 
			name << "uint";
			break;
		default:
			name << string(base_t.spec_here().encoding_lookup(base_t->get_encoding())).substr(sizeof "DW_ATE_" - 1);
			break;
	}

	// weird cases of bit size/offset
	if (base_t->get_bit_offset() != 0 || 
		(base_t->get_bit_size() && *base_t->get_bit_size() != 8 * size))
	{
		// use the bit size and add a bit offset
		name << "$" << *base_t->get_bit_size() 
			<< "$" << (base_t->get_bit_offset() ? *base_t->get_bit_offset() : 0);
	} 
	else
	{
		name << "$" << (8 * size);
	}

	return name.str();
}

/* Subtlety about mangling: does "all names" mean mangled or no? 
 * We take the view that this is a DWARF-/source-level function, so no. 
 * Our caller has to mangle names. */
all_names_for_type_t::all_names_for_type_t() :
	void_case      ([this](iterator_df<type_die> t)            { return deque<string>(1, "void"); }), 
	qualified_case ([this](iterator_df<qualified_type_die> t)  { return operator()(t->get_unqualified_type()); }), 
	typedef_case   ([this](iterator_df<type_chain_die> t)      { 
		// we're a synonym
		assert(t.name_here());
		assert(t.is_a<type_chain_die>());
		deque<string> synonyms = operator()(t.as_a<type_chain_die>()->get_type());
		// append our name at the end (less canonical)
		synonyms.push_back(*name_for_type_die(t));
		return synonyms;
	}),
	base_type_case([this](iterator_df<base_type_die> t)        { 
		// we treat these like a typedef of the language-independent canonical name
		deque<string> synonyms(1, name_for_base_type(t.as_a<base_type_die>()));
		if (t.name_here())
		{
			synonyms.push_back(*name_for_type_die(t));
		}
		return synonyms;
	}),
	pointer_case([this](iterator_df<address_holding_type_die> t) {
		// get the name of whatever the target is, and prepend a prefix
		deque<string> all = operator()(t.as_a<address_holding_type_die>()->get_type());

		for (auto i_name = all.begin(); i_name != all.end(); ++i_name)
		{
			ostringstream prefix;
			switch (t.tag_here())
			{
				case DW_TAG_pointer_type: 
					prefix << "__PTR_"; break;
				case DW_TAG_reference_type:
					prefix << "__REF_"; break;
				case DW_TAG_rvalue_reference_type:
					prefix << "__RR_"; break;
				default:
					assert(false);
			}
			*i_name = prefix.str() + *i_name;
		}
		return all;		
	}),
	array_case([this](iterator_df<array_type_die> t) {
		auto array_t = t.as_a<array_type_die>();
		// get the name of whatever the element type is, and prepend a prefix
		deque<string> all = operator()(array_t->get_type());
		ostringstream array_prefix;
		opt<Dwarf_Unsigned> element_count = array_t->element_count();
		array_prefix << "__ARR" << (element_count ? *element_count : 0) << "_";

		for (auto i_name = all.begin(); i_name != all.end(); ++i_name)
		{
			*i_name = array_prefix.str() + *i_name;
		}
		return all;
	}),
	subroutine_case([this](iterator_df<subroutine_type_die> t) {
		// "__FUN_FROM_" ^ (labelledArgTs argTss 0) ^ (if isSpecial then "__VA_" else "") ^ "__FUN_TO_" ^ (stringFromSig returnTs) 		
		auto sub_t = t.as_a<subroutine_type_die>();
		deque<string> working;

		string funprefix = "__FUN_FROM_";
		working.push_back(funprefix);
		auto fps = sub_t.children().subseq_of<formal_parameter_die>();
		
		// get a feel for the size of the problem.
		cerr << "We have " << srk31::count(fps.first, fps.second) << " fps with [";
		for (auto i_fp = fps.first; i_fp != fps.second; ++i_fp)
		{
			if (i_fp != fps.first) cerr << ", ";
			deque<string> arg_allnames = operator()(i_fp->get_type());
			cerr << arg_allnames.size();
		}
		cerr << "] typenames." << endl;
		
		
		/* Invariant: the working deque consists of partial names for the function type, 
		 * such that all argument types up to the last iteration have been dealt with. 
		 
		 * For each fp we erase each deque element, then replace it with a sequence 
		 * of elements, one per name of the fp type. */
		unsigned argnum;
		for (auto i_fp = fps.first; i_fp != fps.second; ++i_fp, ++argnum)
		{
			cerr << "Set of working names is: {";
			for (auto i_working = working.begin(); i_working != working.end(); ++i_working)
			{
				if (i_working != working.begin()) cerr << ", ";
				cerr << *i_working;
			}
			cerr << endl;

			ostringstream argprefix;
			argprefix << "__ARG" << argnum << "_";

			deque<string> arg_allnames = operator()(i_fp->get_type());
			cerr << "Found an fp with " << arg_allnames.size() << " names" << endl;
			auto i_working = working.begin(); 
			while (i_working != working.end())
			{
				string working_str = *i_working;
				i_working = working.erase(i_working);
				cerr << "working size is now " << working.size() << ", we are "
					<< (i_working - working.begin()) << " from the start" << endl;
				bool was_at_end = (i_working == working.end());

				struct my_output_iter : public std::insert_iterator<std::deque<string> >
				{
					using insert_iterator::insert_iterator;
					deque<string>::iterator get_iter() const { return iter; }
				} i_insert(working, i_working);

				for (auto i_syn = arg_allnames.begin(); i_syn != arg_allnames.end(); ++i_syn)
				{
					*i_insert = working_str + argprefix.str() + *i_syn;
					cerr << "working size is now " << working.size() << ", we are "
						<< (i_working - working.begin()) << " from the start" << endl;
				}
				i_working = i_insert.get_iter();
				// if we were at the end before, we should be at the end now
				assert(!was_at_end || i_working == working.end());
				cerr << "working size is now " << working.size() << ", we are "
					<< (i_working - working.begin()) << " from the start" << endl;
			}
		}
		if (sub_t->is_variadic())
		{
			for (auto i_working = working.begin(); i_working != working.end(); ++i_working)
			{
				*i_working = "__VA_" + *i_working;
			}
		}	
		for (auto i_working = working.begin(); i_working != working.end(); ++i_working)
		{
			*i_working = *i_working + "__FUN_TO_";
		}

		deque<string> all_retnames = operator()(sub_t->get_type());
		auto i_working = working.begin(); 
		while (i_working != working.end())
		{
			string working_str = *i_working;
			i_working = working.erase(i_working);
			bool was_at_end = (i_working == working.end());

			struct my_output_iter : public std::insert_iterator<std::deque<string> >
			{
				using insert_iterator::insert_iterator;
				deque<string>::iterator get_iter() const { return iter; }
			} i_insert(working, i_working);

			for (auto i_syn = all_retnames.begin(); i_syn != all_retnames.end(); ++i_syn)
			{
				*i_insert = working_str + *i_syn;
			}
			i_working = i_insert.get_iter();
			// if we were at the end before, we should be at the end now
			assert(!was_at_end || i_working == working.end());
		}

		return working;
	}),
	with_data_members_case([this](iterator_df<with_data_members_die> t) {
		// we're a named struct/union/class type or an enumeration
		return deque<string>(1, t.name_here() ? *name_for_type_die(t) : offset_to_string(t.offset_here()));
	}), 
	default_case([this](iterator_df<type_die> t) -> deque<string> {
		// we're probably a subrange type
		return deque<string>(1, t.name_here() ? *name_for_type_die(t) : offset_to_string(t.offset_here()));
	})
{} // constructor body

//all_names_for_type(iterator_df<type_die> t)
deque<string> all_names_for_type_t::operator()(iterator_df<type_die> t) const
{
	if (!t) return void_case(t);
	if (t != t->get_unqualified_type()) return qualified_case(t.as_a<qualified_type_die>());
	if (t != t->get_concrete_type()) return typedef_case(t.as_a<type_chain_die>());
	if (t.is_a<base_type_die>()) return base_type_case(t.as_a<base_type_die>());
	if (t.is_a<address_holding_type_die>()) return pointer_case(t.as_a<address_holding_type_die>());
	if (t.is_a<array_type_die>()) return array_case(t.as_a<array_type_die>());
	if (t.is_a<subroutine_type_die>()) return subroutine_case(t.as_a<subroutine_type_die>());
	if (t.is_a<with_data_members_die>()) return with_data_members_case(t.as_a<with_data_members_die>());
	return default_case(t);
}

all_names_for_type_t default_all_names_for_type;

uniqued_name
canonical_key_from_type(iterator_df<type_die> t)
{
	assert(t);
	t = t->get_concrete_type();

	/* we no longer use the defining_header -- use instead
	 * the type summary code */
	uint32_t code = type_summary_code(t);
	string summary_string = summary_code_to_string(code);
	assert(summary_string.size() == 2 * sizeof code);
	
	if (!t.is_a<address_holding_type_die>() && !t.is_a<array_type_die>() && !t.is_a<subroutine_type_die>())
	{
		/* for base types, the canonical key is *always* the summary code *only*, 
		 * i.e. the name component is empty. UNLESS we can place ourselves in a C
		 * equivalence class, in which case.... */
		string name_to_use;
		if (t.is_a<base_type_die>())
		{
// 			optional<string> c_normalized_name;
// 			if (t.name_here())
// 			{
// 				const char **c_equiv_class = abstract_c_compiler::get_equivalence_class_ptr(
// 					t.name_here()->c_str());
// 				if (c_equiv_class)
// 				{
// 					c_normalized_name = c_equiv_class[0];
// 				}
// 			}
			
			/* For base types, we use our own language-independent naming scheme. */
			name_to_use = name_for_base_type(t.as_a<base_type_die>());
		} 
		else
		{
			/* FIXME: deal with nested/qualified names also (nested data types, 
			   local data types, C++ namespaces). */
			/* FIXME: deal with struct/union tags also (but being sensitive to language: 
			   don't do it with C++ CUs). */
			name_to_use = t.name_here() ? *name_for_type_die(t) : offset_to_string(t.offset_here());
		}
// 		else // t->name_here() && t.tag_here() == DW_TAG_base_type
// 		{
// 			assert(t.name_here() && t.tag_here() == DW_TAG_base_type);
// 			string name_to_search_for = *t.name_here();
// 			// search equiv classes for a type of this name
// 			for (const char ** const*p_equiv = &abstract_c_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
// 			{
// 				// assert this equiv class has at least one element
// 				assert((*p_equiv)[0] != NULL);
// 				
// 				for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
// 				{
// 					// is this the relevant equiv class?
// 					if (name_to_search_for == string(*p_el))
// 					{
// 						// yes, so grab its first element
// 						name_to_use = (*p_equiv)[0];
// 						break;
// 					}
// 				}
// 				if (name_to_use != "") break; // we've got it
// 			}
// 			
// 			// if we've still not got it....
// 			if (name_to_use == "") name_to_use = name_to_search_for;
// 			
// 			assert(name_to_use != "char"); // ... for example. It should be "signed char" of course! since cxx_compiler.cpp puts that one first
// 		}

		return make_pair(summary_string, name_to_use);
	}
	else if (t.is_a<subroutine_type_die>())
	{
		// "__FUN_FROM_" ^ (labelledArgTs argTss 0) ^ (if isSpecial then "__VA_" else "") ^ "__FUN_TO_" ^ (stringFromSig returnTs) 		
		ostringstream s;
		auto sub_t = t.as_a<subroutine_type_die>();
		s << "__FUN_FROM_";
		auto fps = sub_t.children().subseq_of<formal_parameter_die>();
		unsigned argnum = 0;
		for (auto i_fp = fps.first; i_fp != fps.second; ++i_fp, ++argnum)
		{
			/* args should not be void */
			/* We're making a canonical typename, so use canonical argnames. */
			s << "__ARG" << argnum << "_" << canonical_key_from_type(i_fp->get_type()).second;
		}
		if (sub_t->is_variadic())
		{
			s << "__VA_";
		}
		s << "__FUN_TO_";
		s << ((!sub_t->get_type() || !sub_t->get_concrete_type()) ? string("void") : canonical_key_from_type(sub_t->get_type()).second);
		return make_pair(summary_string, s.str());
	}
	else if (t.is_a<array_type_die>())
	{
		/* What should the type descriptor for "array of n T" look like? 
		 * What should it be called? 
		 * Answers: always has exactly one nmemb, and use __ARRn_. */
		
		/* What should the type descriptor for "array of undeterminedly-many T" look like?
		 * What should it be called? Answer: use __ARR0_*/
		
		/* How do we encode mutual recursion between array and pointer?
		 * Answer: nothing special: just cut off the array first part and emit it specially,
		 * with a reference to the remainder (what it's an array of).
		 * This handles multidimensional arrays too.
		 * NOTE that our __PTR___PTR_... practice is also redundant now that we 
		 * output every type, because every __PTR prefix is also in the DWARF so
		 * is also emitted. */
		
		auto array_t = t.as_a<array_type_die>();
		ostringstream array_prefix;
		opt<Dwarf_Unsigned> element_count = array_t->element_count();
		array_prefix << "__ARR" << (element_count ? *element_count : 0) << "_";
		return make_pair(summary_string, array_prefix.str() + canonical_key_from_type(array_t->get_type()).second);
	}
	else // DW_TAG_pointer_type and friends
	{
		int levels_of_indirection = 0;
		ostringstream indirection_prefix;
		iterator_df<type_die> working_t = t->get_concrete_type(); // initially
		while (working_t && working_t.is_a<address_holding_type_die>())
		{
			++levels_of_indirection;
			switch (working_t.tag_here())
			{
				case DW_TAG_pointer_type: 
					indirection_prefix << "__PTR_"; break;
				case DW_TAG_reference_type:
					indirection_prefix << "__REF_"; break;
				case DW_TAG_rvalue_reference_type:
					indirection_prefix << "__RR_"; break;
				default:
					assert(false);
			}
			
			// try moving on to the next in the chain
			if (working_t.is_a<address_holding_type_die>()) 
			{
				working_t = working_t.as_a<address_holding_type_die>()->get_type();
				// concretify if we got something
				if (working_t)
				{
					working_t = working_t->get_concrete_type();
				}
			}
		}
		assert(levels_of_indirection >= 1);
		
		ostringstream os;
		os << indirection_prefix.str() << (!working_t ? "void" : canonical_key_from_type(working_t).second);
		return make_pair(summary_string, os.str());
	}
	
	assert(false); // should have returned by now
}

// iterator_df<type_die>
// find_type_in_cu(iterator_df<compile_unit_die> cu, const string& name)
// {
// 	/* For the most part, we just do named_child.
// 	 * BUT, for base types, we widen the search, using our equivalence classes. */
// 	for (const char **const *p_equiv = &abstract_c_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
// 	{
// 		for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
// 		{
// 			if (name == string(*p_el))
// 			{
// 				/* We try every element in the class */
// 				for (const char **i_attempt = p_equiv[0]; *i_attempt != NULL; ++i_attempt)
// 				{
// 					iterator_df<type_die> found = cu.named_child(string(*i_attempt));
// 					if (found != iterator_base::END) return found;
// 				}
// 			}
// 		}
// 	}
// 
// 	// if we got here, just try named_child
// 	return iterator_df<type_die>(cu.named_child(name)); //shared_ptr<type_die>();
// }

struct output_word_t
{
	unsigned val;

	void zero_check()
	{
		if (val == 0)
		{
			cerr << "Warning: output_word value hit zero again." << endl;
			val = (unsigned) -1;
		}
	}

	output_word_t& operator<<(unsigned arg) 
	{
		val = rotate_left(val, 8) ^ arg;
		zero_check();
		return *this;
	}
	output_word_t& operator<<(const string& s) 
	{
		for (auto i = s.begin(); i != s.end(); ++i)
		{
			*this << static_cast<unsigned>(*i);
		}
		zero_check();
		return *this;
	}
	output_word_t() : val(0) {}
};

uint32_t type_summary_code(core::iterator_df<core::type_die> t)
{
	/* Here we compute a 4-byte hash-esque summary of a data type's 
	 * definition. The intentions here are that 
	 *
	 * binary-incompatible definitions of two types will always
	   compare different, even if the incompatibility occurs 
	   
	   - in compiler decisions (e.g. bitfield positions, pointer
	     encoding, padding, etc..)
	
	   - in a child (nested) object.
	   
	 * structurally distinct definitions will always compare different, 
	   even if at the leaf level, they are physically compatible.
	 
	 * binary compatible, structurally compatible definitions will compare 
	   alike iff they are nominally identical at the top-level. It doesn't
	   matter if field names differ. HMM: so what about nested structures' 
	   type names? Answer: not sure yet, but easiest is to require that they
	   match, so our implementation can just use recursion.
	 
	 * WHAT about prefixes? e.g. I define struct FILE with some padding, 
	   and you define it with some implementation-private fields? We handle
	   this at the libcrunch level; here we just want to record that there
	   are two different definitions out there.
	 
	 *
	 * Consequences: 
	 * 
	 * - encode all base type properties
	 * - encode pointer encoding
	 * - encode byte- and bit-offsets of every field
	 */
	using lib::Dwarf_Unsigned;
	using lib::Dwarf_Half;
	using namespace dwarf::core;
	
	if (!t)
	{
		// we got void
		return 0;
	}
	
	auto concrete_t = t->get_concrete_type();
	if (!concrete_t)
	{
		// we got a typedef of void
		return 0;
	}
	
	output_word_t output_word;
	Dwarf_Half tag = concrete_t.tag_here();
	if (concrete_t.is_a<base_type_die>())
	{
		auto base_t = concrete_t.as_a<core::base_type_die>();
		unsigned encoding = base_t->get_encoding();
		assert(base_t->get_byte_size());
		unsigned byte_size = *base_t->get_byte_size();
		unsigned bit_size = base_t->get_bit_size() ? *base_t->get_bit_size() : byte_size * 8;
		unsigned bit_offset = base_t->get_bit_offset() ? *base_t->get_bit_offset() : 0;
		output_word << DW_TAG_base_type << encoding << byte_size << bit_size << bit_offset;
	} 
	else if (concrete_t.is_a<enumeration_type_die>())
	{
		// shift in the enumeration name
		if (concrete_t.name_here())
		{
			output_word << *name_for_type_die(concrete_t);
		} else output_word << concrete_t.offset_here();
		
		// shift in the names and values of each enumerator
		auto enum_t = concrete_t.as_a<enumeration_type_die>();
		auto enumerators = enum_t.children().subseq_of<enumerator_die>();
		int last_enum_value = -1;
		for (auto i_enum = enumerators.first; i_enum != enumerators.second; ++i_enum)
		{
			output_word << *i_enum->get_name();
			if (i_enum->get_const_value())
			{
				last_enum_value = *i_enum->get_const_value();
				output_word << last_enum_value;
			} else output_word << last_enum_value++;
		}
		
		// then shift in the base type's summary code
		if (!enum_t->get_type())
		{
			// cerr << "Warning: saw enum with no type" << endl;
			auto implicit_t = enum_t.enclosing_cu()->implicit_enum_base_type();
			if (!implicit_t)
			{
				cerr << "Warning: saw enum with no type" << endl;
			} else output_word << type_summary_code(implicit_t);
		}
		else
		{
			output_word << type_summary_code(enum_t->get_type());
		}
	} 
	else if (concrete_t.is_a<subrange_type_die>())
	{
		auto subrange_t = concrete_t.as_a<subrange_type_die>();
		
		// shift in the name, if any
		if (concrete_t.name_here())
		{
			output_word << *name_for_type_die(concrete_t);
		} else output_word << concrete_t.offset_here();
		
		// then shift in the base type's summary code
		if (!subrange_t->get_type())
		{
			cerr << "Warning: saw subrange with no type" << endl;
		}
		else
		{
			output_word << type_summary_code(subrange_t->get_type());
		}
		
		/* Then shift in the upper bound and lower bound, if present
		 * NOTE: this means unnamed boundless subrange types have the 
		 * same code as their underlying type. This is probably what we want. */
		if (subrange_t->get_upper_bound())
		{
			output_word << *subrange_t->get_upper_bound();
		}
		if (subrange_t->get_lower_bound())
		{
			output_word << *subrange_t->get_lower_bound();
		}
	} 
	else if (concrete_t.is_a<subroutine_type_die>())
	{
		// shift in the argument and return types
		auto subr_t = concrete_t.as_a<subroutine_type_die>();
		if (subr_t->get_type()) output_word << type_summary_code(subr_t->get_type());
		
		// shift in something to distinguish void(void) from void
		output_word << "()";
		
		auto fps = subr_t.children().subseq_of<formal_parameter_die>();
		for (auto i_fp = fps.first; i_fp != fps.second; ++i_fp)
		{
			output_word << type_summary_code(i_fp->get_type());
		}
		
		auto varargs = subr_t.children().subseq_of<unspecified_parameters_die>();
		if (srk31::count(varargs.first, varargs.second) > 0)
		{
			output_word << "...";
		}
	}
	else if (concrete_t.is_a<address_holding_type_die>())
	{
		/* NOTE: actually, we *do* want to pay attention to what the pointer points to, 
		 * i.e. its contract. BUT there's a problem: recursive data types! For now, we
		 * use a giant HACK: if we're a pointer-to-member, use only the name. */
		auto ptr_t = concrete_t.as_a<core::address_holding_type_die>();
		unsigned ptr_size = *ptr_t->calculate_byte_size();
		unsigned addr_class = ptr_t->get_address_class() ? *ptr_t->get_address_class() : 0;
		if (addr_class != 0)
		{
			switch(addr_class) 
			{
				default:
					assert(false); // nobody seems to use this feature so far
				/* NOTE: There is also something called DWARF Pointer-Encoding (PEs).
				   This is a DWARF representation issue, used in frame info, and is not 
				   something we care about. */
			}
		}
		auto target_t = ptr_t->get_type();
		if (target_t.is_real_die_position()) target_t = target_t->get_concrete_type();
		unsigned target_code;
		if (target_t.is_real_die_position() && target_t.is_a<with_data_members_die>())
		{
			output_word_t tmp_output_word;
			// add in the name only
			if (target_t.name_here())
			{
				tmp_output_word << *name_for_type_die(target_t);
			} else tmp_output_word << target_t.offset_here();

			target_code = tmp_output_word.val;
		} else target_code = type_summary_code(target_t);
		output_word << tag << ptr_size << addr_class << target_code;
	}
	else if (concrete_t.is_a<with_data_members_die>())
	{
		// add in the name
		if (concrete_t.name_here())
		{
			output_word << *name_for_type_die(concrete_t);
		} else output_word << concrete_t.offset_here();

		// for each member 
		auto members = concrete_t.children().subseq_of<core::with_dynamic_location_die>();
		for (auto i_member = members.first; i_member != members.second; ++i_member)
		{
			// skip members that are mere declarations 
			if (i_member->get_declaration() && *i_member->get_declaration()) continue;
			
			// calculate its offset
			opt<Dwarf_Unsigned> opt_offset = i_member->byte_offset_in_enclosing_type();
			if (!opt_offset)
			{
				cerr << "Warning: saw member " << *i_member << " with no apparent offset." << endl;
				continue;
			}
			assert(i_member->get_type());

			output_word << (opt_offset ? *opt_offset : 0);
			// FIXME: also its bit offset!

			output_word << type_summary_code(i_member->get_type());
		}
	}
	else if (concrete_t.is_a<array_type_die>())
	{
		// if we're a member of something, we should be bounded in all dimensions
		auto opt_el_type = concrete_t.as_a<array_type_die>()->ultimate_element_type();
		auto opt_el_count = concrete_t.as_a<array_type_die>()->ultimate_element_count();
		output_word << (opt_el_type ? type_summary_code(opt_el_type) : 0)
			<< (opt_el_count ? *opt_el_count : 0);
			// FIXME: also the factoring into dimensions needs to be taken into account
	} else 
	{
		cerr << "Warning: didn't understand type " << concrete_t;
	}
	
	assert (!concrete_t || output_word.val != 0);
	
	return output_word.val;
	// return std::numeric_limits<uint32_t>::max();
}
uint32_t signedness_complement_type_summary_code(core::iterator_df<core::base_type_die> base_t)
{
	unsigned encoding = base_t->get_encoding();
	assert(encoding == DW_ATE_signed || encoding == DW_ATE_unsigned);
	output_word_t output_word;
	assert(base_t->get_byte_size());
	unsigned byte_size = *base_t->get_byte_size();
	unsigned bit_size = base_t->get_bit_size() ? *base_t->get_bit_size() : byte_size * 8;
	unsigned bit_offset = base_t->get_bit_offset() ? *base_t->get_bit_offset() : 0;
	output_word << DW_TAG_base_type 
		<< (encoding == DW_ATE_unsigned ? DW_ATE_signed : DW_ATE_unsigned) 
		<< byte_size << bit_size << bit_offset;
	return output_word.val;
}	

void get_types_by_codeless_uniqtype_name(
	std::multimap<string, iterator_df<type_die> >& m, 
	iterator_df<> begin, iterator_df<> end)
{	
		
	/* First we look through the whole file and index its types by their *codeless*
	 * *canonical* uniqtype name, i.e. we blank out the first element of the name pair. */
	for (iterator_df<> i = begin; i != end; ++i)
	{
		if (i.is_a<type_die>())
		{
			opt<string> opt_name = i.name_here(); // for debugging
			if (opt_name)
			{
				string name = *opt_name;
				assert(name != "");
			}
			
			auto t = i.as_a<type_die>();
			assert(t.is_real_die_position());
			auto concrete_t = t->get_concrete_type();
			pair<string, string> uniqtype_name_pair;
			
			// handle void case specially
			if (!concrete_t.is_real_die_position())
			{
				uniqtype_name_pair = make_pair("", "void");
			}
			else
			{
				uniqtype_name_pair = canonical_key_from_type(t);
			}

			/* CIL/trumptr will only generate references to aliases in the case of 
			 * base types. We need to handle these here. What should happen? 
			 * 
			 * - we will see references looking like __uniqtype__signed_char
			 * - we want to link in two things:
			 *    1. the nameless __uniqtype_<code>_ definition of this base type
			 *    2. the alias    __uniqtype_<code>_signed_char from the usual alias handling
			 * - we do this by indexing all our types by a *codeless* version of their
			 *   name, then matching our inputs lines against that.
			 * - the input lines will have signed_char instead of ""
			 * - ... so that's what we need to put in our index.
			 * 
			 * IT GETS WORSE: the same is true for any typename *mentioning* a base
			 * type! We will see references in terms of C-canonicalised base type names, 
			 * but we will be trying to match them against language-independent names. 
			 * It seems that we need to do a separate "C fix up" pass first.
			 * */
			
			string canonical_or_base_typename = uniqtype_name_pair.second;
			if (canonical_or_base_typename == "")
			{
				assert(concrete_t.is_a<base_type_die>());
				// if the base type has no name, this DWARF type is useless to us
				if (!concrete_t.name_here()) continue;
				canonical_or_base_typename = *name_for_type_die(concrete_t);
			}
			string codeless_symname = mangle_typename(make_pair("", canonical_or_base_typename));

			m.insert(make_pair(codeless_symname, concrete_t));

			/* Special handling for base types: also add them by the name in which they 
			 * appear in the DWARF, *and* by their C-canonical name. Our CIL frontend
			 * doesn't know the exact bit-widths so must use the latter. */
			if (concrete_t.is_a<base_type_die>() && concrete_t.name_here())
			{
				m.insert(
					make_pair(
						mangle_typename(make_pair("", *name_for_type_die(concrete_t))), 
						concrete_t
					)
				);
				const char **equiv = abstract_c_compiler::get_equivalence_class_ptr(name_for_type_die(concrete_t)->c_str());
				if (equiv)
				{
					m.insert(
						make_pair(
							mangle_typename(make_pair("", equiv[0])), 
							concrete_t
						)
					);
				}
			}
		}
	}
}
