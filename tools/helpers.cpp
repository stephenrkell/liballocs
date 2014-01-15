#include "helpers.hpp"

#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cxxgen/cxx_compiler.hpp>
#include <srk31/algorithm.hpp>

using std::cerr;
using std::endl;
using std::ostringstream;
using std::string;
using namespace dwarf::core;
using dwarf::tool::cxx_compiler;

uniqued_name
key_from_type(iterator_df<type_die> t)
{
	uniqued_name n;
	t = t->get_concrete_type();

	/* we no longer use the defining_header -- use instead
	 * the type summary code */
	ostringstream summary_string;
	summary_string << std::hex << type_summary_code(t) << std::dec;
	
	if (!t.is_a<address_holding_type_die>() && !t.is_a<array_type_die>())
	{
		auto cu = t.enclosing_cu();
		
		int file_index = -1;
		if (t->get_decl_file() && *t->get_decl_file() != 0)
		{ file_index = *t->get_decl_file(); }
		
		string file_to_use = (file_index != -1) ? cu->source_file_name(*t->get_decl_file()) : "";
		
		// for named base types, we use equivalence classes
		string name_to_use; 
		if (!t.name_here() || t.tag_here() != DW_TAG_base_type)
		{
			name_to_use = t.name_here() ? *t.name_here() : offset_to_string(t.offset_here());
		}
		else // t->name_here() && t.tag_here() == DW_TAG_base_type
		{
			/* FIXME: deal with nested/qualified names also (nested data types, 
			   local data types, C++ namespaces). */
			/* FIXME: deal with struct/union tags also (but being sensitive to language: 
			   don't do it with C++ CUs). */
			
			assert(t.name_here() && t.tag_here() == DW_TAG_base_type);
			string name_to_search_for = *t.name_here();
			// search equiv classes for a type of this name
			for (const char ***p_equiv = &cxx_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
			{
				// assert this equiv class has at least one element
				assert((*p_equiv)[0] != NULL);
				
				for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
				{
					// is this the relevant equiv class?
					if (name_to_search_for == string(*p_el))
					{
						// yes, so grab its first element
						name_to_use = (*p_equiv)[0];
						break;
					}
				}
				if (name_to_use != "") break; // we've got it
			}
			
			// if we've still not got it....
			if (name_to_use == "") name_to_use = name_to_search_for;
		}

		assert(name_to_use != "char"); // ... for example. It should be "signed char" of course! since cxx_compiler.cpp puts that one first
		n = make_pair(summary_string.str(), name_to_use);
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
		n = make_pair(summary_string.str(), array_prefix.str() + key_from_type(array_t->get_type()).second);
	}
	else // DW_TAG_pointer_type and friends
	{
		auto t_as_type_chain = t.as_a<type_chain_die>();
		iterator_df<type_die> opt_target_type;
		if (t_as_type_chain != iterator_base::END)
		{
			opt_target_type = t_as_type_chain->get_type();
			// concretify if we got something
			if (opt_target_type != iterator_base::END) opt_target_type = opt_target_type->get_concrete_type();
		}
		// extract the name from what we got, if anything
		string opt_target_type_name;
		if (opt_target_type == iterator_base::END) opt_target_type_name = "void";
		else
		{
			opt_target_type_name = opt_target_type.name_here() ? 
				*opt_target_type.name_here() 
			: offset_to_string(opt_target_type->get_offset());
		}

		/* The defining header file for a pointer type is 
		 * the header file of the ultimate pointee. */
		int levels_of_indirection = 0;
		ostringstream indirection_prefix;
		iterator_df<type_die> ultimate_pointee_type = t->get_concrete_type(); // initially
		iterator_df<address_holding_type_die> address_holder;
		do
		{
			if (ultimate_pointee_type.is_a<address_holding_type_die>()) 
			{
				address_holder = ultimate_pointee_type;
				++levels_of_indirection;
				switch (ultimate_pointee_type.tag_here())
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
				ultimate_pointee_type = address_holder->get_type();
				// concretify if we got something
				if (ultimate_pointee_type != iterator_base::END)
				{
					ultimate_pointee_type = ultimate_pointee_type->get_concrete_type();
				}
			} else address_holder = iterator_base::END;
		} while (address_holder != iterator_base::END);
		assert(levels_of_indirection >= 1);
		
		string defining_header;
		if (ultimate_pointee_type == iterator_base::END)
		{
			// we have the "void" type, possibly indirected over multiple levels
			defining_header = "";
		}
		else 
		{
			defining_header = 
			 (ultimate_pointee_type->get_decl_file() && *ultimate_pointee_type->get_decl_file() != 0) 
			   ? ultimate_pointee_type.enclosing_cu()->source_file_name(
			      *ultimate_pointee_type->get_decl_file()) 
			   : "";
		}

		string target_typename_to_use = opt_target_type ? key_from_type(opt_target_type).second : "void";
		
		ostringstream os(std::ios::out | std::ios::binary);
		std::ostream_iterator<char, char> oi(os);
		
		// here we are translating a dumpallocs-style type descriptor name...
		// ... into a uniqtypes-style name. BUT WHY? 
		//regex_replace(oi, s.begin(), s.end(),
		//	regex("(\\^)"), "(__PTR_)", 
		//	match_default | format_all);
		//assert(os.str() != "char"); // ... for example
		
		os << indirection_prefix.str() << target_typename_to_use;
		
		/* we no longer use the defining_header -- use instead
		 * the type summary code */
		ostringstream summary_string;
		auto code = type_summary_code(t);
		summary_string << std::hex << std::setfill('0') << std::setw(2 * sizeof code) << code << std::dec;
		
		n = make_pair(summary_string.str(), os.str());
	}
	
	return n;
}

iterator_df<type_die>
find_type_in_cu(iterator_df<compile_unit_die> cu, const string& name)
{
	/* For the most part, we just do named_child.
	 * BUT, for base types, we widen the search, using our equivalence classes. */
	for (const char ***p_equiv = &cxx_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
	{
		for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
		{
			if (name == string(*p_el))
			{
				/* We try every element in the class */
				for (const char **i_attempt = p_equiv[0]; *i_attempt != NULL; ++i_attempt)
				{
					iterator_df<type_die> found = cu.named_child(string(*i_attempt));
					if (found != iterator_base::END) return found;
				}
			}
		}
	}

	// if we got here, just try named_child
	return iterator_df<type_die>(cu.named_child(name)); //shared_ptr<type_die>();
}

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
	 
	auto concrete_t = t->get_concrete_type();
	if (!concrete_t)
	{
		// we got void
		return 0;
	}
	
	struct output_word_t
	{
		unsigned val;
		
		output_word_t& operator<<(unsigned arg) 
		{
			val = rotate_left(val, 8) ^ arg;
			return *this;
		}
		output_word_t& operator<<(const string& s) 
		{
			for (auto i = s.begin(); i != s.end(); ++i)
			{
				*this << static_cast<unsigned>(*i);
			}
			return *this;
		}
		output_word_t() : val(0) {}
	} output_word;
	
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
			output_word << *concrete_t.name_here();
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
			cerr << "Warning: saw enum with no type" << endl;
		}
		else
		{
			output_word << type_summary_code(enum_t->get_type());
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
		/* pay attention *only* to the pointer representation (not what it points to)
		 * -- calculate_byte_size knows how to get the CU address size
		 * -- we should use DW_ATTR_address_class */
		// FIXME: actually, why do we not want to pay attention to what it 
		// points to, i.e. its contract? We wouldn't necessarily be baking
		// in any nominality.
		auto ptr_t = concrete_t.as_a<core::address_holding_type_die>();
		unsigned ptr_size = *ptr_t->calculate_byte_size();
		unsigned addr_class = ptr_t->get_address_class() ? *ptr_t->get_address_class() : 0;
		if (addr_class != 0)
		{
			switch(addr_class) 
			{
				default:
					assert(false); // nobody seems to use this feature so far
			}
		}
		output_word << tag << ptr_size << addr_class;
		/* FIXME: There is also something called DWARF Pointer-Encoding (PEs).
		   They only seem to exist in exception handling and unwind tables, though. 
		   I don't think the quite do what we care about. */
	}
	else if (concrete_t.is_a<with_data_members_die>())
	{
		// add in the name
		if (concrete_t.name_here())
		{
			output_word << *concrete_t.name_here();
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
