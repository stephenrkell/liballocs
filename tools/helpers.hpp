#ifndef DUMPALLOCS_HELPERS_HPP_
#define DUMPALLOCS_HELPERS_HPP_

#include <sstream>
#include <fstream>
#include <memory>
#include <cstdint>
#include <dwarfpp/lib.hpp>
#include <srk31/rotate.hpp>
#include <cstdint>
#include <iomanip>
#include <deque>

// FIXME: shouldn't have toplevel "using" in header file
using std::string;
using std::endl;
using std::map;
using std::deque;
using std::pair;
using std::make_pair;
using std::istringstream;
using namespace dwarf;
using spec::opt;
using lib::Dwarf_Unsigned;

typedef pair<string, string> uniqued_name;

inline opt<string>
name_for_type_die(core::iterator_df<core::type_die> t)
{
	/* Normally we just return the name. However: HACK HACK HACK. 
	 * If it's a CIL name like __anonstruct_BLAH_nn, we erase the nn. 
	 * This is so that we don't generate nominally distinct types 
	 * in different compilation units. */
	if (t.name_here() && t.name_here()->find("__anonstruct_") == 0)
	{
		string replacement_name = *t.name_here();
		unsigned last_underscore_pos = replacement_name.find_last_of('_');
		assert(last_underscore_pos && last_underscore_pos + 1 < replacement_name.length());
		replacement_name.replace(last_underscore_pos, 
			replacement_name.length() - last_underscore_pos, "_1");
		return replacement_name;
	}
	else return *t.name_here();
}

uniqued_name
canonical_key_from_type(core::iterator_df<core::type_die> t);

uniqued_name
language_specific_key_from_type(core::iterator_df<core::type_die> t);

/* We expand all the possible names for a type, using synonyms along the 
 * chain starting from t. Don't use C-equivalences though; this is generic code. */
struct all_names_for_type_t : std::unary_function< core::iterator_df<core::type_die>, deque<string> >
{
	/* This function is structured as a pattern-matching sequence, each delegating to 
	 * an overridable method. The sequence is not overridable, but the delegated-to
	 * method is. This is, unfortunately, reinveinting inheritance somewhat. */
	
	std::function< deque<string>(core::iterator_df<core::type_die>) > void_case;
	std::function< deque<string>(core::iterator_df<core::qualified_type_die>) > qualified_case;
	std::function< deque<string>(core::iterator_df<core::type_chain_die>) > typedef_case;
	std::function< deque<string>(core::iterator_df<core::base_type_die>) > base_type_case;
	std::function< deque<string>(core::iterator_df<core::address_holding_type_die>) > pointer_case;
	std::function< deque<string>(core::iterator_df<core::array_type_die>) > array_case;
	std::function< deque<string>(core::iterator_df<core::subroutine_type_die>) > subroutine_case;
	std::function< deque<string>(core::iterator_df<core::with_data_members_die>) > with_data_members_case;
	std::function< deque<string>(core::iterator_df<core::type_die>) > default_case;
	
	// instantiate our default
	all_names_for_type_t();
	deque<string> operator()(core::iterator_df<core::type_die> t) const;
};
extern all_names_for_type_t default_all_names_for_type;

string 
name_for_base_type(core::iterator_df<core::base_type_die> base_t);

string 
name_for_complement_base_type(core::iterator_df<core::base_type_die> base_t);

string 
summary_code_to_string(uint32_t code);

core::iterator_df<core::type_die>
find_type_in_cu(core::iterator_df<core::compile_unit_die> cu, const string& name);

inline string mangle_spaces(const string& s)
{
	string mangled = s ;
	replace(mangled.begin(), mangled.end(), ' ', '_');

	return mangled;
}

inline string mangle_nonalphanums(const string& s)
{
	string mangled = s;
	
	replace(mangled.begin(), mangled.end(), '/', '_');
	replace(mangled.begin(), mangled.end(), '-', '_');
	replace(mangled.begin(), mangled.end(), '.', '_');
	replace(mangled.begin(), mangled.end(), ':', '_');
	replace(mangled.begin(), mangled.end(), '<', '_');
	replace(mangled.begin(), mangled.end(), '>', '_');
	replace(mangled.begin(), mangled.end(), ',', '_');
	replace(mangled.begin(), mangled.end(), '*', '_');
	replace(mangled.begin(), mangled.end(), '&', '_');
	replace(mangled.begin(), mangled.end(), '[', '_');
	replace(mangled.begin(), mangled.end(), ']', '_');
	replace(mangled.begin(), mangled.end(), '(', '_');
	replace(mangled.begin(), mangled.end(), ')', '_');
	replace(mangled.begin(), mangled.end(), '+', '_');
	return mangled;
}

inline string mangle_objname(const string& s)
{
	return mangle_spaces(mangle_nonalphanums(s));
}

inline string mangle_string(const string& s)
{
	return mangle_spaces(mangle_nonalphanums(s));
}

inline string mangle_typename(const pair<string, string>& p)
{
	string first_mangled = mangle_string(p.first);
	string second_mangled = mangle_string(p.second);
	
	return "__uniqtype_" + first_mangled + "_" + second_mangled;
}

uint32_t type_summary_code(core::iterator_df<core::type_die> t);
uint32_t signedness_complement_type_summary_code(core::iterator_df<core::base_type_die> base_t);

inline std::string offset_to_string(lib::Dwarf_Off o)
{
	std::ostringstream s;
	s << "0x" << std::hex << o << std::dec;
	return s.str();
}

inline int read_allocs_line(
	const string& str,
	string& objname,
	string& symname,
	unsigned& file_addr,
	string& cuname,
	unsigned& line,
	unsigned& end_line,
	string& alloc_typename
)
{
	istringstream s(str);

	string file_addrstr;
	string linestr;
	string endlinestr;

	#define report_error(fieldname, buf) \
	do { cerr << "Error reading field '" #fieldname "' from line: " << (buf) << endl; \
		 return 1; \
	   } while (0)
	#define check_error(stream, fieldname, buf) \
	do { \
		if ((stream).bad()) report_error(fieldname, (buf)); \
	   } while (0)		
	std::getline(s, objname, '\t'); check_error(s, objname, str);
	std::getline(s, symname, '\t'); check_error(s, symname, str);
	std::getline(s, file_addrstr, '\t'); check_error(s, offset, str);
	std::getline(s, cuname, '\t'); check_error(s, cuname, str);
	std::getline(s, linestr, '\t'); check_error(s, line, str);
	std::getline(s, endlinestr, '\t'); check_error(s, endline, str);
	std::getline(s, alloc_typename, '\t'); check_error(s, alloc_typename, str);
	// don't bother reading rest -- the line below doesn't work
	//std::getline(s, rest, '\n'); check_error(s, rest);

	if (file_addrstr.substr(0, 2) != "0x") 
	{
		cerr << "str is " << str << "\nfile_addrstr is " << file_addrstr << endl;
		report_error(file_addr, file_addrstr);
	}
	istringstream offsetstream(file_addrstr.substr(2)); offsetstream >> std::hex >> file_addr; check_error(offsetstream, file_addr, file_addrstr);
	istringstream linestream(linestr); linestream >> line; check_error(linestream, line, linestr);
	istringstream endlinestream(endlinestr); endlinestream >> end_line; check_error(endlinestream, end_line, endlinestr);
	return 0;
}

#endif
