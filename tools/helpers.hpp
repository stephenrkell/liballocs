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

// FIXME: shouldn't have toplevel "using" in header file
using std::string;
using std::endl;
using std::map;
using std::pair;
using std::make_pair;
using std::istringstream;
using namespace dwarf;
using spec::opt;
using lib::Dwarf_Unsigned;

typedef pair<string, string> uniqued_name;

uniqued_name
canonical_key_from_type(core::iterator_df<core::type_die> t);

uniqued_name
mayalias_key_from_type(core::iterator_df<core::type_die> t);

uniqued_name
language_specific_key_from_type(core::iterator_df<core::type_die> t);

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

inline string mangle_typename(const pair<string, string>& p)
{
	string first_mangled = mangle_spaces(mangle_nonalphanums(p.first));
	string second_mangled = mangle_spaces(mangle_nonalphanums(p.second));
	
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
