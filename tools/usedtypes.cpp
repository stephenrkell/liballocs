#define _WITH_GETLINE
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
#include <fstream>

#include "helpers.hpp"
#include "uniqtypes.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::multimap;
using std::make_shared;
using std::unique_ptr;
using std::ios;
using std::ifstream;
using std::dynamic_pointer_cast;
using boost::optional;
using std::ostringstream;
using std::set;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::base_type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::member_die;
using dwarf::core::with_data_members_die;
using dwarf::core::variable_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;

using dwarf::lib::Dwarf_Off;

using dwarf::tool::abstract_c_compiler;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

static int debug_out = 1;

int main(int argc, char **argv)
{
	/* From stdin we read a sequence of symbol names that have been output by 
	 * the following OCaml code. 
            let symnameFromString s ts = begin
                let rec definingFile t = match t with 
                  TSComp(isSpecial, name, attrs) -> begin try
                      let l = NamedTypeMap.find name !namedTypesMap in l.file 
                      with Not_found -> output_string Pervasives.stderr ("missing decl for " ^ name ^ "\n"); "" (* raise Not_found *)
                  end
                | TSEnum(name, attrs) -> begin try
                      let l = NamedTypeMap.find name !namedTypesMap in l.file 
                      with Not_found -> output_string Pervasives.stderr ("missing decl for " ^ name ^ "\n"); "" (* raise Not_found *)
                  end
                | TSPtr(tsig, attrs) -> definingFile tsig
                | _ -> ""
                in
                let defining_filestr = definingFile ts
                in 
                let header_insert = Str.global_replace (Str.regexp "[. /-]") "_" defining_filestr in
                let ptr_replaced = Str.global_replace (Str.regexp "\\^") "__PTR_"  (Str.global_replace (Str.regexp "[. /-]") "_" s) in
                (* HACK: using escaped brackets in the regexp doesn't seem to work for replacing, 
                   so just use two dots. Will need to change this if we start to include function
                   argument types in function typestrings. *)
                let ptr_and_fun_replaced = Str.global_replace (Str.regexp "..=>") "__FUN_" ptr_replaced in
                "__uniqtype_" ^ "" ^ "_" ^ ptr_and_fun_replaced
              end in
              let symname = symnameFromString typeStr concreteType in
	 
	   We need to look through the DWARF types in the object file, 
	   generating and emitting the corresponding uniqtype record in each case, 
	   then running the compiler/linker/objcopy to 
	   - compile the emitted uniqtype record into a temporary .o file
	   - *rename* the referenced uniqtype into the actual one used (i.e. with the infix code)
	   - define and localise the original symbol name along the way
	   
	   cc -c -o /tmp/....o generated.c 
	   objcopy --redefine-sym blah file.o
	   ld -r -o file.o file.o /tmp/....o
	   
	   CHECK that the old symname is no longer present after redefine-sym!
	   
	*/
	
	unsigned nfiles = argc - 1;
	if (nfiles < 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}

	vector<string> fnames;
	for (unsigned i = 0; i < nfiles; ++i)
	{
		string fname = argv[1+i];
		fnames.push_back(fname);
	}
	
	return dump_usedtypes(fnames, cout, cerr);
}
