/* This is a simple dwarfpp program which generates a C file
 * recording data on DWARF-described entities which are *not* covered
 * by any symbol in the .symtab or .dynsym.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <srk31/algorithm.hpp>
#include <cxxgen/tokens.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/regs.hpp>
#include <fileno.hpp>

#include "stickyroot.hpp"
#include "uniqtypes.hpp"
#include "allocsites-info.hpp"

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
using dwarf::core::program_element_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;

using namespace dwarf::lib;

static int debug_out = 1;

using dwarf::lib::Dwarf_Off;
using dwarf::lib::Dwarf_Addr;
using dwarf::lib::Dwarf_Signed;
using dwarf::lib::Dwarf_Unsigned;

using namespace allocs::tool;

int main(int argc, char **argv)
{
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	std::ifstream infstream(argv[1]);
	if (!infstream) 
	{
		cerr << "Could not open file " << argv[1] << endl;
		exit(1);
	}
	if (getenv("EXTRASYMS_DEBUG"))
	{
		debug_out = atoi(getenv("EXTRASYMS_DEBUG"));
	}
	using core::root_die;
	int fd = fileno(infstream);
	shared_ptr<sticky_root_die> p_root = sticky_root_die::create(fd);
	if (!p_root) { std::cerr << "Error opening file" << std::endl; return 1; }
	sticky_root_die& root = *p_root;

	/* We walk the DWARF info looking for static-storage stuff. 
	 * In general, for each static-storage thing we might find that
	 * - it exists in dynsym
	 * - it exists in symtab (but not dynsym)  and symtab is in the object
	 *      ... and we should cross-check the symbol size info at this point
	 * - it exists in symtab *and symtab is external.
	 * - it exists in neither.
	 *
	 * Our job, "extrasyms", is to describe only the "in symtab but external"
	 * or "exists in neither" case.
	 */
#define ElfWstr_z(allfrag) #allfrag
#define ElfWstr_y(frag1, middle, frag2) ElfWstr_z(frag1 ## middle ## frag2)
#define ElfWstr_x(frag1, middle, frag2) ElfWstr_y(frag1, middle, frag2)
#define ElfWstr(frag1, frag2) ElfWstr_x(frag1, __ELF_NATIVE_CLASS, frag2)

	auto statics = root.get_sanely_described_statics();
	cout << "#include <elf.h>\n"
	     << "const char (__attribute__((section(\".extrastrtab\"))) str)[] = \"\";\n";
	cout << "const " ElfWstr(Elf, _Sym) " extrasyms[] __attribute__((section(\".extrasymtab\"))) = {\n\t(" ElfWstr(Elf, _Sym) ") { .st_name = 0 }\n};" << endl;
	cout << "#define APPEND_STRING(s) \\\n\
		__asm__(\".pushsection .extrastrtab\\n\\\n\
			.asciz \\\"\"s \"\\\"\" )" << std::endl;
	cout << "/* Pass-through trick so that macros invoked in arg positions (e.g. ELF64_INFO) are expanded. */" << std::endl;
	cout << "#define ASSEMBLE_ELF64_SYM_y(nameoff, value, size, info, other, shndx) \\\n\
		__asm__(\".pushsection .extrasymtab \\n\\\n\
			  .4byte \" #nameoff \" # name\\n\\\n\
			  .byte  \" #info \" # info\\n\\\n\
			  .byte  \" #other \" # other\\n\\\n\
			  .2byte \" \"0\" \" # shndx\\n\\\n\
			  .8byte \" #value \" # value\\n\\\n\
			  .8byte \" #size \" # size\\n\\\n\
			.popsection\\n\")\n";
	cout << "#define ASSEMBLE_ELF64_SYM(nameoff, value, size, info, other, shndx) \\\n\
		ASSEMBLE_ELF64_SYM_y(nameoff, value, size, info, other, shndx)\n";
	/* Keep track of how many bytes we've written to the strtab. */
	unsigned stroff = 1;
	vector< pair <ElfW(Sym), opt<string> > > extrasyms = root.get_extrasyms();
	// use begin+1 because of the null initial entry
	assert(extrasyms.size() >= 1);
	for (auto i_sym = extrasyms.begin() + 1; i_sym != extrasyms.end(); ++i_sym)
	{
		opt<string> opt_name = i_sym->second;
		// name is either 0 or a non-zero offset into the extrasymtab --
		// we keep track of its size, and snarf the offset at each string
		unsigned nameoff = opt_name ? stroff : 0;
		if (opt_name)
		{
			cout << "APPEND_STRING(\"" << *opt_name << "\");\n";
			stroff += opt_name->length();
		}
		sticky_root_die::static_descr::k kind
		 = static_cast<sticky_root_die::static_descr::k>(i_sym->first.st_shndx);
		Dwarf_Off die_offset_or_symidx = i_sym->first.st_name;
		cout << "// extrasym from descr of kind " << kind << ", ";
		if (kind == sticky_root_die::static_descr::DWARF) cout << root.pos(die_offset_or_symidx).summary();
		else cout << "index " << die_offset_or_symidx;
		cout << "\n";
		cout << ElfWstr(ASSEMBLE_ELF, _SYM) << "("
			<< nameoff << " /* name */, "
// FIXME: we used to have this quite nice code which showed the ELF stuff symbolically
// in the generated file. Would be nice to restore it. How? All we need is a
// stringified value<->string table so that we could emit the raw values as strings
// when we recognise them...
#define ELF_STB_VALUES(v) \
	v(STB_LOCAL) \
	v(STB_GLOBAL) \
	v(STB_WEAK)
#define ELF_STT_VALUES(v) \
	v(STT_NOTYPE) \
	v(STT_OBJECT) \
	v(STT_FUNC) \
	v(STT_SECTION) \
	v(STT_FILE) \
	v(STT_COMMON) \
	v(STT_TLS)
#define ELF_STV_VALUES(v) \
	v(STV_DEFAULT) \
	v(STV_INTERNAL) \
	v(STV_HIDDEN) \
	v(STV_PROTECTED)
#if 0
			<< "0x" << std::hex << interval.lower() << std::dec << " /* value */, "
			<< interval.upper() - interval.lower() << " /* size */, ";
		if (saw_sym) cout << saw_sym->st_info;
		else cout << ElfWstr(ELF, _ST_INFO) "(STB_LOCAL, STT_OBJECT)";
		cout << " /* info */, ";
		if (saw_sym) cout << saw_sym->st_other;
		else cout << "STV_HIDDEN";
		cout << " /* other */, "
#else
			<< "0x" << i_sym->first.st_value << std::dec << " /* value */, "
			<< i_sym->first.st_size << " /* size */, "
			<< (int) i_sym->first.st_info << " /* info */, "
			<< (int) i_sym->first.st_other << " /* other */, "
#endif
			<< "0 /* shndx */);\n";
	}
	// fix up the size of our extrasyms
	cout << "__asm__(\".size extrasyms, " << (extrasyms.size() * sizeof (ElfW(Sym))) << "\");\n";
	cout << "__asm__(\".size extrastr, " << stroff << "\");\n";

#if 0
	
	for (auto i_var_pair = sorted_statics.begin(); i_var_pair != sorted_statics.end(); ++i_var_pair)
	{
		auto addr = i_var_pair->first;
		auto& i_var = i_var_pair->second.first;
		
		/* Addr 0 is problematic. It generally refers to thinks that aren't really 
		 * there, like weak symbols (that somehow have debug info) or __evoke_link_warning_*
		 * things. But it could also be a legitimate vaddr. Hmm. Well, skip it for now.
		 * If we leave it, the addr lookup function becomes ambiguous if there are many
		 * allocs at address zero, and this confuses us (e.g. our assertion after chaining
		 * allocsites). FIXME: better to filter out based on the *type* of the thing? */
		if (addr == 0) continue;

		ostringstream anon_name; anon_name << "0x" << std::hex << i_var.offset_here();

		cout << "\n\t/* static alloc record for object "
			 << (i_var->find_name() ? *i_var->find_name() : ("anonymous, DIE " + anon_name.str())) 
			 << " at vaddr " << std::hex << "0x" << addr << std::dec << " */";
		ostringstream name_token;
		if (i_var->find_name()) name_token << "\"" << cxxgen::escape(*i_var->find_name()) << "\"";
		else name_token << "(void*)0";
		cout << "\n\t{ " << name_token.str() << ","
			<< "\n\t  { (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + " << addr << "UL, " 
			<< "&" << mangle_typename(canonical_key_for_type(
				i_var.is_a<subprogram_die>() ? i_var.as_a<type_die>() : i_var.as_a<variable_die>()->find_type()))
			<< " }\n\t}";
		cout << ",";
	}

	// close the list
	cout << "\n};\n";
#endif
	return 0;
}
