#include <fstream>
#include <iostream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sys/mman.h>
#include <fileno.hpp>
extern "C" {
#include <link.h>
}
#include "relf.h"
extern "C" {
#include "systrap.h"
#include "donald.h"
}

using std::cerr;
using std::cout;
using std::endl;

#ifndef MAX_PAGE_SIZE
#define MAX_PAGE_SIZE COMMON_PAGE_SIZE
#endif
extern "C" {
unsigned long page_size = MAX_PAGE_SIZE; // HACK: donald needs this
void *(*orig_dlopen)(char*, int); // HACK: librunt needs this
char **environ; // HACK: we need this why?
void *__private_malloc(size_t sz) { return malloc(sz); } // more HACKS...
char *__private_strdup(const char *s) { return strdup(s); }
}
static int debug_out = 1;

int set_trap(unsigned char *pos, unsigned len, void *load_addr)
{
	//printf("Trap at %p (%p)! len %d\n", pos,
	//	(void*)((uintptr_t) pos - (uintptr_t) load_addr),
	//	(int) len);
	uintptr_t vaddr = (uintptr_t) pos - (uintptr_t) load_addr;
	cout << "\t(Elf64_Rel) { .r_offset = 0x" << std::hex << vaddr << std::dec
	                 << ", .r_info = ELF64_R_INFO(0, R_X86_64_16)"
	                 << " }," << endl;
	return 0;
}
int main(int argc, char **argv)
{
	/* We open the file named by argv[1] and dump its DWARF types. */ 
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	FILE *f = fopen(argv[1], "r");
	if (!f) 
	{
		cerr << "Could not open file " << argv[1] << endl;
		exit(1);
	}
	
	if (getenv("DUMPSYSCALLS_DEBUG"))
	{
		debug_out = atoi(getenv("DUMPSYSCALLS_DEBUG"));
	}
	
	/* We want to use code from donald to map the program headers
	 * of the named file, and the code from librunt/libsystrap to
	 * search for syscall instructions, and then write something
	 * out about what we find.
	 *
	 * In principle it could also write statically analyised
	 * information about which syscalls each may perform... hmm.
	 * Should this be a BAP tool, then?
	 * What was the other BAP tool I was thinking about building?
	 * There was one for binary analysis of allocation sites (sizeofness)
	 * and maybe also one for analysing the kernel syscall entry path i.e.
	 * joining up across the untyped parts of the kernel into the bona-fide
	 * syscall implementation. Any others?
	 */
#if 0
{
	uintptr_t dynamic_vaddr;
	uintptr_t base_addr;
	uintptr_t phdrs_addr;
	ElfW(Ehdr) ehdr;
	ElfW(Dyn)* dynamic;
	size_t dynamic_size;
	char errmsg[400];
};
#endif

#ifndef MAX_PHDR
#define MAX_PHDR 32
#endif
	ElfW(Phdr) phdrs[MAX_PHDR];
	unsigned n_phdr = MAX_PHDR;
	struct loadee_info info = load_from_fd(
		fileno(f),
		argv[1],
		0x555555556000ul /* FIXME: sysdep */,
		phdrs,
		&n_phdr
	);
	if (info.base_addr == 0)
	{
		cerr << "Could not load file " << argv[1] << endl;
		exit(1);
	}
	/* Also snarf the shdrs separately. The plain libsystrap will try to
	 * get them from librunt, but we haven't actually loaded the object into
	 * the link map. */
	off_t mapping_offset = RELF_ROUND_DOWN_(info.ehdr.e_shoff, MAX_PAGE_SIZE);
	off_t mapping_end_offset = RELF_ROUND_UP_(
		info.ehdr.e_shoff + info.ehdr.e_shnum * info.ehdr.e_shentsize,
		MAX_PAGE_SIZE);
	size_t mapping_size = mapping_end_offset - mapping_offset;
	void *shdrs_map = mmap(NULL, mapping_size, PROT_READ, MAP_PRIVATE, fileno(f),
		mapping_offset);
	if (shdrs_map == MAP_FAILED)
	{
		cerr << "Could not map shdrs" << endl;
		exit(1);
	}
	ElfW(Shdr) *shdrs = (void*)((uintptr_t) shdrs_map + (info.ehdr.e_shoff - mapping_offset));

	/* Use libsystrap routines... we do this a bit like trace-syscalls.so does. */
	cout << "#include <elf.h>" << endl
	     << "const Elf64_Rel syscall_rels[] = {" << endl;
	for (unsigned i = 0; i < info.ehdr.e_phnum; ++i)
	{
		ElfW(Phdr) *phdr = (void*)((info.phdrs_addr + i * info.ehdr.e_phentsize));
		if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X)
		{
			trap_one_executable_region_given_shdrs(
				(unsigned char *)(info.base_addr + phdr->p_vaddr),
				(unsigned char *)(info.base_addr + phdr->p_vaddr + phdr->p_memsz),
				argv[1],
				phdr->p_flags & PF_W,
				phdr->p_flags & PF_R,/* preserve_exec */ 0,
				shdrs, info.ehdr.e_shnum, info.base_addr,
				set_trap, (void*) info.base_addr);
		}
	}
	cout << "\t(Elf64_Rel) { .r_offset = 0 }" << endl;
	cout << "};" << endl;
	munmap(shdrs_map, mapping_size);
	// success! 
	return 0;
}
