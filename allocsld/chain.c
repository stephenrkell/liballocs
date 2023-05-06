#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <err.h>
#include <assert.h>
#include "donald.h"
#include <link.h>
#include "relf.h"

#define die(s, ...) do { fprintf(stderr, DONALD_NAME ": " s , ##__VA_ARGS__); exit(-1); } while(0)
// #define die(s, ...) do { fwrite(DONALD_NAME ": " s , sizeof DONALD_NAME ": " s, 1, stderr); exit(-1); } while(0)

/* How do we make debugging work?
 *
 * If the debugger is attached after the inferior receives control,
 * we should not have a problem. Indeed, testing confirms this.
 *
 * If our loader is the 'requested' dynamic linker, gdb will expect
 * it to provide the SVr4 interface... which of course it doesn't, as
 * that is only in the inferior ld.so. What can we do? Some random ideas:
 *
 * - define _r_debug_state at run time as an ABS symbol pointing at inferior?
 *       Problem here is that gdb (at least) expects to be able to open the
 *       ld.so fresh from disk using libbfd and scrape the value, then do
 *       (load_addr + sym_addr) to get the breakpointable address.
 *
 * - define a real _r_debug_state and make the inferior's _r_debug_state jump
 *   into it, by instrumentation?
 *   glibc's ld.so has
     000000000000f8f0     1 FUNC    GLOBAL DEFAULT   12 _dl_debug_state@@GLIBC_PRIVATE
 *
     000000000000f8f0 <_dl_debug_state@@GLIBC_PRIVATE>:
         f8f0:       c3                      retq
         f8f1:       66 66 2e 0f 1f 84 00    data16 nopw %cs:0x0(%rax,%rax,1)
         f8f8:       00 00 00 00
 *
 *   ... which seems to work.
 *
 * If our loader is the program, explicitly chain-loading the inferior,
 * we should borrow the approach from libsystrap's example/trace-syscalls-ld.so
 * where a fake DT_DEBUG entry is created pointing at the inferior ld.so.
 * Probably this should be pulled into donald or a libchainld library.
 */

__attribute__((visibility("hidden")))
void _dl_debug_state(void) {}

void cover_tracks(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum, const char *ldso_path, uintptr_t inferior_dynamic_vaddr, uintptr_t base_addr) __attribute__((visibility("hidden")));
void cover_tracks(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum, const char *ldso_path, uintptr_t inferior_dynamic_vaddr, uintptr_t base_addr)
{	
	// FIXME: arrange for us to be unmapped and disappear
	/* More debugging-related fun... a naive treatment leaves us with.
(gdb) print _r_debug
Missing ELF symbol "_r_debug".

i.e. the real ld.so is missing from the 'info shared' list.
What about in the r_debug that we can reach from DT_DEBUG?
It's missing from that too! i.e. the real ld.so did all the work,
but didn't create a link map entry for itself.

And why would it? It thinks its name is allocsld.so. But
how does it determine that? From the program binary, since that must
name the interpreter... in the .interp section, naturally,
which is mapped by PT_INTERP.

$16 = {
  l_addr = 140737349562368, 
  l_name = 0x5555555542a8 "/usr/local/src/liballocs/allocsld/allocsld.so", 
  l_ld = 0x7ffff7bcae78, 
  l_next = 0x7ffff775a530, 
  l_prev = 0x7ffff775a000, 
  l_real = 0x7ffff7bcb9f0, 
  l_ns = 0, 

Here we see l_addr which is 140737349562368 or (void *) 0x7ffff7ba3000,
which is the load address of ld-linux-x86_64.so.2 and NOT
of allocsld.so.

Perhaps a solution is
when we link with -Wl,--dynamic-linker=/usr/local/src/liballocs/allocsld/allocsld.so
we also need to pad the .interp section to a handy size
and to make it writable or at least RELRO.
Currently, .interp is a PROGBITS read-only allocated section with alignment 1
and vaddr inside the text segment.
How can we make it bigger and put it in the relro?
TRy a custom linker script.

proof of concept:

SECTIONS
      {
        .interp : { *(.interp) ; LONG(0) ; LONG(0) ; LONG(0) }
      }

	  and

.section .interp, "aw"
    .quad 0


-- indeed gives us a writable interp. We get a pointer to it via PT_INTERP.
*/
	
	if (!we_are_the_program)
	{
		char *interp_addr = NULL;
		size_t interp_sz = 0;
		if (!program_phdrs) die("could not find the program phdrs\n");
		// the program should already have been mapped by the kernel. fix up its .interp
		// first we need the program's base addr, inferred from its PHDR phdr
		ElfW(Addr) program_base_addr = 0;
		_Bool saw_pt_phdr = 0;
		for (int i = 0; i < program_phnum; ++i)
		{
			if (program_phdrs[i].p_type == PT_PHDR)
			{
				saw_pt_phdr = 1;
				program_base_addr = (uintptr_t) program_phdrs
					- program_phdrs[i].p_vaddr;
			}
		}
		if (!saw_pt_phdr) die("could not infer program base address (no PT_PHDR?)\n");
		for (int i = 0; i < program_phnum; ++i)
		{
			if (program_phdrs[i].p_type == PT_INTERP)
			{
				/* We should have a *writable* interp. If this isn't true, bail. */
				if (!we_are_the_program && !(program_phdrs[i].p_flags & PF_W))
				{
					die("PT_INTERP is not writable, so can't transparently chain-load ld.so\n"
						"special link args are required when setting allocsld.so as the dynamic linker\n");
				}
				interp_addr = (char*) (program_base_addr + program_phdrs[i].p_vaddr);
				interp_sz = program_phdrs[i].p_filesz;
			}
		}
		if (!interp_addr) die("could not find PT_INTERP header in the target program\n");
		if (interp_sz < strlen(ldso_path) + 1)
		{
			die("insufficient space for ld.so interp string (size %d)\n", interp_sz);
		}
		memcpy(interp_addr, ldso_path, strlen(ldso_path) + 1);

		/* Now we have hoodwinked the program into thinking that the inferior
		 * is the legit ld.so. But if we're running in a debugger, it will have
		 * eagerly snarfed the interpreter name and will still be looking at the
		 * file, not the memory image. So we want to define our own _dl_debug_state.
		 * We need to get the link map... in our not-yet-initialized state, does that
		 * even exist yet? The inferior certainly has an '_r_debug' symbol. */
		ElfW(Dyn) *d = (ElfW(Dyn) *)(inferior_dynamic_vaddr + base_addr);
		ElfW(Sym) *rs = symbol_lookup_in_dyn(d, base_addr, "_r_debug");
		/* don't use sym_to_addr() because we don't have a working link map yet */
		struct r_debug *r = (void*)(base_addr + rs->st_value);
		ElfW(Sym) *fs = symbol_lookup_in_dyn(d, base_addr, "_dl_debug_state");
		assert(fs);
		/* FIXME: it might also be called any of the following
		  "__dl_rtld_db_dlactivity",
		  "_r_debug_state",
		  "_rtld_debug_state",
		  "r_debug_state",
		  "rtld_db_dlactivity",
		 */
		// FIXME: the following assertion is not true (size is 1, i.e. 'retq')...
		// assert(fs->st_size >= 16);
		// ... but want to check that nothing interesting lives in the following 15 bytes.
		// In theory liballocs or even librunt could easily tell us this, and it might make
		// a useful utility call (querying the 'realloc'-available space, generalised)
		// although for us, that's tricky (liballocs isn't running yet; librunt needs fakery).
		void *f = (void*)(base_addr + fs->st_value);
		// mprotect: make it writable -- HACK: use page size
		void *page_addr = (void*) RELF_ROUND_DOWN_((uintptr_t)f, page_size);
		int ret = mprotect(page_addr, page_size, PROT_READ|PROT_WRITE);
		/* %rax is caller-save so we are free to clobber it */
		char bytes[] = { 0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, /* movabs $0x123456789abcdef0,%rax */
			0xff, 0xe0 /* jmpq   *%rax */ };
		uintptr_t address_8bytes = (uintptr_t) &_dl_debug_state;
		memcpy(bytes + 2, &address_8bytes, sizeof address_8bytes);
		memcpy(f, bytes, sizeof bytes);
		mprotect(page_addr, page_size, PROT_READ|PROT_EXEC);
	} // end if (!we_are_the_program)
	// FIXME: now munmap and/or mprotect some stuff:
	// munmap ourselves, to the extent we can
	// mprotect the interpreter string back to read-only
}
