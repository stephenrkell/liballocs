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
 * This is now pulled into donald (create_dt_debug() and populate_dt_debug()).
 *
 * However, it's not enough because although the debugger finds a link map,
 * the ld.so's own path in the link map entry will be wrong... hence the
 * need for fix_link_map_paths below. That is not yet pulled into donald because
 * the fix is very specific: it overwrites the .interp section, which we can
 * only do in allocsld thanks to interference with link args. Note that this
 * problem only affects the "requested" case, so a chain loader that only does
 * "invoked" does not suffer the problem. FIXME: the "invoked" 
 */

__attribute__((visibility("hidden")))
void _dl_debug_state(void) {}

static void
fix_link_map_paths(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum,
	const char *ldso_path)
{
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
	} // end if (!we_are_the_program)
	else
	{
		/* If we are the program, we still need to do a variation on the above.
		 * Without it, one might see the following:
		 
		 $ gdb --args ./allocsld.so /usr/bin/xterm
		 ...
		 (gdb) info shared
		 ...
		 0x0000555555577f70  0x000055555557df12  No          /var/local/stephen/work/devel/liballocs.git/allocsld/allocsld.so
		 ...
		 * ... even though the object at that address is clearly the real ld.so.
		 * Is it because the ld.so gets its own name from argv[0]? Or from AT_EXECFN?
		 * The former, it turns out.
		 * When 'we are the program', the ld.so rewrites AT_EXECFN so that
		 * it becomes the actual executable filename, so we leave it as is.
		 * (that's why the code is #ifdef'd out).
		 */
		extern char** argv;
		argv[0] = (char*) ldso_path;
#if 0
		extern ElfW(auxv_t) *p_auxv;
		for (ElfW(auxv_t) *p = p_auxv; p->a_type; ++p)
		{
			switch (p->a_type)
			{
				case AT_EXECFN:
					p->a_un.a_val = (uintptr_t) ldso_path;
					break;
			}
		}
#endif
	}
}

#include "asmutil.h"
// now we have bytes now available as a char[] and bytes_relocs now available as an ElfW(Rela)[]

/* Make the ld.so's _dl_debug_state function call ours, so that
 * the ld.so logic always connects with the debugger even if it's
 * only seen our function. */
static void
chain_dl_debug_state_function(ElfW(Phdr) *program_phdrs, unsigned program_phnum,
	const char *ldso_path, uintptr_t inferior_dynamic_vaddr, uintptr_t base_addr)
{
	/* We need to get the link map... in our not-yet-initialized state, does that
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
	// FIXME: the following assertion is not true (st_size is 1, i.e. 'retq')...
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
	INSTRS_FROM_ASM (bytes, /* FIXME: sysdep */ " \
1: movabs $0x123456789abcdef0,%rax             # 48 b8 f0 de bc 9a 78 56 34 12 \n\
		RELOC (1b + 2), "R_(X86_64_64)", "/* reloc using symidx 0 */" 0, 0 \n\
   jmpq *%rax \n\
");
	memcpy_and_relocate(f, bytes, /* value for symidx 0 */ (uintptr_t) &_dl_debug_state);
	mprotect(page_addr, page_size, PROT_READ|PROT_EXEC);

	// Call it, so that an attached debugger does its update!
	// Is this correct timing-wise? It will only work if the attached
	// debugger has seen our DT_DEBUG and set a breakpoint on our _dl_debug_state().
	// We could even just call our own _dl_debug_state.
	// Right now, we're running very early... no chance that the inferior dynamic
	// linker has made a call that was "missed", because it hasn't run yet.
	// That also means there's no link map, unless we install a fake.
	((void(*)(void)) f)();

}

__attribute__((visibility("hidden")))
void cover_tracks(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum,
	const char *ldso_path, uintptr_t inferior_dynamic_vaddr, uintptr_t base_addr)
{	
	// FIXME: arrange for us to be unmapped and disappear?
	// That would probably break debugging, because an early-attached
	// debugger *will* breakpoint our _dl_debug_state.

	// ensure the right ld.so filename shows up in the link map
	// -- this may need to rewrite the executable's .interp section,
	// in the case of allocsld-requesting executables.
	fix_link_map_paths(we_are_the_program, program_phdrs, program_phnum,
		ldso_path);

	/* Now we have hoodwinked the program into thinking that the inferior ld.so
	 * was the executable's nominated ld.so all along. But if we're running
	 * in a debugger, it won't be fooled: it will have eagerly snarfed the
	 * interpreter name from the executable and will still be looking at that
	 * file, not the running memory image. So will look at that file for the
	 * address of the _dl_debug_state function, even though the inferior ld.so
	 * will only call *its* _dl_debug_state function. To ensure the debugger is
	 * triggered when new loading, we not only have to define our own _dl_debug_state,
	 * but also we have to make the inferior ld.so call *it*. The solution is
	 * as horrible as one might fear: monkey-patch the inferior ld.so's _dl_debug_state
	 * so that it calls ours, instead of just immediately returning.
	 * (This also means the fully covering our tracks, by unloading allocsld.so entirely
	 * from memory, is not debug-compatible.
	 * FIXME: I'm not sure the above explanation entirely checks out. How does the
	 * debugger get the load address of allocsld.so, on whose _dl_debug_state it
	 * apparently sets the breakpoint, given that allocsld.so is not in the link map?
	 * Hmm, well I guess it could get it from the auxv. Indeed I think it has to do
	 * this in order to get the link map itself anyway.)
	 */
	chain_dl_debug_state_function(program_phdrs, program_phnum,
		ldso_path, inferior_dynamic_vaddr, base_addr);

	instrument_ld_so_allocators(base_addr);

	// FIXME: now munmap and/or mprotect some stuff:
	// munmap ourselves, to the extent we can
	// mprotect the interpreter string back to read-only
}
