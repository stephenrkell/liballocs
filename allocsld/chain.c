#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <err.h>
#include "donald.h"

#define die(s, ...) do { fprintf(stderr, DONALD_NAME ": " s , ##__VA_ARGS__); exit(-1); } while(0)
// #define die(s, ...) do { fwrite(DONALD_NAME ": " s , sizeof DONALD_NAME ": " s, 1, stderr); exit(-1); } while(0)

void cover_tracks(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum, const char *ldso_path) __attribute__((visibility("hidden")));
void cover_tracks(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum, const char *ldso_path)
{	
	// FIXME: arrange for us to be unmapped and disappear
	/* FIXME: other transparency issues:
	(gdb) run
Starting program: /usr/local/src/liballocs/tests/allocsld-as-ldso/allocsld-as-ldso 
warning: Unable to find dynamic linker breakpoint function.
GDB will be unable to debug shared library initializers
and track explicitly loaded dynamic code.

... WHAT's the problem here? It's true that we don't
define the symbol, but the hope was that by the time a link
map is built, ld.so will just see itself and think it was run
directly.. Recall that the r_debug protocol bootstraps
discovery of dynsyms by
(1) look at the executable (probably from /proc)
(2) find its DYNAMIC section using phdrs
(3) look in its DT_DEBUG entry
(4) expect this to point to the struct r_debug created by the ld.so.
So what's not happening?

The failure is reported at startup, so it can't be that the DT_DEBUG
entry is not updated yet; that happens later.

Maybe gdb is traversing the DT_NEEDEDs of the loaded DSOs, and
because it doesn't find the ld.so, does not find the _r_debug symbol?
If so: TRICKY! We can't use run-time mutation to help us, because
gdb is looking offline in the symtab content of the files on disk.

Luckily, gdb seems to be able to recover. If I break in 'main', i.e.
after ld.so has set up the DT_DEBUG entry, 'info shared' works.
But what about dynamic loading?

(gdb) print ((void*(*)(void*, int))dlopen)("/lib/x86_64-linux-gnu/libz.so.1", 257)
$13 = (void *) 0x5555555592f0
(gdb) info shared
From                To                  Syms Read   Shared Object Library
0x00007ffff7dfb000  0x00007ffff7dff129  Yes         /usr/local/src/liballocs/allocsld/allocsld.so
0x00007ffff7b9d6a0  0x00007ffff7b9db47  Yes         /usr/local/src/liballocs/tools/..//lib/liballocs_dummyweaks.so
0x00007ffff797d700  0x00007ffff7989fb2  Yes (*)     /usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8
0x00007ffff7762ee0  0x00007ffff776a1e2  Yes (*)     /usr/lib/x86_64-linux-gnu/libunwind.so.8
0x00007ffff775d130  0x00007ffff775de75  Yes (*)     /lib/x86_64-linux-gnu/libdl.so.2
0x00007ffff75bb320  0x00007ffff770139b  Yes (*)     /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7376090  0x00007ffff738cb92  Yes (*)     /lib/x86_64-linux-gnu/liblzma.so.5
0x00007ffff73585b0  0x00007ffff7366641  Yes         /lib/x86_64-linux-gnu/libpthread.so.0
0x00007ffff71333d0  0x00007ffff7146a70  No          /lib/x86_64-linux-gnu/libz.so.1
(*): Shared library is missing debugging information.

OK, that seems fine. Problem though:
(gdb) print _r_debug
Missing ELF symbol "_r_debug".

i.e. the real ld.so is missing from the 'info shared' list.
What about in the r_debug that we can reach from DT_DEBUG?
It's missing from that too! i.e. the ld.so did all the work,
but didn't create a link map entry for itself.

And why would it? It thinks its name is allocsld.so. But
how does it determine that? from _dl_argv[0]? Don't think
so -- surely it's not in argv in the not-the-program case.
AHA. It gets it from the program binary, since it must
name its interpreter. In the .interp section, naturally,
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


gives us a writable interp. How do we get a pointer to it?

	*/
	
	if (!we_are_the_program)
	{
		char *interp_addr = NULL;
		size_t interp_sz = 0;
		if (!program_phdrs) die("could not find the program phdrs\n");
		// the program should already have been mapped by the kernel. fix up its .interp
		// first we need the program's base addr, inferred from its PHDR phdr
		ElfW(Addr) program_base_addr = 0;
		for (int i = 0; i < program_phnum; ++i)
		{
			if (program_phdrs[i].p_type == PT_PHDR)
			{
				program_base_addr = (uintptr_t) program_phdrs
					- program_phdrs[i].p_vaddr;
			}
		}
		if (!program_base_addr) die("could not infer program base address (no PT_PHDR?)\n");
		for (int i = 0; i < program_phnum; ++i)
		{
			if (program_phdrs[i].p_type == PT_INTERP)
			{
				/* We should have a *writable* interp. If this isn't true, bail. */
				if (!we_are_the_program && !(program_phdrs[i].p_flags & PF_W))
				{
					die("PT_INTERP is not writable, so can't transparently chain-load ld.so\n"
						"special args are required when setting allocsld.so as the dynamic linker\n");
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
	}
	// FIXME: now munmap and/or mprotect some stuff:
	// munmap ourselves, to the extent we can
	// mprotect the interpreter string back to read-only
}
