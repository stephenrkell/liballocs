#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <link.h>
/* Bit of a hack: we don't assume a system-wide 'dwarf.h' and instead vendor
 * our chosen libdwarf. The best way to get at it is still via libdwarfpp. */
#ifndef DWARF_H
#define DWARF_H "dwarf.h"
#endif
#include DWARF_H
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "librunt.h"
#include "relf.h"
#include "maps.h"
#include "systrap.h"
#include "raw-syscalls-defs.h"
#include "liballocs.h"
#include "liballocs_private.h"
#include "allocsites.h"
#include "dlbind.h"

#ifdef _LIBGEN_H
#error "liballocs.c needs GNU basename() so must not include libgen.h"
#endif

_Bool __liballocs_is_initialized;

// HACK
void __liballocs_preload_init(void);

_Bool done_main_init __attribute__((visibility("hidden")));
void __liballocs_main_init(void) __attribute__((constructor(101),visibility("protected")));
// NOTE: runs *before* the constructor in preload.c
__attribute__((constructor(101),visibility("protected")))
void __liballocs_main_init(void)
{
	assert(!done_main_init);

	/* This is a dummy: we choose not to initialise anything at this point, for now.
	 * PROBLEM: gcc optimizes the constructor out! Because after eliminating done_init,
	 * we have no observable effect, it concludes there's no need to put us in
	 * .init_array. This rightly fails our 'constructor priority' check. We make the
	 * done_main_init non-static as a workaround. */

	done_main_init = 1;
}

/* We want to be called early, but not too early, because it might not be safe 
 * to open the -uniqtypes.so handle yet. */
int __liballocs_global_init(void) __attribute__((constructor(103),visibility("protected")));
int ( __attribute__((constructor(103))) __liballocs_global_init)(void)
{
	// write_string("Hello from liballocs global init!\n");
	if (__liballocs_is_initialized) return 0; // we are okay

	// don't try more than once to initialize
	static _Bool tried_to_initialize;
	if (tried_to_initialize) return -1;
	tried_to_initialize = 1;
	
	static _Bool trying_to_initialize;
	if (trying_to_initialize) return 0;
	trying_to_initialize = 1;
	
	// print a summary when the program exits
	atexit(print_exit_summary);

	const char *debug_level_str = getenv("LIBALLOCS_DEBUG_LEVEL");
	if (debug_level_str) __liballocs_debug_level = atoi(debug_level_str);

	if (!orig_dlopen) // might have been done by a pre-init call to our preload dlopen
	{
		orig_dlopen = fake_dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlopen);
		orig_memmove = fake_dlsym(RTLD_NEXT, "memmove");
		assert(orig_memmove);
	}

	/* NOTE that we get called during allocation. So we should avoid 
	 * doing anything that causes more allocation, or else we should
	 * handle the reentrancy gracefully. Calling the dynamic linker
	 * is dangerous. What can we do? Either
	 * 
	 * 1. try to make this function run early, i.e. before main() 
	 *    and during a non-allocation context. 
	 * 
	 * or
	 * 
	 * 2. get the end address without resort to dlopen()... but then
	 *    what about the types objects? 
	 * 
	 * It seems that option 1 is better. 
	 */
	__mmap_allocator_init();
	__static_file_allocator_init();
	
	/* Don't do this. They all have constructors, so it's not necessary.
	 * Moreover, the mmap allocator's constructor 
	 * calls *us* (if we haven't already run) 
	 * because it can't start the systrap before we've loaded all the
	 * metadata for the loaded objects (the "__brk" problem). */
	// __stack_allocator_init();
	// __mmap_allocator_init();
	// __static_allocator_init();
	// __auxv_allocator_init();
	
	// don't init dlbind here -- do it in the mmap allocator, *after* we've started systrap
	//__libdlbind_do_init();
	//__liballocs_rt_uniqtypes_obj = dlcreate("duniqtypes");
	
	trying_to_initialize = 0;
	__liballocs_is_initialized = 1;

	debug_printf(1, "liballocs successfully initialized\n");
	workaround_glibc_bugs();
	
	return 0;
}

void __liballocs_post_systrap_init(void)
{
	/* For testing, become no-op if systrap was not init'd. */
	if (__liballocs_systrap_is_initialized)
	{
		/* Now we can correctly initialize libdlbind. It might malloc,
		 * ensure we have what we need initialized. */
		__brk_allocator_init();
		__libdlbind_do_init();
		init_rt_uniqtypes_obj();
	}
}

// Weak no-op versions of notification functions to prevent undefined symbols
void __notify_copy(void *dest, const void *src, unsigned long n) __attribute__((weak));
void __notify_copy(void *dest, const void *src, unsigned long n) {}
void __notify_free(void *dest) __attribute__((weak));
void __notify_free(void *dest) {}
