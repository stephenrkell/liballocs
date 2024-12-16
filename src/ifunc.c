/* Helpers for liballocs ifuncs.
 * How should this work?
 *
 * We need a helper to detect when liballocs is in preload position.
 * If it is, our ifuncs bind to the real definitions.
 * If it isn't, they bind to dummy definitions *if they exist*.
 *  -- for data, it may not be necessary or desirable to have dummies
 *  -- let's only use IFUNC symbols if a dummy exists
 */
// A minimal IFUNC example looks like the following (from linksem).
#if 0
/* dynamic linker does roughly this */
			void **site = (void**) p_r->r_offset;
			void *(*resolver)(void) = (void*) p_r->r_addend;
			*site = resolver();
#endif
#define _GNU_SOURCE /* for basename() */
#include <string.h>
#include <stdint.h>
#include "librunt.h"
#include "relf.h"
#include "raw-syscalls-defs.h"

#ifdef _LIBGEN_H
#error "ifunc.c needs GNU basename() so must not include libgen.h"
#endif

static _Bool checked_position;
static _Bool is_in_head_preload_position;
static _Bool check_head_preload_position(void)
{
	if (checked_position) return is_in_head_preload_position;
	// else we need to check position in the link map
	struct r_debug *r = find_r_debug();
	/* FIXME: need proper soname. */
	/* FIXME: can we just use "our link map" and forget the soname check?
	 * We know whether we're linked into the real liballocs or not. */
	struct link_map *l;
	for (l = r->r_map; l; l = l->l_next)
	{
		/* Skip over the executable. */
		if (0 == strcmp(l->l_name, "")) continue;
		/* Skip over the VDSO. */ // FIXME: this is sysdep
#define IS_VDSO(n)  (0 == strcmp((n), "linux-vdso.so.1"))
		if (IS_VDSO(l->l_name)) continue;
		break;
	}
	if (!l) { /* We didn't find ourselves.*/ abort(); }
#if 0
	write_string("First non-skippable link map entry name: ");
	raw_write(2, l->l_name, strlen(l->l_name));
	write_string("\n");
#endif
	if (l->l_next)
	{
#if 0
		write_string("Second non-skippable link map entry name: ");
		raw_write(2, l->l_next->l_name, strlen(l->l_next->l_name));
		write_string("\n");
#endif
	}
#ifndef LIBALLOCS_SONAME
#warning "IFUNC test code assuming liballocs soname is liballocs_preload.so (but we should change to liballocs.so)"
#define LIBALLOCS_SONAME "liballocs_preload.so"
#endif
	_Bool result = (l && l->l_name && 0 == strcmp(basename(l->l_name), LIBALLOCS_SONAME));
	checked_position = 1;
	is_in_head_preload_position = result;
	return result;
}

/* From liballocs.a, what's our plan to generate these?
 * We can probably use libcxxgen.
 * Only liballocs's 'public' symbols need to be considered.
 *
 * - version script for liballocs's non-hidden global text symbols
 * - build-time error if we find an unversioned non-hidden global text symbol
 * - replace this file with a generated ifunc.c using libcxxgen...
 * - ... containing for each symbol (1) an ifunc, and (2) a _nopreload stub
 * - build liballocs.so from liballocs.a, symbol-prefix'd (via .objcopy-opts file)
 * - for 'inherited' symbols, either vendor or use --exclude-libs to hide
 * - API cleanup/minimisation
 * - make it a link-time error to link statically with liballocs.a
 *       (how? why did we previously allow linking statically?
 *        am I sure it needs to be ruled out?
 *        problem is that the result still needs to be preloaded on,
 *        esp if it gets linked into a DSO... maybe only error-out on that,
 *        and support as-if-preloading linking into an exe? Can we
 *        ensure we interpose on the things we want to interpose on?
 *        maybe the static-linking case should supply liballocs.o not
 *        liballocs.a? or liballocs.a could be a linker script separating out
 *        the must-have from the optional archivey stuff?)
 * */

__attribute__((visibility("hidden")))
int __liballocs_test_ifunc_nopreload(void) { return 41; }
__attribute__((visibility("hidden")))
int __liballocs_test_ifunc_preload(void) { return 42; }

typedef uintptr_t (*func_ptr_t)();
func_ptr_t __liballocs_test_ifunc(void)
{
	if (check_head_preload_position()) return (func_ptr_t) __liballocs_test_ifunc_preload;
	return (func_ptr_t) __liballocs_test_ifunc_nopreload;
}
__asm__(".type __liballocs_test_ifunc,%gnu_indirect_function");

/* So the code literally binds against an ifunc as if it were
 * the function being called. But the defining symbol is actually
 * of type %gnu_indirect_function. XXX: why does the dynamic linker
 * receive the resolver as the added of the reloc record? Why is it
 * not the resolution of the symbol?
 * */
 
