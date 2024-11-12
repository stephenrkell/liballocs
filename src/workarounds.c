#define _GNU_SOURCE  /* get the right basename() */
#include <string.h>
#include <link.h>
#include "relf.h"
#if 0
#include "donald.h"
#endif
#include "liballocs_private.h"

#ifdef _LIBGEN_H
#error "liballocs.c needs GNU basename() so must not include libgen.h"
#endif

/* This gets called from __liballocs_global_init. */
__attribute__((visibility("hidden")))
void workaround_glibc_bugs(void) 
{
	/* Do we have glibc? Quick check: libc.so.6 soname and
	 * anything else? ideally symbol versions, but skip for now */
	for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
	{
		if (l->l_name && 0 == strcmp(basename(l->l_name), "libc.so.6"))
		{
			/* OK, seems to be glibc. 
			 * Do we have type information for link map entries? */
			struct allocator *a = alloc_get_allocator(l);
			size_t sz = alloc_get_size(l);
			struct uniqtype *u = alloc_get_type(l);
			const void *site = alloc_get_site(l);
			void *base = alloc_get_base(l);
			assert(a);
			debug_printf(0, "first link map is at %p, a %s-allocated object of size %u, type %s, "
				"site %p, base %p\n",
				l, a->name, (unsigned) sz, UNIQTYPE_NAME(u), site, base);

			if (!u)
			{
				debug_printf(0, "no type information for link maps, so cannot apply glibc workarounds\n");
				return;
			}

		}
	}
}

/* To instrument the allocation functions
 * in the ld.so,
 * we need to do a pass to figure out what's there.
 * E.g. we can't assume that instrumenting 'malloc' is all that's needed,
 * because 
 *
 * We could take our lead from LIBALLOCS_ALLOC_FNS, which is already
 * our mechanism for telling us about this. It seems clunky that correct
 * operation would depend on this env var being set, though, in the case of
 * the ld.so. That variable is more of a toolchain-side thing (and perhaps,
 * FIXME, we should solidify that by putting it into a .note section or similar?).
 *
 * So assuming we should do something else for the ld.so, what should it be?
 * The relevant symbols in my own system's ld.so, that would make things work
 * for me Right Now, are: well, they're not! They're not in any symtab. However
 * they are in .extrasyms.
 *
 *
 */
