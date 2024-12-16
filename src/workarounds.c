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

static void validate_or_fix_link_map(void *obj, struct uniqtype *u)
{
#if 0
	/* The bug we care about is where r_nlist does not match
	 * l_initfini's length. */
	
#define FIELD_OFFSET(name) \
	for (unsigned i = 0
#define GET_FIELD(name, localtype) \
	({ localtype buf; memcpy(&buf, (char*)(obj) + FIELD_OFFSET(name), sizeof buf); buf })
#endif
}

/* This gets called from __liballocs_global_init. */
__attribute__((visibility("hidden")))
void workaround_glibc_bugs(void) 
{
	/* We need the ld.so malloc allocator to be working. */
	__ld_so_malloc_allocator_init();

	/* One of glibc's link maps is allocated statically, so
	 * we can get the uniqtype even without the heap information. */
	struct uniqtype *link_map_type = NULL;
	for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
	{
		struct uniqtype *u = alloc_get_type(l);
		if (u) link_map_type = u;
	}
	if (!link_map_type)
	{
		debug_printf(0, "warning: no type information for ld.so link maps, so can't apply workarounds\n");
		goto out;
	}
	else
	{

		/* Do we have glibc? Quick check: libc.so.6 soname and
		 * anything else? ideally symbol versions, but skip for now */
		_Bool warned = 0;
		_Bool seen_glibc = 0;
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			/* Do we have type information for link map entries? */
			struct allocator *a = alloc_get_allocator(l);
			size_t sz = alloc_get_size(l);
			const void *site = alloc_get_site(l);
			struct uniqtype *u = alloc_get_type(l);
			void *base = alloc_get_base(l);
			assert(a);

			if (l ==  _r_debug.r_map)
			{
				debug_printf(0, "first link map is at %p, a %s-allocated object of size %u, type %s, "
					"site %p, base %p\n",
					l, a->name, (unsigned) sz, UNIQTYPE_NAME(u), site, base);
			}

			if (!site && a != &__static_symbol_allocator && !warned)
			{
				debug_printf(0, "warning: incomplete metadata for ld.so link maps\n");
				warned = 1;
			}

			if (l->l_name && 0 == strcmp(basename(l->l_name), "libc.so.6"))
			{
				/* OK, seems to be glibc. FIXME: do more checks */
				seen_glibc = 1;
			}
		}
		if (!seen_glibc)
		{
			debug_printf(0, "not glibc so no workarounds applied\n");
			goto out;
		}
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			validate_or_fix_link_map(l, link_map_type);
		}
	}
out:
	/* We may have done a bunch of liballocs queries in the above, and some
	 * of them may have failed. So re-zero our counters... this is so that
	 * we don't break test cases that pass based on zero failures.
	 * This is a HACK. */
	__liballocs_hit_heap_case = 0;
	__liballocs_hit_static_case = 0;
	__liballocs_aborted_unindexed_heap = 0;
	__liballocs_aborted_unrecognised_allocsite = 0;
	__liballocs_aborted_static = 0;
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
