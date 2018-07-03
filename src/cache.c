#define _GNU_SOURCE
#include "liballocs_cil_inlines.h"
#include "liballocs.h"
#include "pageindex.h"

// FIXME: this should be thread-local but my gdb can't grok that
struct __liballocs_memrange_cache /* __thread */ __liballocs_ool_cache = {
	.size_plus_one = 1 + LIBALLOCS_MEMRANGE_CACHE_MAX_SIZE,
	.next_victim = 1
};

/* FIXME: rewrite these */
void __liballocs_uncache_all(const void *allocptr, unsigned long size)
{
	assert((__liballocs_check_cache_sanity(&__liballocs_ool_cache), 1));
	for (unsigned i = 1; i < __liballocs_ool_cache.size_plus_one; ++i)
	{
		if (__liballocs_ool_cache.validity & (1u << (i-1)))
		{
			assert((__liballocs_check_cache_sanity(&__liballocs_ool_cache), 1));
			/* Uncache any object beginning anywhere within the passed-in range. */
			if ((char*) __liballocs_ool_cache.entries[i].obj_base >= (char*) allocptr
					 && (char*) __liballocs_ool_cache.entries[i].obj_base < (char*) allocptr + size)
			{
				// unset validity and make this the next victim
				__liballocs_cache_unlink(&__liballocs_ool_cache, i);
				__liballocs_ool_cache.next_victim = i;
			}
			assert((__liballocs_check_cache_sanity(&__liballocs_ool_cache), 1));
		}
	}
	assert((__liballocs_check_cache_sanity(&__liballocs_ool_cache), 1));
}
