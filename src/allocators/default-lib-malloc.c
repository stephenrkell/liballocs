/* This file uses GNU C extensions */
#define _GNU_SOURCE

/* We need to create global hooks, not hidden.
 * Must match how we pull in libmallochooks source files in src/Makefile. */
#define ALLOC_EVENT_ATTRIBUTES
#define ALLOC_EVENT(s) __liballocs_malloc_ ## s

#include <sys/types.h>
size_t malloc_usable_size(void *ptr);
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include "liballocs_private.h"
#include "relf.h"
#include "pageindex.h"
#include "generic_malloc_index.h"
#include "malloc-meta.h"

/* Stuff we need to generate glue goes in here. */
#include "../tools/stubgen.h" /* this pathname is a HACK */

/* To be the "default lib malloc" means the one that any preloads
 * in this, preloaded library, will override. */
// FIXME: this indirect call is potentially slow. Could we instead use an ifunc?
static size_t __default_lib_malloc_usable_size(void *ptr)
{
	static size_t (*real_malloc_usable_size)(void *);
	if (!real_malloc_usable_size)
	{
		real_malloc_usable_size = fake_dlsym(RTLD_NEXT, "malloc_usable_size");
	}
	return real_malloc_usable_size(ptr);
}
ALLOC_EVENT_INDEXING_DEFS4(
	/* allocator_namefrag */__default_lib_malloc,
	/* index_namefrag */ __generic_malloc,
	/* sizefn */ __default_lib_malloc_usable_size,
	/* initial_policies */ MANUAL_DEALLOCATION_FLAG
);
ALLOC_EVENT_ALLOCATOR_DEFS4(
	/* allocator_namefrag */__default_lib_malloc,
	/* index_namefrag */ __generic_malloc,
	/* sizefn */ __default_lib_malloc_usable_size,
	/* initial_policies */ MANUAL_DEALLOCATION_FLAG
);

/* By default, the 'malloc' first in libraries' link order, i.e. the one */
/* our preload sits in front of, is deemed the global malloc. But if the */
/* executable has one too, it should override this. */
extern struct allocator __global_malloc_allocator
__attribute__((weak,alias("__default_lib_malloc_allocator")));
