#ifndef _LINEAR_MALLOC_INDEX_H
#define _LINEAR_MALLOC_INDEX_H

/* Note: you have to be _GNU_SOURCE to use this file. */
#ifndef _GNU_SOURCE /* ensure we get PTHREAD_MUTEX_RECURSIVE_NP */
#error "Not _GNU_SOURCE!"
#endif

#include <stdbool.h>
#include "liballocs_config.h"
#include "liballocs.h"
#include "liballocs_ext.h"
#include "pageindex.h"
#include "malloc-meta.h"

struct linear_malloc_rec {
	void *addr;
	unsigned caller_requested_size; // 32 bits should be enough
	unsigned char padding_to_caller_usable_size;
	// te insert lives at userptr + caller_usable_size
};

struct linear_malloc_index_instance {
	/* We have to chain a bigalloc-creating shim onto these once liballocs
	 * starts up. Otherwise we won't be able to find the linear malloc arenas
	 * starting from a liballocs query, which always proceeds via the pageindex.
	 * So we slurp the addresses of our *pointers* to the original malloc-family
	 * functions, and chain our handler after we've done an initial scan of
	 * the chunks indexed so far. */
	void *(**p_orig_malloc)(size_t);
	void *(**p_orig_calloc)(size_t, size_t);
	void *(**p_orig_realloc)(void *, size_t);
	void  (**p_orig_free)(void*);
	struct linear_malloc_rec *recs;
	unsigned nrecs;
	unsigned nrecs_used;
};


#ifndef MAX_LINEAR_MALLOCS
#define space_left_in_one_page  (\
    (4096 - \
     sizeof (struct linear_malloc_index_instance)) \
    & ~((_Alignof (struct linear_malloc_rec)) - 1) \
)
#define MAX_LINEAR_MALLOCS \
   ( (space_left_in_one_page) / (sizeof (struct linear_malloc_rec)) )
#endif

static inline int compare_linear_mallocs(const void *arg1, const void *arg2)
{
	/* Mostly we just compare the addresses. But we want null
	 * addresses to float to the end, to handle deletions properly.
	 * So... */
	void *addr1 = ((struct linear_malloc_rec *) arg1)->addr;
	void *addr2 = ((struct linear_malloc_rec *) arg2)->addr;
	if (!addr1 && !addr2) return 0;
	if (!addr1) /* first argument is greater */ return 1;
	if (!addr2) /* second argument is greater */ return -1;	
	return (uintptr_t) addr1 - (uintptr_t) addr2;
}

static inline
struct linear_malloc_rec *find_linear_malloc_rec(void* addr, struct linear_malloc_rec *recs,
	unsigned nrecs, unsigned nrecs_used)
{
#define proj(r) ((uintptr_t)(r)->addr)
	struct linear_malloc_rec *found = bsearch_leq_generic(struct linear_malloc_rec,
		(uintptr_t) addr,
		recs,
		nrecs_used,
		proj);
#undef proj
	/* Does 'found' span the address we're looking for? */
	if (found &&
		(uintptr_t) addr < ((uintptr_t) found->addr + found->caller_requested_size)
	) return found; else return NULL;
}

static inline size_t linear_malloc_usable_size(void *arg, struct linear_malloc_rec *recs,
	unsigned nrecs, unsigned nrecs_used)
{
	struct linear_malloc_rec *found
	 = find_linear_malloc_rec(arg, recs, nrecs, nrecs_used);
	if (found && found->addr == arg)
	{
		return found->caller_requested_size + found->padding_to_caller_usable_size;
	}
	return (size_t) -1;
}

#endif
