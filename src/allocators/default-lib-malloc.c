/* This file uses GNU C extensions */
#define _GNU_SOURCE

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

/* This file should contain stuff that "could be generated", although
 * for now we're only generating some of it. */

/* This is the default, but go with it anyway. */
#define ALLOC_EVENT_ATTRIBUTES __attribute__((visibility("hidden")))
#define ALLOC_ALLOCATOR_NAME(frag) frag ## _allocator

/* Protos for our hook functions. The mallocapi-to-hookapi glue comes
 * from a copy of alloc_events.c. */
#include "alloc_events.h"

/* hookapi-to-indexapi glue. Which can be generated! */
/* FIXME: We could e.g. also parameterise
 * the generation by alignment, or some other parameter of the malloc,
 * so that the code is tailored to that malloc. */
#define ALLOC_EVENT_INDEXING_DEFS2(allocator_namefrag, do_lifetime_policies) \
ALLOC_EVENT_ATTRIBUTES void ALLOC_EVENT(post_init)(void) {} \
ALLOC_EVENT_ATTRIBUTES \
void  \
ALLOC_EVENT(post_successful_alloc)(void *allocptr, size_t modified_size, size_t modified_alignment, \
		size_t requested_size, size_t requested_alignment, const void *caller) \
{ \
	__generic_malloc_index_insert(arena_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), allocptr), \
		allocptr /* == userptr */, requested_size, \
		__current_allocsite ? __current_allocsite : caller); \
} \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(pre_alloc)(size_t *p_size, size_t *p_alignment, const void *caller) \
{ \
	/* We increase the size by the amount of extra data we store,  \
	 * and possibly a bit more to allow for alignment.  */ \
	size_t orig_size = *p_size; \
	size_t size_to_allocate = CHUNK_SIZE_WITH_TRAILER(orig_size, struct extended_insert, void*); \
	assert(0 == size_to_allocate % ALIGNOF(void *)); \
	*p_size = size_to_allocate; \
} \
ALLOC_EVENT_ATTRIBUTES \
int ALLOC_EVENT(pre_nonnull_free)(void *userptr, size_t freed_usable_size) \
{ \
	if (do_lifetime_policies) /* always statically known but we can't #ifdef here */ \
	{ \
		lifetime_insert_t *lti = lifetime_insert_for_chunk(userptr); \
		*lti &= ~MANUAL_DEALLOCATION_FLAG; \
		if (*lti) return 1; /* Cancel free if we are still alive */ \
		__notify_free(userptr); \
	} \
	__generic_malloc_index_delete(arena_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), userptr/*, freed_usable_size*/); \
	return 0; \
} \
 \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(post_nonnull_free)(void *userptr) \
{} \
 \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(pre_nonnull_nonzero_realloc)(void *userptr, size_t size, const void *caller) \
{ \
	/* When this happens, we *may or may not be freeing an area* */ \
	/* -- i.e. if the realloc fails, we will not actually free anything. */ \
	/* However, when we were using trailers, and  */ \
	/* in the case of realloc()ing a *slightly smaller* region,  */ \
	/* the allocator might trash our insert (by writing its own data over it).  */ \
	/* So we *must* delete the entry first, */ \
	/* then recreate it later, as it may not survive the realloc() uncorrupted. */  \
	/* */ \
	/* Another complication: if we're realloc'ing a bigalloc, we might have to */ \
	/* move its children. BUT should the user ever do this? It's only sensible */ \
	/* to realloc a suballocated area if you know the realloc will happen in-place,  */ \
	/* i.e. if you're making it smaller (only).  */ \
	/*  */ \
	/* BUT some bigallocs are just big; they needn't have children.  */ \
	/* For those, does it matter if we delete and then re-create the bigalloc record? */ \
	/* I don't see why it should. */ \
	__generic_malloc_index_delete(arena_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), userptr/*, malloc_usable_size(ptr)*/); \
} \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(post_nonnull_nonzero_realloc)(void *userptr, \
	size_t modified_size,  \
	size_t old_usable_size, \
	const void *caller, void *new_allocptr) \
{ \
	/* FIXME: This requested size could be wrong. */ \
	/* The caller should give us the real requested size instead. */ \
	size_t requested_size = __current_allocsz ? __current_allocsz : \
		modified_size - sizeof(struct extended_insert); \
	__generic_malloc_index_reinsert_after_resize(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), \
		userptr, \
		modified_size, \
		old_usable_size, \
		requested_size, \
		caller, \
		new_allocptr \
	); \
} \
/* Now the allocator itself. */ \
extern struct allocator ALLOC_ALLOCATOR_NAME(allocator_namefrag); \
static struct big_allocation *ensure_big(void *addr, size_t size) \
{ \
	return __generic_malloc_ensure_big(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), addr, size); \
} \
static liballocs_err_t set_type(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *new_type) \
{ \
	return __generic_malloc_set_type(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), maybe_the_allocation, \
			obj, new_type); \
} \
static liballocs_err_t get_info( \
	void *obj, struct big_allocation *maybe_the_allocation, \
	struct uniqtype **out_type, void **out_base,  \
	unsigned long *out_size, const void **out_site) \
{ \
	return __generic_malloc_get_info(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), obj, maybe_the_allocation, \
		out_type, out_base, out_size, out_site); \
} \
 \
ALLOC_EVENT_ATTRIBUTES \
struct allocator ALLOC_ALLOCATOR_NAME(allocator_namefrag) = { \
	.name = #allocator_namefrag, \
	.get_info = get_info, \
	.is_cacheable = 1, \
	.ensure_big = ensure_big, \
	.set_type = set_type, \
	.free = (void (*)(struct allocated_chunk *)) free, \
};

#ifdef LIFETIME_POLICIES
#define __do_lp 1
#else
#define __do_lp 0
#endif
#define ALLOC_EVENT_INDEXING_DEFS(allocator_namefrag) \
  ALLOC_EVENT_INDEXING_DEFS2(allocator_namefrag, __do_lp)

ALLOC_EVENT_INDEXING_DEFS(__default_lib_malloc)

/* By default, the 'malloc' first in libraries' link order, i.e. the one */
/* our preload sits in front of, is deemed the global malloc. But if the */
/* executable has one too, it should override this. */
extern struct allocator __global_malloc_allocator
__attribute__((weak,alias("__default_lib_malloc_allocator")));
