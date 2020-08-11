#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "relf.h"
#include "vas.h"
#include "liballocs_private.h"
#include "pageindex.h"

static liballocs_err_t get_info(void * obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site);
	
struct allocator __stack_allocator = {
	.name = "stack",
	.min_alignment = PAGE_SIZE, /* should be MIN_PAGE_SIZE */
	.is_cacheable = 0,
	.get_info = get_info
};

static _Bool trying_to_initialize;
static _Bool initialized;

rlim_t __stack_lim_cur __attribute__((visibility("protected")));
rlim_t __stack_lim_max __attribute__((visibility("protected")));

struct suballocated_chunk_rec; // FIXME: remove once heap_index has been refactored

static struct big_allocation *initial_stack_bigalloc;

void (__attribute__((constructor(101))) __stack_allocator_init)(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		
		// grab the maximum stack size
		struct rlimit rlim;
		int rlret = getrlimit(RLIMIT_STACK, &rlim);
		if (rlret == 0)
		{
			__stack_lim_cur = rlim.rlim_cur;
			__stack_lim_max = rlim.rlim_max;
		} else abort();
		
		initialized = 1;
		trying_to_initialize = 0;
		
		/* NOTE: we don't add any mappings initially; we rely on the mmap allocator 
		 * to tell us about them. Similarly for new mappings, we rely on the 
		 * mmap trap logic to identify them, by their MAP_GROWSDOWN flag. */
	}
}

void __stack_allocator_notify_init_stack_region(void *begin, void *end)
{
	initial_stack_bigalloc = __liballocs_new_bigalloc(
		begin,
		(char*) end - (char*) begin,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: {
					.data_ptr = NULL, /* thread a list of *all* stacks through here */
					.free_func = NULL
				}
			}
		},
		NULL, /* Will fill in auxv bigalloc */
		&__stack_allocator
	);
	if (!initial_stack_bigalloc) abort();
	if (!initial_stack_bigalloc->parent || initial_stack_bigalloc->parent->allocated_by
				!= &__auxv_allocator) abort();
	
	/* FIXME: is this necessarily right? a GROWSDOWN mapping might actually 
	 * be managed some other way. */
	initial_stack_bigalloc->suballocator = &__stackframe_allocator;
}

static liballocs_err_t get_info(void *obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void** out_site)
{
	return &__liballocs_err_unrecognised_alloc_site;
}

static size_t guess_sane_max_stack_size(void)
{
	if (__stack_lim_cur == -1 && __stack_lim_max == -1)
	{
		/* No limit set at all. 16MB? */
		return 16 * 1024 * 1024;
	}
	else if (__stack_lim_cur == -1)
	{
		// use max
		return __stack_lim_max;
	} else return __stack_lim_cur;
}

static size_t guess_sane_max_stack_delta(void)
{
	if (__stack_lim_cur == -1 && __stack_lim_max == -1)
	{
		/* No limit set at all. 256kB? */
		return 256 * 1024;
	}
	// else a sensible delta is the max size
	else return guess_sane_max_stack_size();
}

_Bool __stack_allocator_notify_unindexed_address(const void *ptr)
{
	/* Do we claim it? */
	for (struct big_allocation *b = initial_stack_bigalloc;
				b;
				b = (struct big_allocation *) b->meta.un.opaque_data.data_ptr)
	{
		/* Is the address within a sensible distance of the highest addr of this stack,
		 * with no intervening mapping between it and 
		 * HMM. It's possible that __stack_lim_cur is not set, or is -1. */
		ptrdiff_t diff_from_lowest_stack_addr = (char*) b->begin - (char*) ptr;
		ptrdiff_t diff_from_highest_stack_addr = (char*) b->end - (char*) ptr;
		
		if (	(
				(diff_from_lowest_stack_addr > 0 && 
				 diff_from_lowest_stack_addr < guess_sane_max_stack_delta())
			||  (diff_from_highest_stack_addr > 0 && 
				 diff_from_highest_stack_addr < guess_sane_max_stack_size())
				)
			&& __pages_unused(
					ROUND_UP_PTR(ptr, PAGE_SIZE),
					b->begin
				)
		)
		{
			/* Okay, claim it. CHECK if our parent is the auxv (initial stack)
			 * allocation. If so, then before we pre-extend ourselves, pre-extend
			 * the auxv bigalloc and its mmap parent. FIXME: should be a bigalloc
			 * utility call for this. */
			__liballocs_pre_extend_bigalloc_recursive(b, ROUND_DOWN_PTR(ptr, PAGE_SIZE));
			return 1;
		}
	}
	return 0;
}
