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
#include "relf.h"
#include "liballocs_private.h"
#include "pageindex.h"
#include "heap_index.h"

struct allocator __alloca_allocator = {
	.name = "alloca",
	.is_cacheable = 1,   // HMM: am I sure that we're cacheable?
	.get_info = __generic_heap_get_info
};

void __liballocs_unindex_stack_objects_counted_by(unsigned long *bytes_counter, void *frame_addr)
{
	struct big_allocation *b = __lookup_bigalloc_under_pageindex(bytes_counter, &__stackframe_allocator, NULL);
	if (*bytes_counter == 0) goto out;
	if (!b) abort();
	
	/* Starting at the stack pointer, we look for indexed chunks and 
	 * keep unindexing until we have unindexed exactly *bytes_counter bytes. */
	void *sp;
	#ifdef UNW_TARGET_X86
		__asm__ ("movl %%esp, %0\n" :"=r"(sp));
	#else // assume X86_64 for now
		__asm__("movq %%rsp, %0\n" : "=r"(sp));
	#endif

	struct entry *first_head = INDEX_LOC_FOR_ADDR(sp);
	struct entry *cur_head = first_head;
	unsigned long total_to_unindex = *bytes_counter;
	unsigned long total_unindexed = 0;
	unsigned chunks_unindexed = 0;
	
	/* Iterate forward over the buckets, but not beyond frame_addr's bucket. */
	for (; cur_head != INDEX_LOC_FOR_ADDR(frame_addr) + 1; ++cur_head)
	{
		/* Repeatedly find the lowest-addressed chunk and unindex it. */
		while (entry_ptr_to_addr(cur_head) != NULL)
		{
			void *cur_userchunk = entry_ptr_to_addr(cur_head);
			struct insert *cur_insert = insert_for_chunk(cur_userchunk);
			void *lowest_chunkaddr = cur_userchunk;

			for (;
				cur_userchunk; 
				cur_userchunk = entry_to_same_range_addr(cur_insert->un.ptrs.next, cur_userchunk), 
					cur_insert = cur_userchunk ? insert_for_chunk(cur_userchunk) : NULL)
			{
				if ((char*) cur_userchunk < (char*) lowest_chunkaddr)
				{
					lowest_chunkaddr = cur_userchunk;
				}
			}
			
			/* Now we definitely have a lowest chunk addr */
			unsigned long bytes_to_unindex = malloc_usable_size(lowest_chunkaddr);
			__liballocs_index_delete(lowest_chunkaddr);
			total_unindexed += bytes_to_unindex;
			++chunks_unindexed;
			if (total_unindexed >= total_to_unindex)
			{
				if (total_unindexed > total_to_unindex)
				{
					fprintf(stderr, 
						"Warning: unindexed too many bytes "
						"(requested %lu from %p; got %lu in %u chunks)\n",
						total_to_unindex, frame_addr, total_unindexed, chunks_unindexed);
				}
				goto out;
			}
		}
	}
	assert(0);
	
out:
	/* FIXME: be more discriminating in what cache we zap -- only ours or children */
	__liballocs_uncache_all(frame_addr, total_to_unindex);
	if (b) __liballocs_delete_bigalloc_at(bytes_counter, &__stackframe_allocator);
}

/* We have a special connection here. */
struct big_allocation *__stackframe_allocator_find_or_create_bigalloc(
		unsigned long *frame_counter, const void *caller, const void *frame_sp_at_caller, 
		const void *frame_bp_at_caller);

void __alloca_allocator_notify(void *new_userchunkaddr,
		unsigned long requested_size, unsigned long *frame_counter,
		const void *caller, const void *sp_at_caller, const void *bp_at_caller)
{
	/* 1. We need to register the current frame as a "big" allocation, or
	 *    if it already is "big", to extend that to cover the current extent.
	 *    NOTE also that the "cracks" case suddenly becomes important: 
	 *    without crack handling, other locals in the frame will suddenly
	 *    become invisible to get_info calls.
	 *    (One quick fix might be to have the frame's first alloca call
	 *    pad the stack to a page boundary, and pad the amount to something
	 *    page-aligned, so that the pageindex always gives an exact hit.)
	 */
	// XXX: sp as passed by caller is unreliable -- can come out much higher
	// than the actual post-alloca rsp. Not sure why. But can use the chunk addr
	// as our stack lower bound.
	//assert((char*) new_userchunkaddr >= (char*) sp_at_caller);
	struct big_allocation *b = __stackframe_allocator_find_or_create_bigalloc(
		frame_counter, caller, /*sp_at_caller*/ new_userchunkaddr, bp_at_caller);
	assert(b);
	if (!b->suballocator) b->suballocator = &__alloca_allocator;
	else if (b->suballocator != &__alloca_allocator) abort();
	
	/* Extend the frame bigalloc to include this alloca. Note that we're *prepending*
	 * to the allocation. */
	__liballocs_pre_extend_bigalloc_recursive(b, /*sp_at_caller*/ new_userchunkaddr);
	 
	/* index it */
	__liballocs_index_insert(new_userchunkaddr, requested_size, caller);
	
#undef __liballocs_get_alloc_base /* inlcache HACKaround */
	assert(__liballocs_get_alloc_base(new_userchunkaddr));
	assert(((void*(*)(void*))(__liballocs_get_alloc_base))(new_userchunkaddr) == new_userchunkaddr);
}

