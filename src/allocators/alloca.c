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
	.is_cacheable = 0
};

void __liballocs_unindex_stack_objects_counted_by(unsigned long *bytes_counter, void *frame_addr)
{
	if (*bytes_counter == 0) return;
	
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
				return;
			}
		}
	}
	assert(0);
}

void __alloca_allocator_notify(void *new_userchunkaddr, unsigned long modified_size, 
		const void *caller)
{
	/* FIXME: 
	 * 
	 * - we need to register the current frame as a "big" allocation, or
	 *   if it already is "big", to extend that to cover the current extent.
	 *   NOTE also that the "cracks" case suddenly becomes important: 
	 *   without crack handling, other locals in the frame will suddenly
	 *   become invisible to get_info calls.
	 *   (One quick fix might be to have the frame's first alloca call
	 *   pad the stack to a page boundary, and pad the amount to something
	 *   page-aligned, so that the pageindex always gives an exact hit.)
	 */
	__liballocs_index_insert(new_userchunkaddr, modified_size, caller);
}
