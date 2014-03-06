#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "libcrunch_private.h"

void init_prefix_tree_from_maps(void)
{
	/* First use dl_iterate_phdr to check that all library mappings are in the tree 
	 * with a STATIC kind. Since we hook dlopen(), at least from the point where we're
	 * initialized, we should only have to do this on startup.  */
	dl_iterate_phdr(__libcrunch_add_all_mappings_cb, NULL);
	
	/* Now fill in the rest from /proc. */
	prefix_tree_add_missing_maps();
}

void prefix_tree_add_missing_maps(void)
{
	#define NUM_FIELDS 11
	unsigned long first, second;
	char r, w, x, p;
	unsigned offset;
	unsigned devmaj, devmin;
	unsigned inode;
	char rest[4096];

	char proc_buf[4096];
	int ret = snprintf(proc_buf, sizeof proc_buf, "/proc/%d/maps", getpid());
	assert(ret > 0);
	FILE *maps = fopen(proc_buf, "r");
	assert(maps);
	
	char *linebuf = NULL;
	ssize_t nread;
	while (getline(&linebuf, &nread, maps) != -1)
	{
		rest[0] = '\0';
		int fields_read = sscanf(linebuf, 
			"%lx-%lx %c%c%c%c %8x %2x:%2x %d %s\n",
			&first, &second, &r, &w, &x, &p, &offset, &devmaj, &devmin, &inode, rest);

		assert(fields_read >= (NUM_FIELDS-1)); // we might not get a "rest"
		
		// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
		if (second - first > 0 && first < STACK_BEGIN) // don't add kernel pages
		{
			// is there already a matching entry in the tree?
			void *obj = (void *)(uintptr_t) first;
			void *obj_lastbyte = (void *)((uintptr_t) second - 1);
			struct prefix_tree_node **match_prevptr;

			/* If both beginning and end are already covered, we assume 
			 * the whole thing is covered. HMM. */
			struct prefix_tree_node *match_first
			 = prefix_tree_deepest_match_from_root(obj, &match_prevptr);
			struct prefix_tree_node *match_second
			 = prefix_tree_deepest_match_from_root(obj_lastbyte, &match_prevptr);
			
			if (!match_first || !match_second)
			{
				// if 'rest' is '/' it's static, else it's heap or thread
				switch (rest[0])
				{
					case '\0': 
						prefix_tree_add(obj, second - first, HEAP, NULL);
						break;
					case '/': 
						/* library mappings are handled in the dlopen hook, so this 
						 * must be a mapped file that is *not* part of a library. 
						 * We call it MAPPED_FILE because we don't have type info for 
						 * these, and this way we will fail faster (and report it as 
						 * "unknown storage"). */
						prefix_tree_add(obj, second - first, MAPPED_FILE, rest);
						break;
					case '[':
						if (0 == strcmp(rest, "[stack]"))
						{
							prefix_tree_add(obj, second - first, STACK, obj);
						}
						else // treat it as heap
						{
							prefix_tree_add(obj, second - first, HEAP, NULL);
						}
						break;
					default:
						debug_printf(1, "Warning: could not classify maps entry with base %p\n,", obj);
				}
			}
		}
	}
	if (linebuf) free(linebuf);
	
	fclose(maps);
}

void *__try_index_l0(const void *ptr, size_t modified_size, const void *caller)
{
	/* We get called from heap_index when the malloc'd address is a multiple of the 
	 * page size. Check whether it fills (more-or-less) the alloc'd region, and if so,  
	 * install its trailer into the maps. We will fish it out in get_alloc_info. */
	
	__libcrunch_check_init();
	
	assert(page_size);
	
	if ((uintptr_t) ptr % page_size <= MAXIMUM_MALLOC_HEADER_OVERHEAD)
	{
		// ensure we have this in the maps
		enum object_memory_kind k1 = prefix_tree_get_memory_kind(ptr);
		enum object_memory_kind k2 = prefix_tree_get_memory_kind((char*) ptr + modified_size);
		if (k1 == UNKNOWN || k2 == UNKNOWN) 
		{
			prefix_tree_add_missing_maps();
			assert(prefix_tree_get_memory_kind(ptr) != UNKNOWN);
			assert(prefix_tree_get_memory_kind((char*) ptr + modified_size) != UNKNOWN);
		}
		
		/* Collect a contiguous sequence of so-far-l0-unindexed mappings, 
		 * starting from ptr. */
		
		const void *next_lower, *lowest = NULL, *upper = ptr, *cur = ptr;
		struct prefix_tree_node *n;
		unsigned nmappings = 0;
		do
		{
			n = prefix_tree_bounds(cur, &next_lower, &upper);
			cur = n ? upper : cur;
			if (n) ++nmappings;
			if (n && !lowest) lowest = next_lower;
		} while (n && !n->info.what);
		
		// do the lower/upper we extracted match the allocation?
		if ((uintptr_t) ptr <= (uintptr_t) lowest + MAXIMUM_MALLOC_HEADER_OVERHEAD 
				&& (uintptr_t) upper >= (uintptr_t) lowest + modified_size
					&& (uintptr_t) upper < (uintptr_t) lowest + modified_size + 2 * page_size)
		{
			/* We think we've got a mmap()'d region; */
			assert(caller);
			unsigned npages = ((uintptr_t) upper - (uintptr_t) lowest) >> log_page_size;
			
			/* We abuse the spare 16 bits in the word: 
			 * the top bit is set in the node that starts the allocation, 
			 * and the rest is the number of pages in the allocation. 
			 * FIXME: we also need to store the object's logical start from
			 * the start of the mapping, i.e. the malloc() header size.
			 */
			
			cur = ptr;
			lowest = NULL;
			struct prefix_tree_node *lowest_n = prefix_tree_bounds(ptr, NULL, NULL);
			do
			{
				n = prefix_tree_bounds(cur, &next_lower, &upper);
				cur = n ? upper : cur;
				if (n && !lowest) lowest = next_lower;
				n->info = (struct node_info) {
					.what = 1, 
					.un = {
						ins_and_bits: { 
							.ins = (struct insert) {
								.alloc_site_flag = 0,
								.alloc_site = (uintptr_t) caller
							},
							.is_object_start = (n == lowest_n), 
							.npages = npages, 
							.obj_offset = (char*) ptr - (char*) lowest
						}
					}
				};
			} while (n && !n->info.what);

			assert(lowest_n->info.what);
			return &lowest_n->info.un.ins_and_bits.ins;
		}
		else
		{
			debug_printf(3, "Warning: could not l0-index pointer %p in mapping range %p-%p (%u mappings)\n,", ptr, 
				lowest, upper, nmappings);
		}
	}
	
	return NULL;
}

unsigned __unindex_l0(const void *mem)
{
	const void *lower;
	const void *upper;
	struct prefix_tree_node *n = prefix_tree_bounds(mem, &lower, &upper);
	assert(n);

	/* We want to unindex the same number of pages we indexed. */
	unsigned npages_to_unindex = n->info.un.ins_and_bits.npages;
	unsigned lower_to_upper_npages = ((uintptr_t) upper - (uintptr_t) lower) >> log_page_size;
	
	n->info.what = 0;
	unsigned total_size_unindexed = lower_to_upper_npages << log_page_size;
	if (lower_to_upper_npages < npages_to_unindex)
	{
		total_size_unindexed += __unindex_l0(upper);
	}
	return total_size_unindexed;
}

struct insert *__lookup_l0(const void *mem, void **out_object_start)
{
	struct prefix_tree_node *n = prefix_tree_deepest_match_from_root((void*) mem, NULL);
	if (n && n->info.what)
	{
		// 1. we have to search backwards for the start of the mmapped region
		const void *cur = mem;
		const void *lower, *upper;
		// walk backwards through contiguous mappings, til we find one with the high bit set
		do
		{
			n = prefix_tree_bounds(cur, &lower, &upper);
			cur = n ? (const char*) lower - 1  : cur;
		} while (n && (assert(n->info.what), !n->info.un.ins_and_bits.is_object_start));
		
		// if n is null, it means we ran out of mappings before we saw the high bit
		assert(n);
		
		// then HACK HACK HACK OUTRAGEOUS HACK: 
		*out_object_start = (char*) lower + n->info.un.ins_and_bits.obj_offset;
		return (struct insert *) &n->info.un.ins_and_bits.ins;
	}
	else return NULL;
}
