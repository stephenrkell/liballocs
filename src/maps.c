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

_Bool initialized_maps __attribute__((visibility("protected")));

void init_prefix_tree_from_maps(void)
{
	if (!initialized_maps)
	{
		/* First use dl_iterate_phdr to check that all library mappings are in the tree 
		 * with a STATIC kind. Since we hook dlopen(), at least from the point where we're
		 * initialized, we should only have to do this on startup.  */
		dl_iterate_phdr(__libcrunch_add_all_mappings_cb, NULL);

		/* Now fill in the rest from /proc. */
		prefix_tree_add_missing_maps();
		initialized_maps = 1;
	}
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
						// be sloppy, because anonymous mappings can grow without our knowledge
						prefix_tree_add_sloppy(obj, second - first, HEAP, NULL);
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
						{	// be sloppy because the heap grows
							prefix_tree_add_sloppy(obj, second - first, HEAP, NULL);
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
		const void *next_lower, *lowest_bound = NULL, *upper = ptr, *cur = ptr;
		struct prefix_tree_node *n;
		unsigned nmappings = 0;
		do
		{
			n = prefix_tree_bounds(cur, &next_lower, &upper);
			cur = n ? upper : cur;
			if (n && n->info.what == DATA_PTR) ++nmappings;
			if (n && !lowest_bound) lowest_bound = next_lower;
		} while (n && n->info.what == DATA_PTR);
		
		// do the lower/upper we extracted match the allocation?
		if ((uintptr_t) ptr <= (uintptr_t) lowest_bound + MAXIMUM_MALLOC_HEADER_OVERHEAD 
				&& (uintptr_t) upper >= (uintptr_t) lowest_bound + modified_size
					&& (uintptr_t) upper < (uintptr_t) lowest_bound + modified_size + 2 * page_size)
		{
			/* We think we've got a mmap()'d region; */
			assert(caller);
			unsigned npages = ((uintptr_t) upper - (uintptr_t) lowest_bound) >> log_page_size;

			cur = ptr;
			struct prefix_tree_node *lowest_n = prefix_tree_bounds(ptr, NULL, NULL);
			// iterate upwards, and remember the lowest base addr
			unsigned nmappings_modified = 0;
			do
			{
				n = prefix_tree_bounds(cur, &next_lower, &upper);
				cur = n ? upper : cur;
				if (n && !lowest_bound) lowest_bound = next_lower;
				if (n && n->info.what == DATA_PTR) 
				{
					n->info = (struct node_info) {
						.what = INS_AND_BITS, 
						.un = {
							ins_and_bits: { 
								.ins = (struct insert) {
									.alloc_site_flag = 0,
									.alloc_site = (uintptr_t) caller
								},
								.is_object_start = (n == lowest_n), 
								.npages = npages, 
								.obj_offset = (char*) ptr - (char*) lowest_bound
							}
						}
					};
					++nmappings_modified;
				}
				else n = NULL; // stop here
			} while (n);
			assert(nmappings_modified == nmappings);

			assert(lowest_n->info.what == INS_AND_BITS);
			return &lowest_n->info.un.ins_and_bits.ins;
		}
		else
		{
			debug_printf(3, "Warning: could not l0-index pointer %p in mapping range %p-%p (%u mappings)\n,", ptr, 
				lowest_bound, upper, nmappings);
		}
	}
	
	return NULL;
}

static unsigned unindex_l0_one_mapping(struct prefix_tree_node *n, const void *lower, const void *upper)
{
	n->info.what = 0;
	return (char*) upper - (char*) lower;
}

unsigned __unindex_l0(const void *mem)
{
	const void *lower;
	const void *upper;
	struct prefix_tree_node *n = prefix_tree_bounds(mem, &lower, &upper);
	unsigned lower_to_upper_npages = ((uintptr_t) upper - (uintptr_t) lower) >> log_page_size;
	assert(n);

	/* We want to unindex the same number of pages we indexed. */
	unsigned npages_to_unindex = n->info.un.ins_and_bits.npages;
	unsigned total_size_to_unindex = npages_to_unindex << log_page_size;

	unsigned total_size_unindexed = lower_to_upper_npages << log_page_size;
	do
	{
		total_size_unindexed += unindex_l0_one_mapping(n, lower, upper);
		if (total_size_unindexed < total_size_to_unindex)
		{
			// advance to the next mapping
			n = prefix_tree_bounds(upper, &lower, &upper);
		}
	} while (total_size_unindexed < total_size_to_unindex);
	
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
		
		*out_object_start = (char*) lower + n->info.un.ins_and_bits.obj_offset;
		return &n->info.un.ins_and_bits.ins;
	}
	else return NULL;
}
