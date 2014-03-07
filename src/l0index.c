#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <string.h>
#include "libcrunch_private.h"

unsigned char *l0index __attribute__((visibility("protected")));

#define MAPPING_IN_USE(m) ((m)->begin && (m)->end)
struct mapping
{
	void *begin;
	void *end;
	struct prefix_tree_node n;
};
#define NMAPPINGS 256
struct mapping mappings[NMAPPINGS]; // NOTE: we *don't* use mappings[0]; the 0 byte means "empty"

#define PAGE_SIZE 4096
#define LOG_PAGE_SIZE 12

static void (__attribute__((constructor)) init)(void)
{
	/* Mmap our region. We map one byte for every page. */
	assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE);
	l0index = MEMTABLE_NEW_WITH_TYPE(unsigned char, PAGE_SIZE, (void*) 0, (void*)(1ul<<ADDR_BITSIZE));
	assert(l0index != MAP_FAILED);
}

static uintptr_t pagenum(const void *p)
{
	return ((uintptr_t) p) >> LOG_PAGE_SIZE;
}

static const void *addr_of_pagenum(uintptr_t pagenum)
{
	return (const void *) (pagenum << LOG_PAGE_SIZE);
}

_Bool insert_equal(struct insert *p_ins1, struct insert *p_ins2)
{
	return p_ins1->alloc_site_flag == p_ins2->alloc_site_flag &&
		p_ins1->alloc_site == p_ins2->alloc_site;
		// don't compare prev/next, at least not for now
}
_Bool node_info_equal(struct node_info *p_info1, struct node_info *p_info2)
{
	return p_info1->what == p_info2->what && 
	(p_info1->what == DATA_PTR ? p_info1->un.data_ptr == p_info2->un.data_ptr
	            : (assert(p_info1->what == INS_AND_BITS), 
					(insert_equal(&p_info1->un.ins_and_bits.ins, &p_info2->un.ins_and_bits.ins)
						&& p_info1->un.ins_and_bits.npages == p_info2->un.ins_and_bits.npages
						&& p_info1->un.ins_and_bits.obj_offset == p_info2->un.ins_and_bits.obj_offset)
					)
	);
}

static struct mapping *find_free_mapping(void)
{
	for (struct mapping *p = &mappings[1]; p < &mappings[NMAPPINGS]; ++p)
	{
		if (!MAPPING_IN_USE(p))
		{
			return p;
		}
	}
	return NULL;
}

static _Bool
is_unindexed(void *begin, void *end)
{
	unsigned char *pos = &l0index[pagenum(begin)];
	while (pos < l0index + pagenum(end) && !*pos) { ++pos; }
	
	if (pos == l0index + pagenum(end)) return 1;
	
	debug_printf(3, "Found already-indexed position %p (mapping %d)\n", 
			addr_of_pagenum(pos - l0index), *pos);
	return 0;
}

static
struct mapping *create_or_extend_mapping(void *base, size_t s, unsigned kind, struct node_info *p_info)
{
	assert((uintptr_t) base % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	assert(s % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	
	assert(is_unindexed(base, (char*) base + s));
	
	// test for nearby mappings to extend
	unsigned char abuts_existing_start = l0index[pagenum((char*) base + s)];
	unsigned char abuts_existing_end = l0index[pagenum((char*) base - 1)];

	_Bool can_coalesce_after = abuts_existing_start
				&& kind != HEAP
				&& mappings[abuts_existing_start].n.kind == kind
				&& node_info_equal(&mappings[abuts_existing_start].n.info, p_info);
	_Bool can_coalesce_before = abuts_existing_end
				&& kind != HEAP
				&& mappings[abuts_existing_end].n.kind == kind
				&& node_info_equal(&mappings[abuts_existing_end].n.info, p_info);
	
	/* If we *both* abut a start and an end, we're coalescing 
	 * three mappings. If so, just bump up our base and s, 
	 * free the spare mapping and coalesce before. */
	if (__builtin_expect(can_coalesce_before && can_coalesce_after, 0))
	{
		s += (char*) mappings[abuts_existing_start].end - (char*) mappings[abuts_existing_start].begin;
		mappings[abuts_existing_start].begin = 
			mappings[abuts_existing_start].begin =
				NULL;
		can_coalesce_after = 0;
	}
	
	if (can_coalesce_before)
	{
		mappings[abuts_existing_end].end = (char*) base + s;
		return &mappings[abuts_existing_end];
	}
	if (can_coalesce_after)
	{
		mappings[abuts_existing_start].begin = (char*) base;
		return &mappings[abuts_existing_start];
	}
	
	// else create new
	struct mapping *found = find_free_mapping();
	if (found)
	{
		found->begin = base;
		found->end = (char*) base + s;
		found->n.kind = kind;
		found->n.info = *p_info;
		return found;
	}
	
	return NULL;
}

struct prefix_tree_node *prefix_tree_add(void *base, size_t s, unsigned kind, const void *data_ptr)
{
	if (!l0index) init();
	
	struct node_info info = { .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	return prefix_tree_add_full(base, s, kind, &info);
}

void prefix_tree_add_sloppy(void *base, size_t s, unsigned kind, const void *data_ptr)
{
	if (!l0index) init();

	/* What's the biggest mapping you can think of? 
	 * 
	 * We don't want to index our memtables. I'm going to be conservative
	 * and avoid indexing anything above 4GB. */
	if (s >= (1ul<<32))
	{
		debug_printf(3, "Warning: not indexing huge mapping (size %lu) at %p\n", (unsigned long) s, base);
		return;
	}
	
	struct node_info info = { .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	
	/* Just add the as-yet-unmapped bits of the range. */
	uintptr_t begin_pagenum = pagenum(base);
	uintptr_t current_pagenum = begin_pagenum;
	uintptr_t end_pagenum = pagenum((char*) base + s);
	while (current_pagenum != end_pagenum)
	{
		uintptr_t next_indexed_pagenum = current_pagenum;
		while (!l0index[next_indexed_pagenum] && next_indexed_pagenum < end_pagenum) { next_indexed_pagenum++;}
		
		if (next_indexed_pagenum > current_pagenum)
		{
			prefix_tree_add_full((void*) addr_of_pagenum(current_pagenum), 
				(char*) addr_of_pagenum(next_indexed_pagenum) - (char*) addr_of_pagenum(current_pagenum), 
				kind, &info);
		}
		
		current_pagenum = next_indexed_pagenum;
		while (l0index[current_pagenum] && current_pagenum < end_pagenum) { current_pagenum++; }
	}
}

struct prefix_tree_node *prefix_tree_add_full(void *base, size_t s, unsigned kind, struct node_info *p_arg)
{
	if (!l0index) init();

	/* What's the biggest mapping you can think of? 
	 * 
	 * We don't want to index our memtables. I'm going to be conservative
	 * and avoid indexing anything above 4GB. */
	if (s >= (1ul<<32))
	{
		debug_printf(3, "Warning: not indexing huge mapping (size %lu) at %p\n", (unsigned long) s, base);
		return NULL;
	}
	
	uintptr_t first_page_num = (uintptr_t) base >> LOG_PAGE_SIZE;
	uintptr_t npages = s >> LOG_PAGE_SIZE;

	struct mapping *m = create_or_extend_mapping(base, s, kind, p_arg);
	memset(l0index + first_page_num, (unsigned char) (m - &mappings[0]), npages);
	return &m->n;
}

void prefix_tree_del(void *base, size_t s)
{
	if (!l0index) init();
	
	// if we get mapping num 0, try again after forcing init_prefix_tree_from_maps()
	unsigned char first_mapping_num;
	do
	{
		/* We might span multiple mappings, because munmap() is like that. */
		first_mapping_num = l0index[pagenum(base)];
	}
	while (first_mapping_num == 0 && (!initialized_maps ? (init_prefix_tree_from_maps(), 1) : 0));
	
	assert(first_mapping_num != 0);
	
	unsigned char last_mapping_num = l0index[pagenum((char*)base + (s-1))];
	void *this_mapping_addr = mappings[first_mapping_num].begin;
	size_t this_mapping_size = (char*) mappings[first_mapping_num].end
			 - (char*) this_mapping_addr;
	do
	{
		
		/* Do we need to chop an entry? */
		_Bool remaining_before = mappings[first_mapping_num].begin < base;
		_Bool remaining_after = (char*) mappings[first_mapping_num].end > (char*) base + this_mapping_size;

		/* If we're chopping before and after, we need to grab a *new* 
		 * mapping number. */
		if (__builtin_expect(remaining_before && remaining_after, 0))
		{
			// make a new entry for the remaining-after part, then just chop before
			struct mapping *m = find_free_mapping();
			assert(m);
			m->begin = (char*) this_mapping_addr + this_mapping_size;
			m->end = mappings[first_mapping_num].end;
			m->n = mappings[first_mapping_num].n;

			// rewrite uses of the old mapping number in the new-mapping portion of the memtable
			unsigned char new_mapping_num = m - &mappings[0];
			unsigned long npages = ((char*) mappings[first_mapping_num].end - ((char*) this_mapping_addr + this_mapping_size)) >> LOG_PAGE_SIZE;
			memset(l0index + pagenum((char*) this_mapping_addr + this_mapping_size), new_mapping_num, npages);

			remaining_after = 0;
			mappings[first_mapping_num].end = (char*) this_mapping_addr + this_mapping_size;
		}

		if (__builtin_expect(remaining_before, 0))
		{
			memset(l0index + pagenum(mappings[first_mapping_num].end), 0, 
					((char*) this_mapping_addr - (char*) mappings[first_mapping_num].end)>>LOG_PAGE_SIZE);
			mappings[first_mapping_num].end = this_mapping_addr;
		}
		else if (__builtin_expect(remaining_after, 0))
		{
			void *new_begin = (char*) this_mapping_addr + this_mapping_size;
			memset(l0index + pagenum(mappings[first_mapping_num].begin), 0, 
					(new_begin - mappings[first_mapping_num].begin)>>LOG_PAGE_SIZE);
			mappings[first_mapping_num].begin = new_begin;
		}
		else 
		{
			// else we're just deleting the whole entry
			memset(l0index + pagenum(this_mapping_addr), 0, 
					pagenum((char*) this_mapping_addr + this_mapping_size)
					 - pagenum(this_mapping_addr));
			mappings[first_mapping_num].begin = 
				mappings[first_mapping_num].end = 
					NULL;
		}
		
		// continue the loop
		void *next_addr = (char*) this_mapping_addr + this_mapping_size;
		uintptr_t next_pagenum = pagenum(next_addr);
		first_mapping_num = l0index[next_pagenum];
		// FIXME: if it's zero
		if (__builtin_expect(first_mapping_num == 0, 0))
		{
			uintptr_t end_pagenum = pagenum((char*) base + s);
			while (!(first_mapping_num = l0index[next_pagenum++]) && next_pagenum < end_pagenum);
			debug_printf(3, "Warning: l0-unindexing a partially unmapped region %p-%p\n",
				next_addr, addr_of_pagenum(next_pagenum));
			if (first_mapping_num == 0) break;
		}
		this_mapping_addr = mappings[first_mapping_num].begin;
		this_mapping_size = (char*) mappings[first_mapping_num].end - (char*) mappings[first_mapping_num].begin;
	} while (first_mapping_num != last_mapping_num);
	
	assert(is_unindexed(base, (char*) base + s));
}

enum object_memory_kind prefix_tree_get_memory_kind(const void *obj)
{
	if (!l0index) init();
	
	unsigned char mapping_num = l0index[pagenum(obj)];
	if (mapping_num == 0) return UNKNOWN;
	else return mappings[mapping_num].n.kind;
}

void prefix_tree_print_all_to_stderr(void)
{
	if (!l0index) init();
	for (struct mapping *m = &mappings[1]; m < &mappings[NMAPPINGS]; ++m)
	{
		fprintf(stderr, "%p-%p %01d %s %s %p\n", 
				m->begin, m->end, m->n.kind, name_for_memory_kind(m->n.kind), 
				m->n.info.what == DATA_PTR ? "(data ptr) " : "(insert + bits) ", 
				m->n.info.what == DATA_PTR ? m->n.info.un.data_ptr : (void*)(uintptr_t) m->n.info.un.ins_and_bits.ins.alloc_site);
	}
}
struct prefix_tree_node *
prefix_tree_deepest_match_from_root(void *base, struct prefix_tree_node ***out_prev_ptr)
{
	if (!l0index) init();
	if (out_prev_ptr) *out_prev_ptr = NULL;
	unsigned char mapping_num = l0index[pagenum(base)];
	if (mapping_num == 0) return NULL;
	else return &mappings[mapping_num].n;
}

struct prefix_tree_node *
prefix_tree_bounds(const void *ptr, const void **out_begin, const void **out_end)
{
	if (!l0index) init();
	unsigned char mapping_num = l0index[pagenum(ptr)];
	if (mapping_num == 0) return NULL;
	else 
	{
		if (out_begin) *out_begin = mappings[mapping_num].begin;
		if (out_end) *out_end = mappings[mapping_num].end;
		return &mappings[mapping_num].n;
	}
}

