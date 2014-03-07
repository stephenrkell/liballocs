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

static
struct mapping *create_or_extend_mapping(void *base, size_t s, unsigned kind, struct node_info *p_info)
{
	assert((uintptr_t) base % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	assert(s % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	
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


void prefix_tree_add(void *base, size_t s, unsigned kind, const void *data_ptr)
{
	if (!l0index) init();
	
	struct node_info info = { .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	return prefix_tree_add_full(base, s, kind, &info);
}

void prefix_tree_add_full(void *base, size_t s, unsigned kind, struct node_info *p_arg)
{
	if (!l0index) init();

	unsigned first_page_num = (uintptr_t) base >> LOG_PAGE_SIZE;
	unsigned npages = s >> LOG_PAGE_SIZE;

	struct mapping *m = create_or_extend_mapping(base, s, kind, p_arg);
	memset(l0index + first_page_num, (unsigned char) (m - &mappings[0]), npages);
}

void prefix_tree_del(void *base, size_t s)
{
	if (!l0index) init();
	
	/* We shouldn't span multiple mappings. */
	unsigned char first_mapping_num = l0index[(unsigned char) ((uintptr_t) base >> LOG_PAGE_SIZE)];
	unsigned char last_mapping_num = l0index[(unsigned char) ((uintptr_t) (char*)base + (s-1) >> LOG_PAGE_SIZE)];
	assert(first_mapping_num == last_mapping_num);
	unsigned char mapping_num = first_mapping_num;
	assert(mapping_num != 0);
	
	/* Do we need to chop an entry? */
	_Bool remaining_before = mappings[mapping_num].begin < base;
	_Bool remaining_after = (char*) mappings[mapping_num].end > (char*) base + s;
	
	/* If we're chopping before and after, we need to grab a *new* 
	 * mapping number. */
	if (__builtin_expect(remaining_before && remaining_after, 0))
	{
		// make a new entry for the remaining-after part, then just chop before
		struct mapping *m = find_free_mapping();
		assert(m);
		m->begin = (char*) base + s;
		m->end = mappings[mapping_num].end;
		m->n = mappings[mapping_num].n;
		
		// rewrite uses of the old mapping number in the new-mapping portion of the memtable
		unsigned char new_mapping_num = m - &mappings[0];
		unsigned npages = ((char*) mappings[mapping_num].end - ((char*) base + s)) >> LOG_PAGE_SIZE;
		memset(l0index + pagenum((char*) base + s), new_mapping_num, npages);
		
		remaining_after = 0;
		mappings[mapping_num].end = (char*) base + s;
	}
	
	if (__builtin_expect(remaining_before, 0))
	{
		mappings[mapping_num].end = base;
		return;
	}
	
	if (__builtin_expect(remaining_after, 0))
	{
		mappings[mapping_num].begin = (char*) base + s;
		return;
	}
	
	// else we're just deleting the whole entry
	mappings[mapping_num].begin = 
		mappings[mapping_num].end = 
			NULL;
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

