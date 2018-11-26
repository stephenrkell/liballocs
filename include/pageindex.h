#ifndef LIBALLOCS_PAGEINDEX_H_
#define LIBALLOCS_PAGEINDEX_H_
#include "vas.h"

struct entry
{
	unsigned present:1;
	unsigned removed:1;  /* whether this link is in the "removed" state in Harris's algorithm */
	unsigned distance:6; /* distance from the base of this entry's region, in 8-byte units */
} __attribute__((packed));
struct insert;
struct ptrs 
{
	struct entry next;
	struct entry prev;
} __attribute__((packed));
struct insert
{
	unsigned alloc_site_flag:1;
	unsigned long alloc_site:(ADDR_BITSIZE-1);
	union  __attribute__((packed))
	{
		struct ptrs ptrs;
		unsigned bits:16;
	} un;

} __attribute__((packed));

/* We maintain two structures:
 *
 * - a list of "big allocations";
 * - an index mapping from page numbers to
 *      the deepest big allocation that completely spans that page.
 *   (this was formerly called the "level 0 index", and only mapped to
 *    first-level allocations a.k.a. memory mappings).
 * 
 * Note that a suballocated chunk may still be small enough that it
 * doesn't span any whole pages. It will still have a bigalloc number.
 * Indeed, one of the points of "big allocations" is to centralise the
 * complex business of allocation nesting. Since all nested allocations
 * are made out of a bigalloc, we can handle all that stuff here once
 * for every possible leaf allocator.
 */

/* Each big allocation has some metadata attached. The meaning of 
 * "insert" is down to the individual allocator. */
struct meta_info
{
	enum meta_info_kind { DATA_PTR, INS_AND_BITS } what;
	union
	{
		struct
		{
			void *data_ptr;
			void (*free_func)(void*);
		} opaque_data;
		struct 
		{
			struct insert ins;
			/* FIXME: document what these fields are for. I think it's when we 
			 * push malloc chunks' metadata down into the bigalloc metadata. */
			/*unsigned is_object_start:1;
			unsigned npages:20;
			unsigned obj_offset:7;*/
		} ins_and_bits;
	} un;
};

/* A "big allocation" is one that 
 * is suballocated from, or
 * spans at least BIG_ALLOC_THRESHOLD bytes of page-aligned memory. */
#define BIG_ALLOC_THRESHOLD (16*PAGE_SIZE)

struct allocator;
struct big_allocation
{
	void *begin;
	void *end;
	struct big_allocation *parent;
	struct big_allocation *next_sib;
	struct big_allocation *prev_sib;
	struct big_allocation *first_child;
	struct allocator *allocated_by; // should always be parent->suballocator
	struct allocator *suballocator; // ... suballocated bigallocs may have only small children
	struct meta_info meta;          // metadata for use by the `allocated_by' allocator
	void *suballocator_meta;        // metadata for use by the suballocator, if any
	void (*suballocator_free_func)(void*);
};
#define BIGALLOC_IN_USE(b) ((b)->begin && (b)->end)
#define NBIGALLOCS 1024
extern struct big_allocation big_allocations[];

typedef uint16_t bigalloc_num_t;

extern bigalloc_num_t *pageindex __attribute__((weak,visibility("protected")));

enum object_memory_kind __liballocs_get_memory_kind(const void *obj) __attribute__((visibility("protected")));

void __liballocs_print_l0_to_stream_err(void) __attribute__((visibility("protected")));
void __liballocs_report_wild_address(const void *ptr) __attribute__((visibility("protected")));

struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size, struct meta_info meta, struct big_allocation *maybe_parent, struct allocator *a) __attribute__((visibility("hidden")));

_Bool __liballocs_delete_bigalloc_at(const void *begin, struct allocator *a) __attribute__((visibility("hidden")));
_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end);
_Bool __liballocs_pre_extend_bigalloc(struct big_allocation *b, const void *new_begin) __attribute__((visibility("protected")));
_Bool __liballocs_pre_extend_bigalloc_recursive(struct big_allocation *b, const void *new_begin) __attribute__((visibility("protected")));
_Bool __liballocs_truncate_bigalloc_at_end(struct big_allocation *b, const void *new_end);
_Bool __liballocs_truncate_bigalloc_at_beginning(struct big_allocation *b, const void *new_begin);
struct big_allocation *__liballocs_split_bigalloc_at_page_boundary(struct big_allocation *b, const void *split_addr);
struct big_allocation * __liballocs_find_common_parent_bigalloc(const void *ptr, const void *end);
_Bool __liballocs_delete_all_bigallocs_overlapping_range(const void *begin, const void *end) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_bigalloc(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));
struct insert *__lookup_bigalloc_with_insert(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_bigalloc_top_level(const void *mem) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_deepest_bigalloc(const void *mem) __attribute__((visibility("hidden")));
struct allocator *__liballocs_get_allocator_upper_bound(const void *obj) __attribute__((visibility("protected")));
struct allocator *__liballocs_ool_get_allocator(const void *obj) __attribute__((visibility("protected")));
_Bool __pages_unused(void *begin, void *end) __attribute__((visibility("hidden")));
_Bool __liballocs_notify_unindexed_address(const void *);

/* mappings of 4GB or more in size are assumed to be memtables and are ignored */
#define BIGGEST_BIGALLOC BIGGEST_SANE_USER_ALLOC

/* Convenience for code that does raw mmap. */
#define MMAP_RETURN_IS_ERROR(p) \
	(((intptr_t)(void*)-1 - (intptr_t)(p)) < PAGE_SIZE)

/* FIXME: tweak this logic so that important liballocs workloads
 * (e.g. libcrunch benchmarks) go fast. We can be relatively precise, 
 * by calling into the pageindex, or we can be crude,
 * using the stack-pointer and sbrk heuristics. Opt initially 
 * to be precise. */
inline struct big_allocation *__liballocs_get_bigalloc_containing(const void *obj)
{
	// if (__builtin_expect(obj == 0, 0)) return NULL;
	// if (__builtin_expect(obj == (void*) -1, 0)) return NULL;
	/* More heuristics go here. */
	bigalloc_num_t bigalloc_num = pageindex[PAGENUM(obj)];
	if (bigalloc_num == 0) return NULL;
	struct big_allocation *b = &big_allocations[bigalloc_num];
	return b;
}

inline
struct allocator *__liballocs_leaf_allocator_for(const void *obj,
	struct big_allocation **out_containing_bigalloc,
	struct big_allocation **out_maybe_the_allocation)
{
	struct big_allocation *deepest = NULL;
	for (struct big_allocation *cur = __liballocs_get_bigalloc_containing(obj);
			__builtin_expect(cur != NULL, 1);
			)
	{
		deepest = cur;

		/* Increment: does one of the children overlap? */
		for (struct big_allocation *child = cur->first_child;
				__builtin_expect(child != NULL, 0);
				child = child->next_sib)
		{
			if ((char*) child->begin <= (char*) obj && 
					(char*) child->end > (char*) obj)
			{
				cur = child;
			}
		}
		
		if (cur == deepest) cur = NULL;
	}
	/* Now cur is null, and deepest is the deepest overlapping.
	 * If the deepest is not suballocated, then it's definitely
	 * the leaf. If it is suballocated, then *either* the suballocator
	 * *or* the bigalloc allocator might be responsible for the
	 * memory under ptr. We assume that it's the suballocator.
	 * 
	 * ... but that's wrong. All we know is that if a deeper
	 * allocation exists, it's not big, and it's exactly one level
	 * down (there's no nesting in non-big allocations). 
	 * FIMXE: we should really *try* the suballocator and then,
	 * if ptr actually falls between the cracks, return the 
	 * bigalloc's allocator. But that makes things slower than
	 * we want. So we should add a slower call for this. */
	
	if (__builtin_expect(!deepest, 0)) return NULL;
	else if (__builtin_expect(deepest->suballocator != NULL, 1))
	{
		/* The allocator is the suballocator, and the containing bigalloc
		 * is deepest. */
		if (out_containing_bigalloc) *out_containing_bigalloc = deepest;
		if (out_maybe_the_allocation) *out_maybe_the_allocation = NULL;
		return deepest->suballocator;
	}
	else
	{
		if (out_containing_bigalloc) *out_containing_bigalloc = deepest->parent;
		if (out_maybe_the_allocation) *out_maybe_the_allocation = deepest;
		return deepest->allocated_by;
	}
}

#endif
