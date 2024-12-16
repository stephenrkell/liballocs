#ifndef LIBALLOCS_PAGEINDEX_H_
#define LIBALLOCS_PAGEINDEX_H_
#include <assert.h>
#include "vas.h"

/* We maintain two structures:
 *
 * - an array of "big allocations";
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

struct allocator;
struct big_allocation
{
	void *begin;
	void *end;              // XXX: store 'size' instead? 32 bits max, would help hot/cold packing
	uint16_t first_child;   // idx of parent, etc. We keep these as 16-bit integers
	uint16_t next_sib;      // to stop the structure getting too large. Also we try to
	uint16_t parent;        // keep a hot/cold split: first_child and next_sib are hottest.
	uint16_t prev_sib;      // (Could take this split further if it affects perf.)
	struct allocator *allocated_by; // should always be parent->suballocator *if* parent has a suballocator -- but it needn't, because suballocation is about small stuff
	struct allocator *suballocator; // ... suballocated bigallocs may have BOTH small and big children
	void *allocator_private;        // metadata for use by the `allocated_by' allocator
	void (*allocator_private_free)(void*);
	void *suballocator_private;     // metadata for use by the suballocator, if any -- generic_small uses this to hold its chunk_rec
	void (*suballocator_private_free)(void*);
	/* Contemplating adding some common suballocator helpers -- if
	 * we fix these, we gain some potential for fast paths later.
	 * But shortcut vectors only really make sense for static
	 * allocations -- too expensive to recompute on changes.

	bitmap ptr
	"delta" to bitmap/shortcut base
	min alignment          a.k.a. granularity of bitmap
	biggest live/seen suballocation (<=)  i.e. to bound backward search for object bases
	shortcut vector ptr    -- 
	shortcut scale factor

	These feel a bit wrong. We are losing our generality by baking
	this into the big_allocation abstraction. But if we had bitmaps
	as a fast path, we could do fast pointer normalization (or at least
	a fast check for this) which might help with... libcrunch-style
	queries when we have inline caching of allocators, say (a common-case
	"normalized" heap query could be inlined into the caller).
	 */
};
#define BIGALLOC_IN_USE(b) ((b)->begin && (b)->end)
#define NBIGALLOCS 32768
#ifdef IN_LIBALLOCS_DSO
#define BIDX(idx) ((struct big_allocation *)((idx) ? &big_allocations[(idx)] : NULL))
#define IDXB(b)   ((b) ? (b) - &big_allocations[0] : 0)
#else
#define BIDX(idx) ((struct big_allocation *)((idx) ? &__liballocs_big_allocations[(idx)] : NULL))
#define IDXB(b)   ((b) ? (b) - &__liballocs_big_allocations[0] : 0)
#endif
extern struct big_allocation big_allocations[] __attribute__((weak));
extern struct big_allocation __liballocs_big_allocations[] __attribute__((weak));

void __pageindex_init(void) __attribute__((constructor(101)));
typedef uint16_t bigalloc_num_t;

// FIXME: protected stuff should be in private header only. This is now a public header.
// If I didn't want that (good arguments for a single <allocs.h>), then some refactoring to do.
extern bigalloc_num_t *pageindex __attribute__((weak));
extern bigalloc_num_t *__liballocs_pageindex __attribute__((weak));

enum object_memory_kind __liballocs_get_memory_kind(const void *obj) __attribute__((visibility("protected")));

void __liballocs_print_l0_to_stream_err(void);
void __liballocs_report_wild_address(const void *ptr); //__attribute__((visibility("protected")));

struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size,
	void *allocator_private, void (*allocator_private_free)(void*),
	struct big_allocation *maybe_parent, struct allocator *a);

_Bool __liballocs_delete_bigalloc_at(const void *begin, struct allocator *a);
_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end);
_Bool __liballocs_pre_extend_bigalloc(struct big_allocation *b, const void *new_begin);
_Bool __liballocs_pre_extend_bigalloc_recursive(struct big_allocation *b, const void *new_begin);
_Bool __liballocs_truncate_bigalloc_at_end(struct big_allocation *b, const void *new_end);
_Bool __liballocs_truncate_bigalloc_at_beginning(struct big_allocation *b, const void *new_begin);
struct big_allocation *__liballocs_split_bigalloc_at_page_boundary(struct big_allocation *b, const void *split_addr);
_Bool __liballocs_delete_all_bigallocs_overlapping_range(const void *begin, const void *end) __attribute__((visibility("hidden")));

struct big_allocation * __liballocs_find_common_parent_bigalloc(const void *ptr, const void *end);
struct big_allocation *__lookup_bigalloc_under_pageindex(const void *mem, struct allocator *a, void **out_object_start);
struct big_allocation *__lookup_bigalloc_under(const void *mem, struct allocator *a, struct big_allocation *start, void **out_object_start);
struct big_allocation *__lookup_bigalloc_under_by_suballocator(const void *mem, struct allocator *sub_a, struct big_allocation *start, void **out_object_start);
struct big_allocation *__lookup_bigalloc_from_root(const void *mem, struct allocator *a, void **out_object_start);
struct big_allocation *__lookup_bigalloc_from_root_by_suballocator(const void *mem, struct allocator *sub_a, void **out_object_start);
struct big_allocation *__lookup_bigalloc_top_level(const void *mem);
struct big_allocation *__liballocs_find_mapping_at_or_above(void *addr);
struct big_allocation *__liballocs_find_mapping_below(void *addr);
struct big_allocation *__lookup_deepest_bigalloc(const void *mem);

struct allocator *__liballocs_get_allocator_upper_bound(const void *obj) __attribute__((visibility("protected")));
struct allocator *__liballocs_ool_get_allocator(const void *obj) __attribute__((visibility("protected")));
_Bool __pages_unused(void *begin, void *end) __attribute__((visibility("hidden")));
_Bool __liballocs_notify_unindexed_address(const void *);
void __adjust_bigalloc_end(struct big_allocation *b, void *new_curbrk) __attribute__((visibility("hidden")));

/* mappings of 4GB or more in size are assumed to be memtables and are ignored */
#define BIGGEST_BIGALLOC BIGGEST_SANE_USER_ALLOC

/* Convenience for code that does raw mmap. */
#ifndef MMAP_RETURN_IS_ERROR
#define MMAP_RETURN_IS_ERROR(p) \
	(((uintptr_t)(void*)-1 - (uintptr_t)(p)) < PAGE_SIZE)
#endif

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
	bigalloc_num_t bigalloc_num = __liballocs_pageindex[PAGENUM(obj)];
	if (bigalloc_num == 0) return NULL;
	struct big_allocation *b = &__liballocs_big_allocations[bigalloc_num];
	return b;
}

/* If we know enough about the bigallocs, we can infer what the allocator
 * is. */
static inline
struct allocator *
__liballocs_infer_allocator(void *obj, struct big_allocation *maybe_the_allocation,
	struct big_allocation *containing_bigalloc)
{
	assert(containing_bigalloc);
	assert(containing_bigalloc->suballocator || maybe_the_allocation);
	struct allocator *a;
	if (maybe_the_allocation)
	{
		a = maybe_the_allocation->allocated_by;
	} else a = containing_bigalloc->suballocator;
	return a;
}

inline
struct allocator *__liballocs_leaf_allocator_for(const void *obj,
	struct big_allocation **out_bigalloc)
{
	struct big_allocation *deepest = NULL;
	for (struct big_allocation *cur = __liballocs_get_bigalloc_containing(obj);
			__builtin_expect(cur != NULL, 1);
			)
	{
		deepest = cur;

		/* Increment: does one of the children overlap? */
		for (struct big_allocation *child = BIDX(cur->first_child);
				__builtin_expect(child != NULL, 0);
				child = BIDX(child->next_sib))
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
	 * FIXME: we should really *try* the suballocator and then,
	 * if ptr actually falls between the cracks, return the 
	 * bigalloc's allocator. But that makes things slower than
	 * we want. So we should add a slower call for this.
	 *
	 * It's possible that the planned 'pageindex top bit' usage could
	 * avoid any slowdown here. If the top bit is set, it means there
	 * is nothing in the page (any part of the page, i.e. it may *begin*
	 * on a previous page) that is not common-case, i.e. not allocated by
	 * the suballocator of this bigalloc (if there is one; otherwise
	 * it means it is all part of this exact bigalloc?).
	 *
	 * How does this 'top bit' thing work in the case of, say, a
	 * malloc arena? When the arena is allocated, we set the top
	 * bits for all pages except perhaps the end ones if it's not
	 * page-aligned. We clear some of them if we, sya, promote a
	 * malloc chunk to a bigalloc; its begin and end pages might need
	 * their bits cleared. But its fully-contained pages would be
	 * fine to keep their bits. DOES THIS WORK? It means that even
	 * for an empty arena, the malloc is 'the leaf allocator' for
	 * all addresses in the range, even if there is nothing allocated
	 * at a queried address. Is that the semantics we want? Depends
	 * a bit on our callers, i.e. who wants to know about leaf allocators
	 * and why. libcrunch is one. It doesn't want to know about the arena,
	 * only about stuff in it, so 'yes it's the leaf; nothing here' would
	 * indeed be the correct response here.
	 */
	
	if (__builtin_expect(!deepest, 0)) return NULL;
	if (out_bigalloc) *out_bigalloc = deepest;
	if (__builtin_expect(deepest->suballocator != NULL, 1))
	{
		/* The allocator is the suballocator, and the containing bigalloc
		 * is deepest. */
		return deepest->suballocator;
	}
	return deepest->allocated_by;
}

#endif
