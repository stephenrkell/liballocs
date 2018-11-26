#ifndef LIBALLOCS_VEC_H_
#define LIBALLOCS_VEC_H_

#define _GNU_SOURCE
#include <stdint.h>
#include <search.h>

/* We define routines for working with the following kinds of structure:
 *
 * metadata vectors, which may be
 *     sorted or
 *     unsorted
 *   ... but are always dense arrays of fixed-length metadata records
 *
 * metadata index vector, which is
 *     used to store an address-sorted order for visiting an unsorted metadata vector
 *
 * starts bitmaps,
 *     which record the start positions of objects
 *         and are primarily used for backward search.
 *
 * cumulative index maps,
 *     which shadow memory with the number of starts occurring *prior* memory,
 *         and are used to bound the backward search in a bitmap
 *
 * (There are also *presence bitmaps* used for broad range queries on sparse
 * metadata structures in virtual memory. We don't use them here. FIXME: what
 * are the pros and cons of each? We seem to be working only with dense metadata
 * structures here. Do we still have use for a sparse structure? We seem to
 * have pushed the sparseness into the pageindex / bigallocs table, and be hanging
 * all structure densely off those entries. Can I imagine some applications of
 * a sparse thing? General shadow allocations perhaps? Still unclear whether bitmap
 * is as good as memtable.
 *
 * I initially wrote that
 * "The sparse/dense thing is a bit of a red herring; we are still using "MMU assist"
 * even if we have a dense lookup. The main idea of MMU assist is that the index
 * structure (associative structure) mirrors the domain structure (addresses).)"
 * But actually I think that only works with sparseness, except in the degenerate
 * case where the actual described objects are dense.
 *
 * Perhaps one way to write it up:
 *
 * Imagine a collection of varying-size objects in memory that is partly unused.
 * We want to attach metadata.
 * We could perhaps keep a sorted array of metadata records and use binary search.
 * Or, if the objects come and go,
 * we might use a tree map or similar, at the expense of more pointer-chasing.
 * Traditionally we would optimise to reduce pointer chasing by using a splay tree.
 *
 * Or instead, we could use an MMU-assisted linear lookup.
 * This works if our metadata is either large enough in unit size,
 *  or occurs clustered together,
 *  that it occupies page-sized chunks.
 *  This is exactly the idea of linear page tables.
 *  Any address-keyed trie (Valgrind, SoftBound) is a candidate.
 *  Also Boehm GC? Also TinySTM lock table?
 *
 * Can we encode our structure some other way, to get MMU assistance?
 * The general idea seems to be to take any associative structure
 * with a partitionable key -- i.e. something we could use a trie for --
 * and partition it so that the first-level lookup narrows to 
 * about a page's worth of stuff.
 * This is clearly assuming some properties of the payload volume per unit
 * key-space.
 * But some adaptive fudges are available:
 * perhaps we have a static guess of
 * what yields a page-sized amount, and use variants to handle the cases
 * when much more or much less than a page's owrth of stuff is under that.
 * Or perhaps we have a dynamic partition of the key space,
 * i.e. the container tells us how much to examine in our key
 * in the first (MMU-assisted) step.
 *
 * The two-dimensional "layered" approach I came up with for suballocs
 * also seems to merit inclusion here, although it was annoyingly slow
 * in the practical cases I tried. Perhaps those cases were just really
 * demanding.
 */

/* Set a bit for an object start in a bitmap. */
#define bitmap_set_start(bitmap, align_bytes, region_begin, obj_begin) \
	/* call to generic bitmap routine */

/* Given an unsorted metadata vector (like an ELF section header list say),
 * build a version sorted keyed on some key expression,
 * then build a vector mapping indices in sorted order
 * to indices in the unsorted array.
 *
 * At first I wanted to use qsort(), but that does not tell us
 * where it put each element in the sorted order.
 * This is only a correctness problem when elements compare equal,
 * which they shouldn't. But it's an efficiency problem anyway.
 * It doesn't preserve the indices of the sorted positions relative
 * to their initial positions. To maintain this information, instead
 * build a temporary tree structure that lets us
 * (1) traverse it in sorted order, to define the indices;
 * (2) look up an element by its key. */

	/* We define this just to make the code easier to understand.
	 * The tsearch man page says
	 * "The first field in each node of the tree is a pointer to the corresponding
	 * data item."  */
struct internal_treenode { void *value_addr; };
static free_node_payload(void *nodep)
{
	struct internal_treenode *p = (struct internal_treenode *) nodep;
	if (p) free(p->value_addr);
}
#define make_populate_meta_idx_vec_func(prefix, nbits_addr, nbytes_addr_offset, nbits_idx) \
struct prefix ## pair_value { void *addr; uint ## nbits_idx ## _t idx_in_unsorted_vec; } \
static uint ## nbits_addr ## _t prefix ## addrget(void* x) \
{ \
	uint ## nbits_addr ## _t val; \
	memcpy(&val, (char*)x + nbytes_offset, nbits_addr / 8); \
	return val; \
} \
static inline prefix ## addrcompare(void *x1, void *x2) \
{  \
	uint ## nbits_addr ## _t val1 = prefix ## addrget(x1); \
	uint ## nbits_addr ## _t val2 = prefix ## addrget(x2); \
	return val1 - val2; \
} \
static __thread uint ## nbits_idx ## _t *outvec_ptr; \
static inline void prefix ## add_ordinal_action(const void *nodep, \
		const VISIT which, \
		const int depth) \
{ \
	switch (which) \
	{ \
		case postorder: \
		case leaf: \
			*outvec_ptr++ = (struct pair_value *)( \
				((struct internal_treenode *) nodep)->value_addr \
			)->idx_in_unsorted_vec; \
		break; \
		case preorder: \
		case endorder: \
		default: \
		break; \
	} \
} \
static void prefix ## populate_meta_idx_vec(void *begin, void *end, unsigned stepsz, \
	uint ## nbits_idx ## _t *outvec_ptr_arg, \
	int (*filter)(void*)) \
{ \
	void *root = NULL; \
	prefix ## outvec_ptr = outvec_ptr_arg; \
	for (int i = 0; i < ((char*)end - (char*)begin) / stepsz; ++i) \
	{ \
		void *addr = prefix ## addrget((char*) begin + i * stepsz); \
		struct internal_treenode *added \
		 = tsearch(addr, &root, addrcompare); \
		added->value_addr = malloc(sizeof (struct prefix ## pair_value)); \
		if (!added->value_addr) __assert_fail(#prefix ": malloc succeeded", __FILE__, __LINE__, __func__); \
		*(struct pair_value*) added->value_addr = (struct prefix ## pair_value) { \
			.addr = addr, \
			idx_in_unsorted_vec = i \
		}; \
	} \
	/* Now walk the tree in order and fill in the ordinals. */ \
	twalk(root, prefix ## add_ordinal_action); \
	/* Now destroy the tree */ \
	tdestroy(root, free_node_payload); \
}

#endif
