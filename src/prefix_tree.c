#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "libcrunch_private.h"

struct prefix_tree_node {
	struct prefix_tree_node *next/*, prev*/;
	unsigned long bits:48;
	unsigned nbits:6; 
	unsigned kind:2; // UNKNOWN, STACK, HEAP, STATIC
	//union // GNU extension
	//{
		struct prefix_tree_node *first_child;  // or stack block ptr, or mapping name ptr
		void *data_ptr;
	//};
};
struct prefix_tree_node *__libcrunch_prefix_tree_head;

void prefix_tree_add(void *base, size_t s, const char *filename);
void prefix_tree_add_prefix(uintptr_t base, int nbits, const char *filename);
void prefix_tree_del(void *base, size_t s);
void init_prefix_tree_from_maps(void);
void prefix_tree_check_against_maps(void);

// HACK for debugging startup -- call from functions, not during constructor.
void __libcrunch_preload_init(void);

#define BOTTOM_N_BITS_SET(n)  ( ( (n)==0 ) ? 0 : ((n) == 8*sizeof(uintptr_t) ) ? (~((uintptr_t)0)) : ((((uintptr_t)1u) << ((n))) - 1))
#define BOTTOM_N_BITS_CLEAR(n) (~(BOTTOM_N_BITS_SET((n))))

#define TOP_N_BITS_SET(n)      (BOTTOM_N_BITS_CLEAR(8*(sizeof(uintptr_t))-((n))))
#define TOP_N_BITS_CLEAR(n)    (BOTTOM_N_BITS_SET(8*(sizeof(uintptr_t))-((n))))

#define NODE_MATCHES(pn, addr)  \
  (~((uintptr_t) ((pn))->bits ^ (uintptr_t) ((addr))) >= TOP_N_BITS_SET(((pn))->nbits))

struct prefix_tree_node *
prefix_tree_deepest_matching(void *base, struct prefix_tree_node *start, 
	struct prefix_tree_node **prev_ptr, struct prefix_tree_node ***out_prev_ptr)
{
	// if we don't have our bits in common with base, there's a problem
	assert(!start || NODE_MATCHES(start, base));
	
	// if we have a non-head start and its prevptr is the head's address, the caller is confused
	assert(!start || start == __libcrunch_prefix_tree_head || prev_ptr != &__libcrunch_prefix_tree_head);

	// descend if any of the children (i.e. siblings under start) have their bits in common...
	struct prefix_tree_node **first_child_prevptr = start ? &start->first_child : &__libcrunch_prefix_tree_head;
	struct prefix_tree_node *first_child = *first_child_prevptr;
	for (struct prefix_tree_node *child = first_child, *prev_child = NULL;
		child != NULL;
		prev_child = child, child = child->next)
	{
		if (NODE_MATCHES(child, base))
		{
			// recurse
			return prefix_tree_deepest_matching(base, child, 
				(child == first_child)
					? first_child_prevptr
					: (assert(prev_child), &prev_child->next),
				out_prev_ptr);
		}
	}
	
	// if we got here, we're the best match
	if (out_prev_ptr) *out_prev_ptr = (start == NULL ? &__libcrunch_prefix_tree_head : (assert(prev_ptr), prev_ptr));
	return start;
}

// stolen from hacker's delight, then updated for 64 bits
static int nlz1(unsigned long x) {
	int n;

	if (x == 0) return 64;
	n = 0;

	if (x <= 0x00000000FFFFFFFFL) { n += 32; x <<= 32; }
	if (x <= 0x0000FFFFFFFFFFFFL) { n += 16; x <<= 16; }
	if (x <= 0x00FFFFFFFFFFFFFFL) { n += 8;  x <<= 8; }
	if (x <= 0x0FFFFFFFFFFFFFFFL) { n += 4;  x <<= 4; }
	if (x <= 0x3FFFFFFFFFFFFFFFL) { n += 2;  x <<= 2; }
	if (x <= 0x7FFFFFFFFFFFFFFFL) { n += 1;  x <<= 1; }
	
	return n;
}

static inline uintptr_t highest_dividing_power(uintptr_t v)
{
	/* The highest power of two that exactly divides v. 
	 * This corresponds to the lowest bit set. */
	assert(v != 0);
	uintptr_t power = 0;
	while (!(v & 0x1u)) { ++power; v >>= 1u; }
	return power;
}
static inline uintptr_t align_of(uintptr_t v)
{
	return 1ul << highest_dividing_power(v);
}
static inline uintptr_t highest_power_le(uintptr_t v)
{
	/* The highest power of two that is less than or equal to v.
	 * i.e. the top bit set. Obviously v can't be zero. */
	assert(v != 0);
	int nlz = nlz1(v);
	int msb = sizeof (uintptr_t) * 8 - 1 - nlz;
	assert(msb >= 0);
	return msb;
}
static inline uintptr_t biggest_power_of_two_in(uintptr_t v)
{
	return 1ul<<highest_power_le(v);
}

static void sibling_check(struct prefix_tree_node *parent, struct prefix_tree_node *new_child);

void prefix_tree_add(void *base, size_t s, const char *filename)
{
	/* Split [base, base+length) into a minimal set of 
	 * disjoint, contiguous, power-of-two-sized chunks. 
	 
	 * Do this recursively: 
	 * Take the min(align-of(base), biggest-power-of-two-le(s)),
	 * then recurse on whatever's left.
	 */

	if (s == 0) return;

	int align_of_base_power = highest_dividing_power((uintptr_t) base);
	int biggest_power_le_size = highest_power_le(s);
	int min_power = (biggest_power_le_size < align_of_base_power) ? biggest_power_le_size : align_of_base_power;
	size_t subrange_size = 1ul<<min_power;
	
	prefix_tree_add_prefix((uintptr_t) base, 8 * sizeof (uintptr_t) - min_power, filename);
	
	size_t next_size = s - subrange_size;
	prefix_tree_add((unsigned char *) base + subrange_size, next_size, filename);
}

void prefix_tree_add_prefix(uintptr_t base, int nbits, const char *filename)
{
	/* Find the node with the longest prefix in common with `base`. 
	 * Get a pointer to its *prevptr*. */
	struct prefix_tree_node **parent_prevptr = NULL;
	struct prefix_tree_node *parent 
	= prefix_tree_deepest_matching((void*) base, NULL, NULL, &parent_prevptr);

	struct prefix_tree_node **new_leaf_prevptr = NULL;
	
	/* Now we have `parent`, which is the deepest matching node (perhaps null), 
	 * and `parent_prevptr` which is *either* a next ptr or a first_child ptr
	 * (where the root ptr is a first_child ptr) 
	 * pointing at parent-or-null. 
	 * 
	 * What we want to do now is walk all children of parent-or-null. 
	 * By definition, none of the children is a better patch than `parent`. 
	 * But it might be that one or more children has a prefix which we can *split*
	 * to create a branch node that is a better match.
	 * e.g. if we have match + 001, and children exist with 
	 *                         000, 
	 *                         110     THEN
	 *        we split the first child because it begins with two zeroes.
	 * 
	 * We should only ever find one child to split, by construction. If we find
	 * more than one, it means a previous splitting should have happened bit didn't.
	 */
	
	/* Do we have any bits in common with a sibling (beyond what we have with the parent)? 
	 * If so, make a new branch node and move us+them under it. */
	assert(parent_prevptr);

	struct prefix_tree_node *sib_to_pull_down = NULL;
	struct prefix_tree_node **sib_to_pull_down_prevptr = NULL;
	uintptr_t sib_to_pull_down_bits_in_common = 0ul;

	// walk the sequence of children
	struct prefix_tree_node **sib_prevptr = parent ? &parent->first_child : &__libcrunch_prefix_tree_head;
	unsigned sibling_sequence_length = 0;
	for (struct prefix_tree_node *sib = *sib_prevptr; 
		sib != NULL;
		sib_prevptr = &sib->next, sib = sib->next, ++sibling_sequence_length)
	{
		/* For a child to be a candidate for splitting, it needs to have 
		 * some bits in common with `bits` *beyond* what we have in common with the parent;
		 * moreover, these should be *high-order* bits when we strip off the parent prefix. */
		uintptr_t all_bits_in_common = ~ (base ^ sib->bits);
		int parent_prefix_nbits = parent ? parent->nbits : 0;
		uintptr_t parent_prefix_bits = TOP_N_BITS_SET(parent_prefix_nbits);
		uintptr_t parent_bits_in_common = all_bits_in_common & parent_prefix_bits;
		if (parent_bits_in_common == parent_prefix_bits)
		{
			uintptr_t extra_bits_in_common = all_bits_in_common & ~parent_prefix_bits;
			uintptr_t extra_bits_shifted_to_high_order = extra_bits_in_common << parent_prefix_nbits;
			int nleading_high_order_bits = nlz1(~extra_bits_shifted_to_high_order);

			if (nleading_high_order_bits >= 1)
			{
				// this child is a candidate for splitting...
				// first assert that no *other* child is a candidate.
				assert(sib_to_pull_down == NULL);

				sib_to_pull_down = sib;
				sib_to_pull_down_prevptr = sib_prevptr;
				sib_to_pull_down_bits_in_common = parent_prefix_bits | 
					(BOTTOM_N_BITS_SET(nleading_high_order_bits)
					<< (8 * sizeof (uintptr_t) - parent_prefix_nbits - nleading_high_order_bits));

				// unless NDEBUG, keep going round loop, to exercise the assertion we just made
	#ifdef NDEBUG
				break;
	#endif
			}
		}
	}
	struct prefix_tree_node *new_leaf_parent = (struct prefix_tree_node *) 0xf0f0f0f0f0f0f0f0; // suspicious value
	/* Do the split if necessary. The new node will be a non-leaf node 
	 * one of whose children is the existing node (leaf or non-leaf) 
	 * and another of whose children is the new leaf node. */
	if (sib_to_pull_down)
	{
		struct prefix_tree_node *new_branch_node = calloc(1, sizeof (struct prefix_tree_node));
		new_branch_node->first_child = sib_to_pull_down;
		new_branch_node->kind = UNKNOWN; // branch nodes use unknown
		
		/* How do we calculate the bits in common from the mask?
		 * Start with 1 + the parent's bits, and iterate.  */
		uintptr_t parent_nbits = (parent ? parent->nbits : 0);
		new_branch_node->nbits = parent_nbits + 1;
		while (TOP_N_BITS_SET(new_branch_node->nbits) != sib_to_pull_down_bits_in_common) 
		{ ++(new_branch_node->nbits); }
		new_branch_node->bits = sib_to_pull_down->bits & TOP_N_BITS_SET(new_branch_node->nbits);

		// the branch node replaces the sibling in the list
		new_branch_node->next = sib_to_pull_down->next;
		*sib_to_pull_down_prevptr = new_branch_node;
		
		// we will add the new leaf node as a sibling of what we pulled down
		new_leaf_parent = new_branch_node;
		new_leaf_prevptr = &sib_to_pull_down->next;
		sib_to_pull_down->next = NULL; // it's a singleton for the moment, til we add the new leaf

		// this is an invariant-breaking tree because we have a singleton child,
		// but we can still check the new branch node for sanity
		sibling_check(parent, new_branch_node);
	}
	else
	{
		/* We didn't find a sibling to pull down. This should mean that the 
		 * sibling sequence we searched was empty. */
		assert(sibling_sequence_length == 0);
		
		/* Our deepest matching node has no children. 
		 * has no siblings ve any bits in common. 
		 * Can this happen? 
		 * Yes, but it means that said node has no children. 
		 * Note that we want *any* bits in common. For a properly-structured
		 * tree, this will happen assuming we have >1 child, because the top 
		 * post-prefix bit can only be 0 or 1, and we should have both of 
		 * these. And we shouldn't have only one child *except* at the root. 
		 * 
		 * So this only happens when we have zero children, i.e. 
		 * parent_prevptr points at a null pointer (zero-length sibling sequence),
		 * or at the root. */
		assert(!*parent_prevptr || parent_prevptr == &__libcrunch_prefix_tree_head
			|| !parent->first_child);
		
		/* HMM. So we want to add a child of our deepest matching node. */

		new_leaf_prevptr = &__libcrunch_prefix_tree_head;
		new_leaf_parent = NULL;
	}

	struct prefix_tree_node *new_leaf_node = calloc(1, sizeof (struct prefix_tree_node));
	new_leaf_node->next = *new_leaf_prevptr;
	new_leaf_node->bits = base;
	new_leaf_node->nbits = nbits;
	new_leaf_node->first_child = NULL; // new one is a leaf
	new_leaf_node->kind = STATIC; // FIXME: also add heap and stack mappings
	new_leaf_node->data_ptr = strdup(filename);
	*new_leaf_prevptr = new_leaf_node;
	
	/* Assert that the new leaf node does not share any bits with any of its siblings, 
	 * beyond what it shares with its parent. */
#ifndef NDEBUG
	sibling_check(new_leaf_parent, new_leaf_node);
#endif
	
}

static void sibling_check(struct prefix_tree_node *parent, struct prefix_tree_node *new_child)
{
	/* Assert that we don't share any prefix bits with any other sibling
	 * of our former parent, beyond what we share with the parent. If we do, it means that 
	 * we chose the wrong sibling to pull down. */
	_Bool saw_ourselves = 0;
	for (struct prefix_tree_node *sib = parent ? parent->first_child : NULL;
		sib != NULL;
		sib = sib->next)
	{
		if (sib == new_child) { saw_ourselves = 1; continue; }
		
		uintptr_t new_child_extra_prefix_bits = ((uintptr_t) new_child->bits) << (parent ? parent->nbits : 0);
		uintptr_t sib_extra_prefix_bits = ((uintptr_t) sib->bits) << (parent ? parent->nbits : 0);
		uintptr_t in_common = ~(new_child_extra_prefix_bits ^ sib_extra_prefix_bits);
		int nlz = nlz1(in_common);
		assert(nlz > 0);
	}
	assert(!parent || saw_ourselves);
}

void prefix_tree_del(void *base, size_t s)
{
	// we don't want zero-length mappings
	assert(s != 0);
	
	// we should have a tree already
	assert(__libcrunch_prefix_tree_head);

	/* Find the node with the longest prefix in common with `base`. */
	struct prefix_tree_node **prev_ptr = NULL;
	struct prefix_tree_node *matching 
	= prefix_tree_deepest_matching(base, NULL, NULL, &prev_ptr);
	
	assert(matching);
	assert(matching->bits == (uintptr_t) base);
	assert(prev_ptr != NULL);
	
	*prev_ptr = matching->next;
	free(matching->data_ptr);
	free(matching);
	
	// if we now have a parent with only one child, coalesce -- FIXME
	
}

void init_prefix_tree_from_maps(void)
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
		int fields_read = sscanf(linebuf, 
			"%lx-%lx %c%c%c%c %8x %2x:%2x %d %s\n",
			&first, &second, &r, &w, &x, &p, &offset, &devmaj, &devmin, &inode, rest);

		assert(fields_read >= (NUM_FIELDS-1)); // we might not get a "rest"
		
		// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
		if (fields_read == NUM_FIELDS && rest[0] != '[' && second - first > 0)
		{
			prefix_tree_add((void *)(uintptr_t)first, second - first, rest);
		}
	}
	if (linebuf) free(linebuf);
	
	fclose(maps);
}
