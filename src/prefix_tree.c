#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "liballocs_private.h"

struct prefix_tree_node {
	struct prefix_tree_node *next/*, prev*/;
	unsigned long bits:48;
	unsigned nbits:6; 
	unsigned kind:2; // UNKNOWN, STACK, HEAP, STATIC
	//union // GNU extension
	//{
		struct prefix_tree_node *first_child;  // or stack block ptr, or mapping name ptr
		const void *data_ptr;
	//};
};
struct prefix_tree_node *__liballocs_prefix_tree_head;

struct prefix_tree_add_args
{
	unsigned kind;
	const void *data_ptr;
};

void prefix_tree_add(void *base, size_t s, unsigned kind, const void *data_ptr);

static
void prefix_tree_add_prefix(uintptr_t base, int nbits, const struct prefix_tree_add_args *data_ptr);

void prefix_tree_del(void *base, size_t s);
static void 
prefix_tree_del_prefix(uintptr_t addr, int sz, const void* arg);

void init_prefix_tree_from_maps(void);
void prefix_tree_check_against_maps(void);

// HACK for debugging startup -- call from functions, not during constructor.
void __liballocs_preload_init(void);

#define BOTTOM_N_BITS_SET(n)  ( ( (n)==0 ) ? 0 : ((n) == 8*sizeof(uintptr_t) ) ? (~((uintptr_t)0)) : ((((uintptr_t)1u) << ((n))) - 1))
#define BOTTOM_N_BITS_CLEAR(n) (~(BOTTOM_N_BITS_SET((n))))

#define TOP_N_BITS_SET(n)      (BOTTOM_N_BITS_CLEAR(8*(sizeof(uintptr_t))-((n))))
#define TOP_N_BITS_CLEAR(n)    (BOTTOM_N_BITS_SET(8*(sizeof(uintptr_t))-((n))))

#define NODE_MATCHES(pn, addr)  \
  (~((uintptr_t) ((pn))->bits ^ (uintptr_t) ((addr))) >= TOP_N_BITS_SET(((pn))->nbits))

#define NODE_IS_LEAF(n)  ((n) && !(n)->first_child) 
// FIXME: support the union optimisation above here

struct prefix_tree_node *
prefix_tree_deepest_matching(void *base, struct prefix_tree_node *start, 
	struct prefix_tree_node **prev_ptr, struct prefix_tree_node ***out_prev_ptr)
{
	// if we don't have our bits in common with base, there's a problem
	assert(!start || NODE_MATCHES(start, base));
	
	// if we have a non-head start and its prevptr is the head's address, the caller is confused
	assert(!start || start == __liballocs_prefix_tree_head || prev_ptr != &__liballocs_prefix_tree_head);

	// descend if any of the children (i.e. siblings under start) have their bits in common...
	struct prefix_tree_node **first_child_prevptr = start ? &start->first_child : &__liballocs_prefix_tree_head;
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
	if (out_prev_ptr) *out_prev_ptr = (start == NULL ? &__liballocs_prefix_tree_head : (assert(prev_ptr), prev_ptr));
	return start;
}

struct prefix_tree_node *
prefix_tree_deepest_match_from_root(void *obj)
{	
	struct prefix_tree_node *prevptr;
	return prefix_tree_deepest_matching((void*) obj, NULL, NULL, &prevptr);
}

enum object_memory_kind
prefix_tree_get_memory_kind(const void *obj)
{
	stuct prefix_tree_node *match = prefix_tree_deepest_match_from_root(obj);
	return (NODE_IS_LEAF(match) ? match->kind : UNKNOWN);
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
// the same, but for trailing zeroes
static int ntz1(unsigned long x) {
	int n;

	if (x == 0) return 64;
	n = 0;

	if (!(x & 0x00000000FFFFFFFFL)) { n += 32; x >>= 32; }
	if (!(x & 0x000000000000FFFFL)) { n += 16; x >>= 16; }
	if (!(x & 0x00000000000000FFL)) { n += 8;  x >>= 8; }
	if (!(x & 0x000000000000000FL)) { n += 4;  x >>= 4; }
	if (!(x & 0x0000000000000003L)) { n += 2;  x >>= 2; }
	if (!(x & 0x0000000000000001L)) { n += 1;  x >>= 1; }
	
	return n;
}

static inline uintptr_t highest_dividing_power(uintptr_t v)
{
	/* The highest power of two that exactly divides v. 
	 * This corresponds to the lowest bit set. */
	assert(v != 0);
	uintptr_t power = 0;
	// while (!(v & 0x1u)) { ++power; v >>= 1u; }
	power = ntz1(v);
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

static void iterate_power_of_two_intervals(void (*callback)(uintptr_t, int, const void *),
	const void *base, size_t s, const void* arg)
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
	
	callback((uintptr_t) base, 8 * sizeof (uintptr_t) - min_power, arg);
	
	size_t next_size = s - subrange_size;
	iterate_power_of_two_intervals(callback, (unsigned char *) base + subrange_size, next_size, arg);
}

void prefix_tree_add(void *base, size_t s, unsigned kind, const void *filename)
{
	struct prefix_tree_add_args args = { kind, filename };
	iterate_power_of_two_intervals((void(*)(uintptr_t, int, const void *)) &prefix_tree_add_prefix, 
		base, s, &args);
}

void prefix_tree_add_prefix(uintptr_t base, int nbits, const struct prefix_tree_add_args *args)
{
	/* Find the node with the longest prefix in common with `base`. 
	 * Get a pointer to its *prevptr*. */
	struct prefix_tree_node **parent_prevptr = NULL;
	struct prefix_tree_node *parent 
	= prefix_tree_deepest_match_from_root((void*) base, &parent_prevptr);

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
	 * more than one, it means a previous splitting should have happened but didn't.
	 */
	
	/* Do we have any bits in common with a sibling (beyond what we have with the parent)? 
	 * If so, make a new branch node and move us+them under it. */
	assert(parent_prevptr);

	struct prefix_tree_node *sib_to_pull_down = NULL;
	struct prefix_tree_node **sib_to_pull_down_prevptr = NULL;
	uintptr_t sib_to_pull_down_bits_in_common = 0ul;

	// walk the sequence of children
	struct prefix_tree_node **sib_prevptr = parent ? &parent->first_child : &__liballocs_prefix_tree_head;
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
		assert(!*parent_prevptr || parent_prevptr == &__liballocs_prefix_tree_head
			|| !parent->first_child);
		
		/* HMM. So we want to add a child of our deepest matching node. */

		new_leaf_prevptr = &__liballocs_prefix_tree_head;
		new_leaf_parent = NULL;
	}

	struct prefix_tree_node *new_leaf_node = calloc(1, sizeof (struct prefix_tree_node));
	new_leaf_node->next = *new_leaf_prevptr;
	new_leaf_node->bits = base;
	new_leaf_node->nbits = nbits;
	new_leaf_node->first_child = NULL; // new one is a leaf
	new_leaf_node->kind = args->kind;
	new_leaf_node->data_ptr = (args->kind == STATIC) ? strdup((const char *) args->data_ptr) : args->data_ptr;
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

static void 
prefix_tree_print_to_stderr(struct prefix_tree_node *start, int indent_level);

void 
prefix_tree_print_all_to_stderr(void)
{
	prefix_tree_print_to_stderr(NULL, 0);
}

static void 
prefix_tree_print_to_stderr(struct prefix_tree_node *start, int indent_level)
{
	for (int i = 0; i < indent_level; ++i) fputc('\t', stderr);
	
	struct prefix_tree_node *first_child;
	if (!start)
	{
		// start from root
		fprintf(stderr, "{implicit root node}\n");
		first_child = __liballocs_prefix_tree_head;
	}
	else 
	{
		fprintf(stderr, "{%012lx, %012lx, %d, %s}\n", 
			(uintptr_t) start->bits, 
			(!start->nbits) ? (unsigned long) 0 : TOP_N_BITS_SET(start->nbits), 
			(int) start->kind, 
			start->kind == STATIC ? (const char*)start->data_ptr : (start->data_ptr ? "(data ptr)" : "(nil)"));
		first_child = start->first_child;
	}

	for (struct prefix_tree_node *i = first_child;
		i; i = i->next)
	{
		prefix_tree_print_to_stderr(i, indent_level + 1);
	}
	fflush(stderr);
}

static 
struct prefix_tree_node *
lift_singleton_children(struct prefix_tree_node *start, struct prefix_tree_node **prev_ptr)
{
	assert(start);
	
	/* Is our child a singleton? */
	if (start->first_child && !start->first_child->next)
	{
		/* Replace ourselves with the child. 
		 * CARE: we need to return the replacement for "start", to
		 * avoid breaking the iteration in our caller 
		 * (see recursion below). */
		start->first_child->next = start->next;
		*prev_ptr = start->first_child;
	}
	
	/* Recurse. */
	struct prefix_tree_node **i_prev = &start->first_child;
	for (struct prefix_tree_node *i_node = start->first_child; 
		i_node != NULL;
		i_prev = &i_node->next, i_node = i_node->next)
	{
		i_node = lift_singleton_children(i_node, i_prev);
		assert(i_node);
	}
	
	return *prev_ptr;
}

static void 
prefix_tree_del_prefix(uintptr_t base, int nbits, const void* arg)
{
	assert(arg == NULL);
	
	struct prefix_tree_node **prev_ptr = NULL;
	struct prefix_tree_node *matching 
	= prefix_tree_deepest_match_from_root((void *) base, &prev_ptr);
	
	assert(matching);
	assert(matching->bits == (uintptr_t) base);
	assert(matching->nbits == nbits);
	assert(prev_ptr != NULL);
	
	*prev_ptr = matching->next;
	if (matching->kind == STATIC) free((void *) matching->data_ptr);
	free(matching);
	
	// if we've left a parent with only one child, coalesce
	// -- NOTING that prev_ptr might be in the child *or* the parent,
	// and because we can't walk backwards, we can't tell if it
	// points to a singleton child sequence. HMM. So maybe the 
	// answer is to doubly-link the lists? 
	lift_singleton_children(__liballocs_prefix_tree_head, &__liballocs_prefix_tree_head); // FIXME: ideally we'd not have to scan the tree here
}

void prefix_tree_del(void *base, size_t s)
{
	// we don't want zero-length mappings
	assert(s != 0);
	
	// we should have a tree already
	assert(__liballocs_prefix_tree_head);

	/* Find *all* nodes in the interval [base, base+s).
	 * What's an efficient way to do this? 
	 * If we find the deepest matching, we might miss less-deep intervals
	 * that still cover some of the range. So iterate: 
	 * find a deep interval that matches,  */
	iterate_power_of_two_intervals((void(*)(uintptr_t, int, const void*)) &prefix_tree_del_prefix, 
		base, s, NULL);
}
