#define _GNU_SOURCE
#include <stdio.h>
#include "liballocs.h"
#include "liballocs_private.h"

/* Ways to walk allocations:
 *
 * - each allocator may provide a walk_allocations function
 *   which walks (exactly) its allocations as contained within
 *   a given containment context (bigalloc, mostly -- see below about uniqtype).
 *      - if there are 'imposed child bigallocs', i.e. child
 *        bigallocs that are not allocated_by that allocator,
 *        it will *not* walk them. These are rare... 'stackframe
 *        within auxv' is probably the only case to date.
 * - the *top-level* walk_allocations function, below, can walk
 *   allocations in any containment context (by delegating to the
 *   appropriate allocator, but also optionally *will* walk imposed
 *   children, if given the right flag.
 * - iterating contained subobjects within a uniqtype is currently
 *   a separate case but should eventually become just another allocator.
 * Given a bigalloc, there are two kinds of allocation to walk:
 * child bigallocs, and suballocator chunks. If it's the suballocator,
 * we need to ask it to walk *its* allocations. The allocator API
 * also uses ALLOC_REFLECTIVE_API so we need the top-level API here
 * to be uniform.
 *
 * Is there an invariant that says we can't have both child allocs
 * and bigallocs? No, actually we CAN because a malloc chunk can be
 * promoted to a bigalloc if it gets suballocated-from. So we may
 * need to walk both.
 *
 * Now think ahead to a near future where we have __uniqtype_allocator.
 * Given a uniqtype, the allocations to walk are its subobjects.
 * There is no bigalloc; there is a uniqtype *and* a base address.
 * So we pass two pointers; in the bigalloc case we pass some flags.
 * Since uniqtypes are always aligned addresses, we ensure all 'flags'
 * have LSB set, and one or more flags is compulsory, so we can
 * disambiguate a bigalloc call even in this top-level function.
 */
int __liballocs_walk_allocations(
	struct alloc_tree_pos *scope,
	walk_alloc_cb_t *cb,
	void *arg,
	void *maybe_range_begin,
	void *maybe_range_end
)
{
	/* If we are asked to walk children of a bigalloc,
	 * not of a uniqtype, then
	 *
	 * - the bigalloc may have a type, in which case
	 *    - it must NOT have suballocation
	 *    - it must NOT have child allocations
	 *    - we delegate to the uniqtype walker and that's it
	 *    - FIXME: I don't think we do that right now. Unless
	 *      our bou is a uniqtype... can we represent the context
	 *      as "the whole of this bigalloc"?
	 * - the bigalloc may have suballocations *and* children
	 *    - flags determine which one(s) we walk (can be both)
	 * - the bigalloc may have only children
	 *    - we still honor the flags
	 *
	 * Given just an alloc_tree_path, where do we get
	 * our flags from? We can include flags in the uniqtype
	 * as it is always 8-byte-aligned. */
	assert(scope);
	uintptr_t flags = (scope->bigalloc_or_uniqtype & UNIQTYPE_PTR_MASK_FLAGS);
	/* Currently we
	 * - walk child bigallocs (if asked), then
	 * - walk suballocator allocations (if asked), then
	 * - walk uniqtype substructure.
	 * BUT
	 * - we want a depth-first walk to be possible
	 *   which visits allocations at any depth in increasing address order.
	 * - That means we MAY need to interleave the bigalloc-walking
	 *   with the suballoc-walking.
	 *   One way: accept a range, and walk within that range; use bigalloc start/end to break up.
	 * - SANITY: when do we have a mix of child bigallocs and ordinary allocs?
	 *
	 * The wackiest cases are
	 * - promoted malloc chunks, which may or may not be suballoc-d from
	 * - auxv containing the initial stack, rather
	 *   than the other way around, which was so that stackframe could be
	 *   stack's suballocator.
	 * - packed_sequence instances -- these may have a type, but also have a
	 *   bigalloc that knows more fine-grained types. The allocator may not
	 *   know about them.
	 
	 * From auxv.c:
	 * Don't record the stack allocator as a suballocator; child bigallocs
	 * fill this function for us. Suballocators only make sense at the leaf
	 * level, when you can say "anything smaller than us is managed by this
	 * allocator". Child bigallocs can be sized precisely, leaving our auxv
	 * "crack" modelled with precise bounds, which is exactly what we need 
	 * as the auxv is often less than a whole page. The stack will always be
	 * a bigalloc, and having it as our child is how we carve out this
	 * not-page-boundaried region as the auxv.

	 * So here we have the auxv mostly-covered by a child bigalloc that is
	 * the stack, which is suballocated by the stackframe. If we wanted to
	 * walk the auxv depth-first, what would we need to do?
	 * And let's imagine (falsely) that there is stuff at the end of the auxv
	 * too.
	 * We would need exactly to interleave the walking of child small allocs
	 * with the walking of the child bigalloc. Using the 'range' arguments is
	 * probably the right thing here. Remember that 'walk_allocations' is a
	 * primitive which allocators can reasonably provide, but which client code
	 * is unlikely to call directly - walk_df is much more useful.
	 *
	 * So what about *non*-imposed child bigallocs? We seem to be expecting the
	 * 'promoting' allocator to notice that there's a bigalloc and interleave
	 * that. But is that reasonable? If it promoted the chunk, then fine. But
	 * we seem to have cases where that's not so, e.g. in the ELF elements
	 * allocator. There we try to promote a section simply by creating a new
	 * bigalloc that hangs in the relevant place. But it doesn't show up as
	 * imposed... why not? That would mean
	 * b->suballocator || child->allocated_by != b->suballocator
	 * ... but what is b? it's the ELF file bigalloc, and its suballocator is __elf_elements_allocator
	 * ... and 'child' is the new bigalloc for the section, and allocated_by is ^^ that too.
	 * So it's not considered imposed.
	 */
	int ret = 0;
	void *walked_up_to = maybe_range_begin ?: scope->base;
	/* Our path to the child needs an 'encl'. Or does it?
	 * 'encl' means 'path_to_container'. */
	if (BOU_IS_BIGALLOC(scope->bigalloc_or_uniqtype))
	{
		struct big_allocation *b = BOU_BIGALLOC(scope->bigalloc_or_uniqtype);
		assert(b->begin == scope->base);
		struct alloc_tree_path new_cont = {
			.to_here = (struct alloc_tree_link) {
				.container = (struct alloc_tree_pos) {
					.base = b->begin,
					.bigalloc_or_uniqtype = (uintptr_t) b /* no flags set */
				},
				.containee_coord = 1
			},
			.encl = NULL,
			.encl_depth = 0
		};
		if (flags & ALLOC_WALK_BIGALLOC_IMPOSED_CHILDREN)
		{
			// we are asked to walk the allocations under b in the allocation tree
			/* To walk the imposed children, we need to divide the range up into
			 * chunks for each imposed child. FIXME: this is racy, but imposed
			 * children are rare and come/go/move even more rarely. */
			for (struct big_allocation *child = BIDX(b->first_child); child;
				walked_up_to = child->end,
				child = BIDX(child->next_sib),
				++new_cont.to_here.containee_coord)
			{
				// skip any that don't fall within our range
				if ((uintptr_t) child->end <= (uintptr_t) walked_up_to) continue;
				if (maybe_range_end && (uintptr_t) child->begin > (uintptr_t) maybe_range_end) continue;
				if (!b->suballocator || child->allocated_by != b->suballocator)
				{
					// it's an imposed child
					// 1. walk non-i.c. suballocations
					// NOTE: this will override the 'coord' as it calls the cb
					// for its own children; we only pass coords for bigallocs
					// or for uniqtype containeds
					ret = b->suballocator->walk_allocations(&new_cont.to_here.container, cb, arg,
						walked_up_to, child->begin);
					if (ret != 0) return ret;
					// 2. walk the i.c.
					ret = cb(b, b->begin, NULL /* FIXME: type */, NULL /* FIXME: allocsite */,
						&new_cont.to_here, arg);
					if (ret != 0) return ret;
				}
			}
		}
		// now there is a range, either from the beginning or from the last i.c.,
		// to the end, that we haven't walked yet and which by definition only contains normal children
		ret = b->suballocator->walk_allocations(&new_cont.to_here.container, cb, arg,
			walked_up_to, maybe_range_end ?: b->end);
		return ret;
	}
	// if we get here, then
	// we're just a thing with a type, and want to walk its substructure
	// eventually: delegate to the uniqtype allocator (more uniform)
	// for now: use UNIQTYPE_FOR_EACH_SUBOBJECT
#if 0
	return __uniqtype_allocator_walk_allocations(...);
#else
	/* We've ruled out the bigalloc case, so we're being asked
	 * to iterate through subobjects given a uniqtype. */
	// for now, use our iteration macro
	struct alloc_tree_path path_to_child = (struct alloc_tree_path) {
		.to_here = (struct alloc_tree_link) {
			.container = { scope->base, scope->bigalloc_or_uniqtype },
			.containee_coord = 0 // will update
		},
		.encl = NULL,
		.encl_depth = 0
	};
#define suballoc_thing(_i, _t, _offs) do { \
	path_to_child.to_here.containee_coord = (_i) + 1; \
	void *base = (void*)(((uintptr_t) path_to_child.to_here.container.base) + (_offs)); \
	ret = cb(NULL, base, \
	   (_t), \
	   NULL /* allocsite */, \
	   &path_to_child.to_here, \
	   arg); \
	if (ret != 0) return ret; \
} while (0)
	struct uniqtype *u = BOU_UNIQTYPE(scope->bigalloc_or_uniqtype);
	if (UNIQTYPE_HAS_SUBOBJECTS(u))
	{
		UNIQTYPE_FOR_EACH_SUBOBJECT(u, suballoc_thing);
	}
	return ret;
#endif
}

int
alloc_walk_allocations(struct alloc_tree_pos *cont,
	walk_alloc_cb_t *cb,
	void *arg,
	void *maybe_range_begin,
	void *maybe_range_end) __attribute__((alias("__liballocs_walk_allocations")));

struct walk_df_arg
{
	walk_alloc_cb_t *cb;
	void *arg;
	struct alloc_tree_path path_to_container;
};
static int walk_one_df_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
		struct alloc_tree_link *link, void *walk_df_arg_as_void)
{
	// NOT this: struct alloc_tree_path *path = (struct alloc_tree_path *) link; // downcast
	/* We can't do the downcast. We have to make it so that our
	 * callee cbs can do te downcast. */
	/* As a way to signal "skip this subtree" as distinct from
	 * "terminate the whole walk here", return values mean
	 *     0: carry on
	 *    -1: skip the subtree
	 *  else: return immediately
	 */
	// If the allocating allocator says there's no bigalloc, it doesn't
	// mean there isn't. It just means it doesn't know or care. We do
	// because we don't want to double-walk the substructure (once
	// with uniqtype, once with the bigalloc child structure).
	if (t && BOU_IS_BIGALLOC(link->container.bigalloc_or_uniqtype))
	{
		for (struct big_allocation *child = BIDX(BOU_BIGALLOC(link->container.bigalloc_or_uniqtype)->first_child);
			child;
			child = BIDX(child->next_sib))
		{
			// does this child alloc actually describe the alloc
			// in question? e.g. if it was just hung on there.
			if (child->begin == obj)
			{
				maybe_the_allocation = child;
				// this will force us to pass a BOU_BIGALLOC not a BOU_UNIQTYPE
				// wheren we call __liballocs_walk_allocations below
				break;
			}
		}
	}

	struct walk_df_arg *arg = (struct walk_df_arg *) walk_df_arg_as_void;
	/*
	 * First, we call back for the present thing (i.e. we are pre-order).
	 * When we call a CB, we guarantee that we give it a path not just a link.
	 * Our arg gives us the path to the current position.
	 */
	struct alloc_tree_path *path_to_container = &arg->path_to_container;
	struct alloc_tree_path path_to_here = {
		.to_here = { .container = { link->container.base, link->container.bigalloc_or_uniqtype },
		             .containee_coord = link->containee_coord },
		.encl = path_to_container,
		.encl_depth = 1 + path_to_container->encl_depth
	};
	int ret = arg->cb(maybe_the_allocation, obj, t, allocsite, /* upcast */ &path_to_here.to_here,
		arg->arg);
	if (ret == -1) return 0; // tell the caller to carry on *its* traversal
	if (ret) return ret;     // stop immdiately
	/*
	 * Now... is this a thing that might contain things?
	 * We can exit early if not.
	 */
	if (!maybe_the_allocation && !t) return 0;
	// It is, so set it as our new pos, under which we then walk.
	// We build the path to it, and pass that in our opaque arg.
	struct alloc_tree_pos new_pos = (struct alloc_tree_pos) {
		.base = obj,
		.bigalloc_or_uniqtype = (uintptr_t)((void*)maybe_the_allocation ?: (void*)t)
	};
	struct walk_df_arg new_arg = {
		.cb = arg->cb,
		.arg = arg->arg,
		.path_to_container = path_to_here
	};
	return __liballocs_walk_allocations(&new_pos, walk_one_df_cb,
		&new_arg, NULL, NULL);
}
/* NOTE this is non-recursive. We only call this one at top level. */
int __liballocs_walk_allocations_df(
	struct alloc_tree_pos *under_here,
	walk_alloc_cb_t *cb,
	void *arg
)
{
	/* We walk the tree rooted at scope 'cont',
	 * by walking the allocations with a callback
	 * that walks deeper. */
	struct walk_df_arg walk_df_arg = {
		.cb = cb,
		.arg = arg,
		.path_to_container = { // initially empty
			.to_here = { .container = { .base = NULL, .bigalloc_or_uniqtype = 0UL },
			             .containee_coord = 0 },
			.encl = NULL,
			.encl_depth = 0
		}
	};
	return __liballocs_walk_allocations(
		under_here,
		walk_one_df_cb,
		&walk_df_arg,
		NULL,
		NULL
	);
}

int
__liballocs_walk_refs_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *to_here, void *walk_refs_state_as_void)
{
	struct walk_refs_state *state = (struct walk_refs_state *) walk_refs_state_as_void;
	/* To walk references, we walk allocations (our caller is doing that) and
	 * - if they are a reference, run our cb on them
	 * - if they might contain references, recursively walk them with the same cb;
	 * - otherwise skip them.
	 */
	// 1. is this a reference?
	intptr_t how;
	if (0 != (how = state->interp->can_interp(obj, t, to_here)))
	{
		state->seen_how = how;
		int ret = state->ref_cb(maybe_the_allocation,
			obj, t, allocsite, to_here, walk_refs_state_as_void);
		state->seen_how = 0;
		// 'ret' tells us whether or not to keep walking references; non-zero means stop
		if (ret) return ret;
		// if we got 0, we still don't want to "continue" per se; we want to cut off
		// the subtree
		return -1;
	}
	// 2. Is this a thing that might contain references?
	// We really want our interpreter to help us here.
	// Even a simple scalar might be a reference, so we really need help.
	if (!state->interp->may_contain(obj, t, to_here)) return -1;

	return 0; // keep going with the depth-first thing
}

/* This cb can be given to a depth-first walk to enumerate environment elements,
 * using a given interpreter. */
int
__liballocs_walk_environ_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link, void *walk_environ_state_as_void)
{
	// downcast 'link' as we are always doing a depth-first walk
	struct alloc_tree_path *path = (struct alloc_tree_path *) link;
	struct walk_environ_state *state = (struct walk_environ_state *) walk_environ_state_as_void;
	/* To walk environment info, we walk allocations (our caller is doing that) and
	 * - if they are part of the environment, run our cb on them
	 * - if they might contain environment info, recursively walk them with the same cb;
	 * - otherwise skip them.
	 */
	// 1. is this a reference?
	uintptr_t maybe_environ_key = state->interp->is_environ(obj, t, &path->to_here);
	if (maybe_environ_key)
	{
		// we want to pass the key through to our callback; how?
		struct environ_elt_cb_arg arg = {
			.state = state,
			.key = maybe_environ_key
		};
		int ret = state->environ_cb(maybe_the_allocation,
			obj, t, allocsite, &path->to_here, &arg);
		// 'ret' tells us whether or not to keep walking environment; non-zero means stop
		if (ret) return ret;
		// if we got 0, we still don't want to "continue" per se; we want to cut off
		// the subtree
		return -1;
	}
	// 2. Is this a thing that might contain references?
	// We really want our interpreter to help us here.
	// Even a simple scalar might be a reference, so we really need help.
	if (!/*state->interp->may_contain(obj, t, cont)*/ 1) return -1;

	return 0; // keep going with the depth-first thing
}

// instantiate inline
extern inline _Bool 
__liballocs_find_matching_subobject(unsigned target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, unsigned *last_uniqtype_offset,
		unsigned *p_cumulative_offset_searched,
		struct uniqtype **p_cur_containing_uniqtype,
		struct uniqtype_rel_info **p_cur_contained_pos);
