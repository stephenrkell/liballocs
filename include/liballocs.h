#ifndef LIBALLOCS_H_
#define LIBALLOCS_H_

#ifndef _GNU_SOURCE
#warning "compilation unit is not _GNU_SOURCE; some features liballocs requires may not be available"
#endif

#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#else
#endif

#include <sys/types.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

extern void warnx(const char *fmt, ...); // avoid repeating proto
#ifndef NDEBUG
#include <assert.h>
#endif

#include "memtable.h"
#include "uniqtype.h"
struct insert; // instead of heap_index.h
struct allocator; // instead of allocmeta.h

#define ALLOC_IS_DYNAMICALLY_SIZED(all, as) \
	((all) != (as))

#ifdef USE_REAL_LIBUNWIND
#include <libunwind.h>
#else
#include "fake-libunwind.h"
#endif

#include "allocsmt.h"
#include "liballocs_cil_inlines.h"

extern unsigned long __liballocs_aborted_stack;
extern unsigned long __liballocs_aborted_static;
extern unsigned long __liballocs_aborted_unknown_storage;
extern unsigned long __liballocs_hit_heap_case;
extern unsigned long __liballocs_hit_stack_case;
extern unsigned long __liballocs_hit_static_case;
extern unsigned long __liballocs_aborted_unindexed_heap;
extern unsigned long __liballocs_aborted_unrecognised_allocsite;

/* This API is a mess because there are three different classes of client. 
 * 
 * - extenders (libcrunch)
 * - direct clients (programs linking -lallocs and using our API) 
 * - weak clients (programs that can use liballocs, but run okay without)
 * 
 * The first two are the ones who'll instantiate our inlines and hence
 * generate references to our stuff. Weak clients will just (perhaps)
 * embed our CIL inlines. So it's only stuff in the liballocs_cil_inlines.h 
 * header file that they depend on. We deliberately keep this small, and
 * ideally it will run even without the noop library (i.e. never branch
 * out of line), but the linker currently won't generate the right code
 * without the noop library being present.
 */

// stuff for use by extenders only -- direct/weak clients shouldn't use this
struct addrlist;
int __liballocs_addrlist_contains(struct addrlist *l, void *addr);
void __liballocs_addrlist_add(struct addrlist *l, void *addr);
extern struct addrlist __liballocs_unrecognised_heap_alloc_sites;

Dl_info dladdr_with_cache(const void *addr);

extern void *__liballocs_main_bp; // beginning of main's stack frame
char *get_exe_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_basename(void) __attribute__((visibility("hidden")));

extern inline struct allocsite_entry *allocsite_to_entry(const void *allocsite) __attribute__((gnu_inline,always_inline));
extern inline struct allocsite_entry * __attribute__((gnu_inline)) allocsite_to_entry(const void *allocsite)
{
	if (!allocsite) return NULL;
	assert(__liballocs_allocsmt != NULL);
	struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, allocsite);
	struct allocsite_entry *bucket = *bucketpos;
	for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
	{
		if (p->allocsite == allocsite)
		{
			return p;
		}
	}
	return NULL;
}
struct allocsite_entry *__liballocs_allocsite_to_entry(const void *allocsite);

extern inline struct uniqtype *allocsite_to_uniqtype(const void *allocsite) __attribute__((gnu_inline,always_inline));
extern inline struct uniqtype * __attribute__((gnu_inline)) allocsite_to_uniqtype(const void *allocsite)
{
	struct allocsite_entry *e = allocsite_to_entry(allocsite);
	if (!e) return NULL;
	return e->uniqtype;
}
struct uniqtype *__liballocs_allocsite_to_uniqtype(const void *allocsite);

extern int __liballocs_debug_level;
extern _Bool __liballocs_is_initialized __attribute__((weak));

int __liballocs_global_init(void) __attribute__((weak));
// declare as const void *-returning, to simplify trumptr
const void *__liballocs_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
// used by section-group test case, among others
void *__liballocs_my_metaobj(void);

/* Uniqtypes for signed_char and unsigned_char and so on.
 * 
 * These are part of the API, BUT we don't want them to appear in the preload .so 
 * because then they can't be uniqued w.r.t. the executable.
 * So they go in a nasty .a, and the -lallocs .so is a linker script.
 * That way, an executable linking -lallocs will get them, together with
 * a reference to the liballocs .so. The .so does not define them.
 */

extern struct uniqtype __uniqtype__void/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__int/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__unsigned_int/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__signed_char/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__unsigned_char/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype____FUN_FROM___FUN_TO_uint$64 /* __attribute__((weak))*/;
// #pragma 
#define __liballocs_uniqtype_of_typeless_functions __uniqtype____FUN_FROM___FUN_TO_uint$64
extern struct uniqtype __uniqtype__long_int;
extern struct uniqtype __uniqtype__unsigned_long_int;
extern struct uniqtype __uniqtype__short_int;
extern struct uniqtype __uniqtype__short_unsigned_int;
extern struct uniqtype __uniqtype____PTR_void;
extern struct uniqtype __uniqtype____PTR_signed_char;
extern struct uniqtype __uniqtype__float;
extern struct uniqtype __uniqtype__double;

#ifdef __GNUC__ /* HACK. FIXME: why do we need this? maybe libfootprints uses them? */
extern struct uniqtype __uniqtype__float$32;
extern struct uniqtype __uniqtype__float$64;
extern struct uniqtype __uniqtype__int$16;
extern struct uniqtype __uniqtype__int$32;
extern struct uniqtype __uniqtype__int$64;
extern struct uniqtype __uniqtype__uint$16;
extern struct uniqtype __uniqtype__uint$32;
extern struct uniqtype __uniqtype__uint$64;
extern struct uniqtype __uniqtype__signed_char$8;
extern struct uniqtype __uniqtype__unsigned_char$8;
extern struct uniqtype __uniqtype____PTR_int$32;
extern struct uniqtype __uniqtype____PTR_int$64;
extern struct uniqtype __uniqtype____PTR_uint$32;
extern struct uniqtype __uniqtype____PTR_uint$64;
extern struct uniqtype __uniqtype____PTR_signed_char$8;
#endif

struct liballocs_err;
typedef struct liballocs_err *liballocs_err_t;

extern struct liballocs_err __liballocs_err_stack_walk_step_failure;
extern struct liballocs_err __liballocs_err_stack_walk_reached_higher_frame;
extern struct liballocs_err __liballocs_err_stack_walk_reached_top_of_stack;
extern struct liballocs_err __liballocs_err_unknown_stack_walk_problem;
extern struct liballocs_err __liballocs_err_unindexed_heap_object;
extern struct liballocs_err __liballocs_err_unrecognised_alloc_site;
extern struct liballocs_err __liballocs_err_unrecognised_static_object;
extern struct liballocs_err __liballocs_err_object_of_unknown_storage;

const char *__liballocs_errstring(struct liballocs_err *err);
liballocs_err_t extract_and_output_alloc_site_and_type(
    struct insert *p_ins,
    struct uniqtype **out_type,
    void **out_site
) __attribute__((visibility("hidden")));


/* We define a dladdr that caches stuff. */
Dl_info dladdr_with_cache(const void *addr);

/* Iterate over all uniqtypes in a given shared object. */
int __liballocs_iterate_types(void *typelib_handle, 
		int (*cb)(struct uniqtype *t, void *arg), void *arg);
/* Our main API: query allocation information for a pointer */
#if defined(__PIC__) || defined(__code_model_large__) /* see note below! */
inline 
#endif
struct liballocs_err *__liballocs_get_alloc_info(const void *obj, 
	struct allocator **out_allocator, const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site);
/* Some inlines follow at the bottom. */

/* Public API for l0index / mappings was here. FIXME: why was it public? Presumably
 * for libcrunch's consumption, i.e. clients that "extend". But libcrunch
 * already includes liballocs_private.h, so there's no need for this to be here.
 * I've moved it to liballocs_private.h. */

#include "allocmeta.h"

/* our own private assert */
extern inline void
__attribute__((always_inline,gnu_inline))
__liballocs_private_assert (_Bool cond, const char *reason, 
	const char *f, unsigned l, const char *fn)
{
#ifndef NDEBUG
	if (!cond) __assert_fail(reason, f, l, fn);
#endif
}

extern inline void 
__attribute__((always_inline,gnu_inline))
__liballocs_ensure_init(void)
{
	if (__builtin_expect(!__liballocs_is_initialized, 0))
	{
		/* This means we haven't initialized.
		 * Try that now (it won't try more than once). */
		int ret = __liballocs_global_init();
		__liballocs_private_assert(ret == 0, "liballocs init",
			__FILE__, __LINE__, __func__);
	}
}
// inline definition in pageindex.h, instantiated in pageindex.c
// GAH -- so clients including only this header will complain "used but not defined"
// -- we need ordinary headers to be all-inline, but
// pageindex.c to have one non-inline.
// How to placate the compiler of the translation unit that doesn't include pageindex.h?
// I think the answer is "you can't; refactor headers to avoid this"
/* The "leaf allocator" for an address is the allocator
 * of the most deeply nested allocation covering a particular
 * address. For example, if a malloc has two live allocations
 * and a gap in the middle, the leaf allocator for an address
 * in the gap is that of the malloc *arena*, so probably mmap.  */

inline struct allocator *__liballocs_leaf_allocator_for(const void *obj, 
	struct big_allocation **out_containing_bigalloc,
	struct big_allocation **out_maybe_the_allocation);

/* The "page-leaf allocator" for an address
 * is the allocator, if any,
 * of the deepest bigalloc that covers the entire page and is not suballocated,
 * or the suballocator managing the deepest bigalloc covering the entire page.
 * Unlike the above, it will not "see through holes": if we query an address
 * which is not covered by a (sub)allocation of the page-managing allocator,
 * we will still be returned the page-managing allocator and not one higher.
 *
 * These semantics are cacheable via the pageindex, although we don't currently
 * do this (FIXME): we set a spare bit iff the recorded bigalloc# is the page-leaf
 * allocator for the whole page. This must not be set if the page contains a
 * non-page-aligned bigalloc boundary. FIXME: take care of this in pageindex.c.
 * Bit set means "no deeper bigalloc covers *any part of this page*".
 */


// declare some more stuff that our inlines need, but is really liballocs-internal
_Bool __liballocs_notify_unindexed_address(const void *obj);
void __liballocs_report_wild_address(const void *ptr);

/* Find the first-level subobject spanning a given offset.
 *
 * The caller knows whether
 * the rel is a .memb or a .t from t->kind.
 * It also knows the starting offset of the contained span:
 * if it's a subobject, it's the member offset.
 * If it's an array element, it's the target offset
 * rounded down to a multiple of the the element size.
 * The macros UNIQTYPE_SUBOBJECT_TYPE and
 * UNIQTYPE_SUBOBJECT_OFFSET can be used to extract these.
 *
 * If there are
 * many contained subobjects that might span the offset
 * (e.g. if we're a union) we can specify which one we
 * want to start from, and we do a linear search until
 * the start offset is > the target offset. Otherwise
 * we do a binary search.
 *
 * We leave recursive search to a separate function. */
inline
struct uniqtype_rel_info *
__liballocs_find_span(struct uniqtype *u, unsigned target_offset,
	struct uniqtype_rel_info *contained_search_start /* typically NULL */)
{
	#define BIGGEST_SANE_UNIQTYPE_STRUCT_SIZE 4096
	if (UNIQTYPE_IS_ARRAY_TYPE(u))
	{
		unsigned num_contained = UNIQTYPE_ARRAY_LENGTH(u);
		struct uniqtype *element_u = UNIQTYPE_ARRAY_ELEMENT_TYPE(u);
		unsigned contained_target_idx = target_offset / element_u->pos_maxoff;
		if (element_u->pos_maxoff != 0 &&
				num_contained > contained_target_idx)
		{
			return &u->related[0];
		}
		return NULL;
	}
	// besides arrays, only composites have subobjects
	if (!(UNIQTYPE_IS_COMPOSITE_TYPE(u))) return NULL;
	unsigned num_contained = UNIQTYPE_COMPOSITE_MEMBER_COUNT(u);
	/* If we were given a starting place, linear-search forward from
	 * that until the member offset no longer spans. */
	if (contained_search_start)
	{
		assert((uintptr_t) contained_search_start - (uintptr_t) u < BIGGEST_SANE_UNIQTYPE_STRUCT_SIZE);
		/* linear search until the subobject begins after the
		 * target offset; return the first one that overlaps. */
		for (struct uniqtype_rel_info *p_rel = contained_search_start;
			p_rel - &u->related[0] < UNIQTYPE_COMPOSITE_MEMBER_COUNT(u)
			&& p_rel->un.memb.off <= target_offset; ++p_rel)
		{
			if (p_rel->un.memb.off + p_rel->un.memb.ptr->pos_maxoff > target_offset)
			{
				return p_rel;
			}
		}
		return NULL;
	}
	/* We're doing a binary search for the first contained subobject
	 * that spans our target address; that is, its offset is <= the
	 * target offset and its offset+size is > the target offset.
	 * The subobject entries are sorted by offset and size.
	 * NOTE that they need nto be any contained object that satisfies
	 * this! */
	int lower_ind = 0;
	int upper_ind = num_contained;
	while (lower_ind + 1 < upper_ind) // difference of >= 2
	{
		/* Bisect the interval */
		int bisect_ind = (upper_ind + lower_ind) / 2;
		assert(bisect_ind > lower_ind && "bisection progress");
		// which half do we want?
		unsigned bisect_pos_off = u->related[bisect_ind].un.memb.off;
		if (bisect_pos_off > target_offset)
		{
			/* Our solution lies in the lower half of the interval */
			upper_ind = bisect_ind;
		} else lower_ind = bisect_ind;
	}
	// did we find anything?
	if (lower_ind >= upper_ind)
	{
		// this should mean num_contained == 0
		assert(num_contained == 0 && "no contained objects");
		return NULL;
	}
	assert(lower_ind + 1 == upper_ind); // difference of 1, i.e. we got down to one slot
	/* We're down to one slot. But we may still have overshot
	 * the target offset, e.g. in the case of a 
	 * stack frame where offset zero might not be used. */
	if (u->related[lower_ind].un.memb.off > target_offset)
	{
		assert(lower_ind == 0);
		return NULL;
	}
	/* We found one subobject whose offset is <= the target offset.
	 * The next subobject, if it exists, is definitely at an offset that is >. */
	unsigned cur_off = u->related[lower_ind].un.memb.off;
	assert(cur_off <= target_offset && "offset underapproximates");
	assert((lower_ind+1 == num_contained
		|| u->related[lower_ind+1].un.memb.off > target_offset) &&
		"found offset is the greatest");
	/* ... but we might not have found the *first* contained object
	 * spanning the target offset -- in the case of a union or stack
	 * frame. We require that same-offset subobjects are sorted in
	 * increasing size. And we don't allow subobjects to left-overlap,
	 * i.e. a *lower*-starting offset spanning until *later*.
	 * So scan backwards through same-offset members until so that we have the lowest.
	 * FIXME: need to account for the element size? Or here are we
	 * ignoring padding anyway? */
	while (
		lower_ind > 0
			&& u->related[lower_ind-1].un.memb.off == cur_off
			&& u->related[lower_ind-1].un.memb.off + u->related[lower_ind-1].un.memb.ptr->pos_maxoff
				> target_offset
	) --lower_ind;

	return &u->related[lower_ind];
}

/* HMM. I probably should just have coded the descent recursively. */
struct uniqtype_containment_ctxt
{
	struct uniqtype *u_container;
	unsigned u_offset_within_container;
	struct uniqtype_rel_info *u_ctxt;
	struct uniqtype_containment_ctxt *next;
};

inline _Bool
 __liballocs_search_subobjects_spanning_with_ctxt
	(struct uniqtype *u,
	struct uniqtype_containment_ctxt *ucc,
	unsigned u_offset_from_search_start,
	unsigned target_offset_within_u,
	_Bool (*visit_stop_test)(struct uniqtype *, struct uniqtype_containment_ctxt *, unsigned, void*),
	void *arg, unsigned *out_offset, struct uniqtype_rel_info **out_ctxt)
{
	struct uniqtype_containment_ctxt terminal_ctxt = (struct uniqtype_containment_ctxt) {
		.u_container = NULL
	};
	if (!ucc) ucc = &terminal_ctxt;
	assert(!ucc->u_ctxt ||
		(uintptr_t) ucc->u_ctxt - (uintptr_t) ucc->u_container < BIGGEST_SANE_UNIQTYPE_STRUCT_SIZE);
	struct uniqtype_containment_ctxt local_ctxt = (struct uniqtype_containment_ctxt) {
		.u_container = NULL
	};
	/* Use find_span to walk spans, calling the test
	 * until it returns true. Return the context where it does so. */
	do // hmm -- should maybe be a "for" loop
	{
		// 1. process our current position
		_Bool stop = 0;
		assert(u->pos_maxoff > target_offset_within_u);
		stop = visit_stop_test(u, ucc, u_offset_from_search_start, arg);
		if (stop)
		{
			if (out_offset) *out_offset = u_offset_from_search_start;
			if (out_ctxt) *out_ctxt = ucc->u_ctxt;
			return 1;
		}

		// 2. if we have a sibling context, process it recursively
		if (ucc->u_ctxt && UNIQTYPE_IS_COMPOSITE_TYPE(ucc->u_container))
		{
			unsigned target_offset_within_container = target_offset_within_u + ucc->u_offset_within_container;
			struct uniqtype_rel_info *sibling = __liballocs_find_span(ucc->u_container,
				target_offset_within_container, ucc->u_ctxt + 1);
			if (__builtin_expect(sibling != NULL, 0))
			{
				unsigned sibling_offset_within_container
				 = UNIQTYPE_SUBOBJECT_OFFSET(ucc->u_container, sibling, target_offset_within_container);
				assert(sibling_offset_within_container == ucc->u_offset_within_container);

				// if the sibling doesn't span up to the target offset, skip it
				// (actually this shouldn't happen, if members are sorted by size
				struct uniqtype *sibling_type = UNIQTYPE_SUBOBJECT_TYPE(ucc->u_container, sibling);
				assert(sibling_type->pos_maxoff > target_offset_within_u);
				struct uniqtype_containment_ctxt sibling_ctxt = *ucc;
				sibling_ctxt.u_ctxt = sibling;
				stop = __liballocs_search_subobjects_spanning_with_ctxt(
					sibling_type,
					&sibling_ctxt,
					u_offset_from_search_start, // sibling must start at same address as us
					target_offset_within_u,
					visit_stop_test,
					arg,
					out_offset,
					out_ctxt);
				if (stop) return 1;
				// note we only need to process one sibling, because it will recurse down its siblings
			}
		}

		// move deeper iteratively
		struct uniqtype_rel_info *new_u_ctxt = __liballocs_find_span(u, target_offset_within_u, NULL);
		if (new_u_ctxt)
		{
			unsigned distance_moved = UNIQTYPE_SUBOBJECT_OFFSET(u, new_u_ctxt, target_offset_within_u);
			// CARE with these assignments... don't change anything til we have everything
			struct uniqtype *new_u_container = u;
			unsigned new_u_offset_within_container = distance_moved;
			struct uniqtype *new_u = UNIQTYPE_SUBOBJECT_TYPE(u, new_u_ctxt);
			unsigned new_u_offset_from_search_start = u_offset_from_search_start + distance_moved;
			unsigned new_target_offset_within_u = target_offset_within_u - distance_moved;
			// now push a new ucc
			local_ctxt.u_container = new_u_container;
			local_ctxt.u_offset_within_container = new_u_offset_within_container;
			local_ctxt.u_ctxt = new_u_ctxt;
			local_ctxt.next = (ucc == &local_ctxt ? &terminal_ctxt : ucc);
			ucc = &local_ctxt;
			u = new_u;
			u_offset_from_search_start = new_u_offset_from_search_start;
			target_offset_within_u = new_target_offset_within_u;
		}
		else
		{
			// we want to terminate
			u = NULL;
		}
	} while (u);
	// if we got here, no visit function said "stop".
	// so the outputs are not valid.
	return 0;
}

extern inline _Bool
(__attribute__((always_inline,gnu_inline)) __liballocs_search_subobjects_spanning)
	(struct uniqtype *u,
	unsigned target_offset_within_u,
	_Bool (*visit_stop_test)(struct uniqtype *, struct uniqtype_containment_ctxt *, unsigned, void*),
	void *arg, unsigned *out_offset, struct uniqtype_rel_info **out_ctxt)
{
	struct uniqtype_containment_ctxt ctxt = (struct uniqtype_containment_ctxt) {
		.u_container = NULL
	};
	return __liballocs_search_subobjects_spanning_with_ctxt(
		u,
		&ctxt,
		0,
		target_offset_within_u,
		visit_stop_test,
		arg,
		out_offset,
		out_ctxt
	);
}

extern inline struct uniqtype *
( __attribute__((always_inline,gnu_inline))
 __liballocs_deepest_span)
	(struct uniqtype *u, unsigned target_offset,
	unsigned *out_offset, struct uniqtype_rel_info **out_ctxt)
{
	// FIXME: does backtracking search make sense here?
	struct uniqtype_rel_info *contained;
	struct uniqtype_rel_info *last_contained = NULL;
	struct uniqtype *t_reached = u;
	unsigned offset_reached = 0;
	while (NULL != (contained = __liballocs_find_span(t_reached, target_offset, NULL)))
	{
		// -- make the sibling case a recursive call, so that commonly recursion is not needed
		// For now, we immediately descend a level
		unsigned distance_traversed = UNIQTYPE_SUBOBJECT_OFFSET(t_reached, contained, target_offset);
		struct uniqtype *subobj_type = UNIQTYPE_SUBOBJECT_TYPE(t_reached, contained);
		offset_reached += distance_traversed;
		target_offset -= distance_traversed;
		t_reached = subobj_type;
		last_contained = contained;
	}
	if (out_offset) *out_offset = offset_reached;
	if (out_ctxt) *out_ctxt = last_contained;
	return t_reached;
}

extern inline struct uniqtype *
( __attribute__((always_inline,gnu_inline))
 __liballocs_outermost_subobject_at_offset)
	(struct uniqtype *u, unsigned target_offset,
	unsigned *out_offset)
{
	/* Backtracking search *does* makes sense here. We want
	 * a subobject that starts exactly at the target offset.
	 * Our breadth-first (siblings-first) approach does a good
	 * approximation of the Right Thing, although I think
	 * probably not exactly the Right Thing, when there are
	 unions in the mix. */
	struct uniqtype_rel_info *contained;
	struct uniqtype *t_reached = u;
	unsigned offset_reached = 0;
	while (target_offset != 0)
	{
		contained = __liballocs_find_span(t_reached, target_offset, NULL);
		if (!contained) break;
		// we've descended a level
		unsigned distance_traversed = UNIQTYPE_SUBOBJECT_OFFSET(t_reached, contained, target_offset);
		struct uniqtype *subobj_type = UNIQTYPE_SUBOBJECT_TYPE(t_reached, contained);
		offset_reached += distance_traversed;
		target_offset -= distance_traversed;
		t_reached = subobj_type;
		// FIXME: backtracking search: use "contained" to check for sibling possibilities
	}
	if (target_offset != 0)
	{
		// we failed
		return NULL;
	}
	if (out_offset) *out_offset = offset_reached;
	return t_reached;
}

/* HACK HACK HACKETY HACK: we want our fast-path functions to be inlined.
 * However, there's a linking problem: we reference pageindex which is a protected
 * symbol. From an executable that is a client of liballocs, under the small code
 * model, the linker won't let us reference this symbol (copy-reloc'ing a protected
 * symbol is a recipe for trouble, which ld.bfd sensibly does not allow). So we
 * don't inline this function from such clients. We use a hacky method for identifying
 * them: non-PIC code. This BREAKS small-model PIE executables -- use -mcmodel=large
 * if you want a PIE executable that is a client of liballocs. FIXME: I'm not actually
 * sure that sensible things happen under the large code model -- more experimentation
 * required.
 */
#if defined(__PIC__) || defined(__code_model_large__)
inline 
struct liballocs_err *
__liballocs_get_alloc_info
	(const void *obj, 
	struct allocator **out_allocator,
	const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes, 
	struct uniqtype **out_alloc_uniqtype, 
	const void **out_alloc_site)
{
	struct liballocs_err *err = 0;
	
	/* This function is always asking about the leaf
	 * allocator. And our cached memranges always
	 * talk about those? ARGH, no, they could be
	 * underneath.
	 *
	 * Do we want a leaf cache, a memrange cache,
	 * an any-level cache, or some mixture?
	 *
	 * So if we hit the cache,
	 * there's no need to query the allocator. The
	 * cache entries should record the allocator. */

	struct big_allocation *containing_bigalloc;
	struct big_allocation *maybe_the_allocation;
	struct allocator *a = __liballocs_leaf_allocator_for(obj, &containing_bigalloc, &maybe_the_allocation);
	if (__builtin_expect(!a, 0))
	{
		_Bool fixed = __liballocs_notify_unindexed_address(obj);
		if (fixed)
		{
			a = __liballocs_leaf_allocator_for(obj, &containing_bigalloc, &maybe_the_allocation);
			if (!a) abort();
		}
		else
		{
			__liballocs_report_wild_address(obj);
			++__liballocs_aborted_unknown_storage;
			err = &__liballocs_err_object_of_unknown_storage;
			goto out_nocache;
		}
	/* Can we use our cached memranges somehow?
	 * Those with depth == 0 reflect leaf allocations. */
	}
	if (out_allocator) *out_allocator = a;
	err = a->get_info((void*) obj, maybe_the_allocation, out_alloc_uniqtype, (void**) out_alloc_start,
			out_alloc_size_bytes, out_alloc_site);
	if (!err || err == &__liballocs_err_unrecognised_alloc_site)
	{
		/* We can cache something. */
	}
out_nocache:
	return err;
}
#else
struct liballocs_err *
__liballocs_get_alloc_info
	(const void *obj, 
	struct allocator **out_allocator,
	const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes, 
	struct uniqtype **out_alloc_uniqtype, 
	const void **out_alloc_site);
#endif

/* We define a more friendly API for simple queries.
 * NOTE that we don't make these functions inline. They are still fast, internally,
 * because they make an inlined call to __liballocs_get_alloc_info.
 * BUT we don't want to make them inline themselves, because this complicates linking
 * to liballocs quite a bit. Specifically, if we inline them into callers, then 
 * callers need to link against lots of internals of liballocs which would otherwise
 * have hidden visibility. We would have to add mocked-up versions of all this stuff
 * to the noop library if we wanted this to work. Recall also that linking -lallocs does
 * *not* work! You really need to preload liballocs for it to work. */

#if defined(__GNUC__) && defined(LIBALLOCS_USE_INLCACHE) /* requires statement expression */
#define __liballocs_get_alloc_type(obj) \
	({ \
		static struct allocator *cached_allocator; \
		static /*bigalloc_num_t */ unsigned short cached_num; \
		(likely(cached_num && pageindex[PAGENUM(obj)] == cached_num)) ? \
		cached_allocator->get_type(obj) \
		: __liballocs_get_alloc_type_with_fill(obj, &cached_allocator, &cached_num); \
	})
struct uniqtype * 
__liballocs_get_alloc_type_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num);
#else
struct uniqtype * 
__liballocs_get_alloc_type(void *obj);
#endif

#if defined(__GNUC__) && defined(LIBALLOCS_USE_INLCACHE)
#define __liballocs_get_alloc_base(obj) \
	({ \
		static struct allocator *cached_allocator; \
		static /*bigalloc_num_t*/ unsigned short cached_num; \
		(likely(cached_num && pageindex[PAGENUM(obj)] == cached_num)) ? \
		generic_bitmap_get_base(obj, &big_allocations[cached_num]) \
		: __liballocs_get_alloc_base_with_fill(obj, &cached_allocator, &cached_num); \
	})
void *
__liballocs_get_alloc_base_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num);
#else
void *
__liballocs_get_alloc_base(void *obj);
#endif



struct uniqtype * 
__liballocs_get_outermost_type(void *obj);

struct uniqtype * 
__liballocs_get_type_inside(void *obj, struct uniqtype *t);

struct uniqtype * 
__liballocs_get_innermost_type(void *obj);

struct uniqtype * 
__liballocs_get_inner_type(void *obj, unsigned skip_at_bottom);

/* FIXME: we'd like to be able to walk the containment chain upwards. 
 * Feels like we want an API call that dumps a vector of uniqtype pointers,
 * each with their start offset. */

/* FIXME: this call needs to go away. */
struct insert *__liballocs_get_insert(struct big_allocation *maybe_the_allocation, const void *mem); // HACK: please remove (see libcrunch)

/* FIXME: use newer/better features in uniqtype definition */
inline 
const char **__liballocs_uniqtype_subobject_names(struct uniqtype *t)
{
	/* HACK: this all needs to go away, once we overhaul uniqtype's layout. */
	Dl_info i = dladdr_with_cache(t);
	if (i.dli_sname)
	{
		char *names_name = (char*) alloca(strlen(i.dli_sname) + sizeof "_subobj_names" + 1); /* HACK: necessary? */
		strncpy(names_name, i.dli_sname, strlen(i.dli_sname));
		strcat(names_name, "_subobj_names");
		void *handle = dlopen(i.dli_fname, RTLD_NOW | RTLD_NOLOAD);
		if (handle)
		{
			const char **names_name_array = (const char**) dlsym(handle, names_name);
			dlclose(handle);
			return names_name_array;
		}
	}
	return NULL;
}

struct allocator *
__liballocs_get_leaf_allocator(void *obj);

struct mapping_entry
{
	void *begin;
	void *end;
	int prot;
	int flags;
	off_t offset;
	_Bool is_anon;
	void *caller;
};
struct mapping_entry *__liballocs_get_memory_mapping(const void *obj,
		struct big_allocation **maybe_out_bigalloc);

static inline int __liballocs_walk_stack(int (*cb)(void *, void *, void *, void *), void *arg)
{
	liballocs_err_t err;
	unw_cursor_t cursor, saved_cursor;
	unw_word_t higherframe_sp = 0, sp, higherframe_bp = 0, bp = 0, ip = 0, higherframe_ip = 0;
	int unw_ret;
	int ret = 0;
	
	/* Get an initial snapshot. */
	unw_context_t unw_context;
	unw_ret = unw_getcontext(&unw_context);
	unw_init_local(&cursor, &unw_context);

	unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp);
#ifndef NDEBUG
	assert(__liballocs_get_sp() == (const void *) higherframe_sp);
#endif
	unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip);

	_Bool at_or_above_main = 0;
	do
	{
		// callee_ip = ip;
		// prev_saved_cursor is the cursor into the callee's frame 
		// prev_saved_cursor = saved_cursor; // FIXME: will be garbage if callee_ip == 0
		saved_cursor = cursor; // saved_cursor is the *current* frame's cursor

		/* First get the ip, sp and symname of the current stack frame. */
		unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
		unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0);
		// try to get the bp, but no problem if we don't
		unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &bp); 
		_Bool got_higherframe_bp = 0;
		
		ret = cb((void*) ip, (void*) sp, (void*) bp, arg);
		if (ret) return ret;
		
		int step_ret = unw_step(&cursor);
		if (step_ret > 0)
		{
			unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp); assert(unw_ret == 0);
			unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip); assert(unw_ret == 0);
			// try to get the bp, but no problem if we don't
			unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &higherframe_bp); 
			got_higherframe_bp = (unw_ret == 0) && higherframe_bp != 0;
		}
		else if (step_ret == 0)
		{
#define BEGINNING_OF_STACK ((uintptr_t) MAXIMUM_USER_ADDRESS)
			higherframe_sp = BEGINNING_OF_STACK;
			higherframe_bp = BEGINNING_OF_STACK;
			got_higherframe_bp = 1;
			higherframe_ip = 0x0;
		}
		else // step failure
		{
			// err = &__liballocs_err_stack_walk_step_failure;
			ret = -1;
			break;
		}
	} while (higherframe_sp != BEGINNING_OF_STACK);
#undef BEGINNING_OF_STACK
	
	return ret;
}

struct uniqtype *
__liballocs_get_or_create_union_type(unsigned n, /* struct uniqtype *first_memb_t, */...);
int __liballocs_add_type_to_block(void *block, struct uniqtype *t);

#ifdef __cplusplus
} // end extern "C"
#endif

#endif
