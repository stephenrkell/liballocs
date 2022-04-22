#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include "relf.h" /* for fake_dlsym, used by callee wrappers */

#ifndef NO_TLS
extern __thread void *__current_allocsite; // __attribute__((weak)); // defined by heap_index_hooks
extern __thread void *__current_allocfn;// __attribute__((weak)); // defined by heap_index_hooks
extern __thread size_t __current_allocsz;// __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_freeing;// __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_allocating;// __attribute__((weak)); // defined by heap_index_hooks
#else // DOUBLE HACK: make weak *definitions* here
void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
int __currently_allocating __attribute__((weak)); // defined by heap_index_hooks
#endif

int  __index_small_alloc(void *ptr, int level, unsigned size_bytes); // defined by heap_index_hooks
void __unindex_small_alloc(void *ptr, int level); // defined by heap_index_hooks

/* these are our per-allocfn caller wrappers */

#define type_for_argchar_z size_t
#define type_for_argchar_Z size_t

#define type_for_argchar_p void*
#define type_for_argchar_P void*

#define type_for_argchar_i int
#define type_for_argchar_I int

#define make_argdecl(num, c) \
	type_for_argchar_ ## c arg ## num

#define make_argname(num, c) \
	arg ## num

#define make_argtype(num, c) \
	type_for_argchar_ ## c

#define pre_realarg(num, c) \
	pre_realarg_ ## c (arg ## num)

#define post_realarg(num, c) \
	post_realarg_ ## c (arg ## num)

#ifndef do_caller_wrapper_init
#define do_caller_wrapper_init(name)
#endif

#ifndef do_arginit_z
#define do_arginit_z(argname)
#endif
#ifndef do_arginit_Z
#define do_arginit_Z(argname)
#endif
#ifndef do_arginit_p
#define do_arginit_p(argname)
#endif
#ifndef do_arginit_P
#define do_arginit_P(argname)
#endif
#ifndef do_arginit_i
#define do_arginit_i(argname)
#endif
#ifndef do_arginit_I
#define do_arginit_I(argname)
#endif

#ifndef pre_realarg_z
#define pre_realarg_z(argname)
#endif
#ifndef pre_realarg_Z
#define pre_realarg_Z(argname)
#endif
#ifndef pre_realarg_p
#define pre_realarg_p(argname)
#endif
#ifndef pre_realarg_P
#define pre_realarg_P(argname)
#endif
#ifndef pre_realarg_i
#define pre_realarg_i(argname)
#endif
#ifndef pre_realarg_I
#define pre_realarg_I(argname)
#endif

#ifndef pre_realcall
#define pre_realcall(callee, ...)
#endif

#ifndef post_realcall
#define post_realcall(callee, ...)
#endif

#ifndef post_realarg_z
#define post_realarg_z(argname)
#endif
#ifndef post_realarg_Z
#define post_realarg_Z(argname)
#endif
#ifndef post_realarg_p
#define post_realarg_p(argname)
#endif
#ifndef post_realarg_P
#define post_realarg_P(argname)
#endif
#ifndef post_realarg_i
#define post_realarg_i(argname)
#endif
#ifndef post_realarg_I
#define post_realarg_I(argname)
#endif

#ifndef do_caller_wrapper_fini
#define do_caller_wrapper_fini(name)
#endif

#ifndef do_ret_z
#define do_ret_z(name)
#endif
#ifndef do_ret_Z
#define do_ret_Z(name)
#endif
#ifndef do_ret_p
#define do_ret_p(name)
#endif
#ifndef do_ret_P
#define do_ret_P(name)
#endif
#ifndef do_ret_i
#define do_ret_i(name)
#endif
#ifndef do_ret_I
#define do_ret_I(name)
#endif
#ifndef do_ret_void
#define do_ret_void(name)
#endif

#ifndef do_arginit
#define do_arginit(num, c) do_arginit_ ## c ( arg ## num )
#endif

#define make_caller_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __real_ ## name ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_caller_wrapper_init(name) \
		arglist_nocomma_ ## name (do_arginit) \
		type_for_argchar_ ## retchar real_retval; \
		if (&__current_allocfn && !__current_allocfn) \
		{ \
			_Bool set_currently_allocating = 0; \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			/* only set the site if we don't have one already */ \
			if (!__current_allocsite) __current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &__real_ ## name; \
			__current_allocsz = size_arg_ ## name; \
			rev_arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
			arglist_nocomma_ ## name (post_realarg) \
			/* __current_alloclevel = 0; */ \
			/* zero the site now the alloc action is completed, even if it was already set */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
			if (set_currently_allocating) __currently_allocating = 0; \
			real_retval = retval; \
		} \
		else \
		{ \
			/* printf("&__current_allocfn: %p    ", &__current_allocfn); */ \
			/* if (&__current_allocfn) printf("__current_allocfn: %d", __current_allocfn); */ \
			rev_arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
			arglist_nocomma_ ## name (post_realarg) \
		} \
		do_caller_wrapper_fini(name) \
		do_ret_ ## retchar (name) \
		return real_retval; \
	}

/* For "size-only" caller wrappers, we leave the size *set* on return. 
 * "Action-only" and "normal" wrappers are the same case: 
 * */
#define make_size_caller_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __real_ ## name( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_caller_wrapper_init(name) \
		arglist_nocomma_ ## name (do_arginit) \
		type_for_argchar_ ## retchar real_retval; \
		if (&__current_allocsite && !__current_allocsite) \
		{ \
			_Bool set_currently_allocating = 0; \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			/* only set the site if we don't have one already */ \
			__current_allocsite = __builtin_return_address(0); \
			rev_arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
			arglist_nocomma_ ## name (post_realarg) \
			/* __current_alloclevel = 0; */ \
			if (set_currently_allocating) __currently_allocating = 0; \
			/* *leave* the site to be picked up the the next alloc action, in case we're a helper */ \
			real_retval = retval; \
		} \
		else { \
			rev_arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
			arglist_nocomma_ ## name (post_realarg) \
		} \
		do_caller_wrapper_fini(name) \
		do_ret_ ## retchar (name) \
		return real_retval; \
	}
	
/* This is like the normal alloc caller wrapper but we allow for the fact that 
 * we're a nested allocator. FIXME: split off the callee stuff. */
#define make_suballocator_alloc_caller_wrapper(name, retchar) \
	static int name ## _alloclevel; /* FIXME: thread-safety for access to this. */\
	type_for_argchar_ ## retchar __real_ ## name ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_caller_wrapper_init(name) \
		arglist_nocomma_ ## name (do_arginit) \
		_Bool have_caller_allocfn; \
		_Bool set_currently_allocating = 0; \
		if (&__current_allocfn && !__current_allocfn) /* This means we're not in any kind of alloc function yet */ \
		{ \
			set_currently_allocating = 0; \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			/* only set the site if we don't have one already */ \
			if (!__current_allocsite) __current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &__real_ ## name; \
			__current_allocsz = size_arg_ ## name; \
			have_caller_allocfn = 0; \
		}  else have_caller_allocfn = 1; \
		/* __current_alloclevel = 1; */ /* We're at least at level 1, i.e. below sbrk()/mmap(). pre_alloc increments this too */ \
		rev_arglist_nocomma_ ## name (pre_realarg) \
		pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
		void *real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		arglist_nocomma_ ## name (post_realarg) \
		if (/* __current_alloclevel > name ## _alloclevel*/ 0) \
		{ \
			/* Warn if we've already initialized our_alloclevel and saw a greater level */ \
			if (name ## _alloclevel != 0) \
			{ \
				warnx("Warning: __wrap_%s operating at alloclevel %d greater than previous level %d", \
					#name, name ## _alloclevel, /* __current_alloclevel */ 0); \
			} \
			name ## _alloclevel = 0/*__current_alloclevel*/; \
		} \
		if (&__index_small_alloc) \
		{ \
			int seen_alloclevel = __index_small_alloc(real_retval, /* name ## _alloclevel */ -1, __current_allocsz); \
			assert(name ## _alloclevel == 0 || seen_alloclevel == name ## _alloclevel); \
			if (name ## _alloclevel == 0) name ## _alloclevel = seen_alloclevel; \
		} \
		if (!have_caller_allocfn) \
		{ \
			/* __current_alloclevel = 0; */ \
			/* zero the site now the alloc action is completed, even if it was already set */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
		} \
		if (set_currently_allocating) __currently_allocating = 0; \
		do_caller_wrapper_fini(name) \
		do_ret_ ## retchar (name) \
		return real_retval; \
	}

#define make_free_caller_wrapper(name) /* HACK: assume void-returning for now */ \
	void __real_ ## name( arglist_ ## name (make_argdecl) ); \
	void __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_caller_wrapper_init(name) \
		arglist_nocomma_ ## name (do_arginit) \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		rev_arglist_nocomma_ ## name (pre_realarg) \
		pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
		__real_ ## name( arglist_ ## name (make_argname) ); \
		post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		arglist_nocomma_ ## name (post_realarg) \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
		do_caller_wrapper_fini(name) \
		do_ret_void(name) \
	}

#define make_suballocator_free_caller_wrapper(name, alloc_name) /* HACK: assume void-returning for now */ \
	void __real_ ## name( arglist_ ## name (make_argdecl) ); \
	void __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		assert(alloc_name ## _alloclevel); \
		do_caller_wrapper_init(name) \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		rev_arglist_nocomma_ ## name (pre_realarg) \
		pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
		__real_ ## name( arglist_ ## name (make_argname) ); \
		post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		arglist_nocomma_ ## name (post_realarg) \
		__unindex_small_alloc(ptr_arg_ ## name, alloc_name ## _alloclevel); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
		do_caller_wrapper_fini(name) \
	}

/* We also have some macros for generating callee wrappers. These are what 
 * do the indexing, at least logically. Being "callee" wrapper, we only 
 * generate them for objects that really do define the given allocator.
 * 
 * Logically, indexing operations belong here: we should actually invoke
 * the indexing hooks from this wrapper. Currently this isn't what happens.
 * Instead:
 * 
 * - "deep" allocators get the indexing done on the caller side (see above);
 *
 * - wrappers around the system malloc get hte indexing done in the preload 
 *   malloc;
 *
 * - objects which define their own malloc get the callee wrappers from
 *   liballocs_nonshared.a, which is using a mashup of this style of __wrap_*
 *   and the mallochooks stuff (in nonshared_hook_wrappers.c).
 *
 * So there is a gap to close off here: we should do the indexing here,
 * and only rely on the preload as a "special case" albeit the common case,
 * where libc supplies the malloc but is not itself built via us. We should
 * generate the "struct allocator" instance here. And we should dogfood these
 * macros to generate the actual preload stuff.
 *
 * Note that to do this properly, we need to distinguish actual alloc
 * functions from wrappers. Currently LIBALLOCS_ALLOC_FNS really refers
 * to wrappers; for your own actual allocators, they need to be a suballoc.
 *
 * See below for the alloc event stuff which is a step towards clearing this
 * mess up.
 */
#define make_callee_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __wrap___real_ ## name ( arglist_ ## name (make_argdecl) ) \
	{ \
		static type_for_argchar_ ## retchar (*real_ ## name)( arglist_ ## name (make_argtype) ); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, "__real_" #name); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, #name); /* probably infinite regress... */ \
		if (!real_ ## name) abort(); \
		type_for_argchar_ ## retchar real_retval; \
		real_retval = real_ ## name( arglist_ ## name (make_argname) ); \
		return real_retval; \
	}
#define make_void_callee_wrapper(name) \
	void __wrap___real_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		void (*real_ ## name)( arglist_ ## name (make_argtype) ); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, "__real_" #name); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, #name); /* probably infinite regress... */ \
		if (!real_ ## name) abort(); \
		real_ ## name( arglist_ ## name (make_argname) ); \
		return; \
	}

/* Protos for our hook functions. The mallocapi-to-hookapi glue comes
 * from a copy of alloc_events.c. */
#include "alloc_events.h"

/* hookapi-to-indexapi glue can be generated! */
/* FIXME: We could e.g. also parameterise
 * the generation by alignment, or some other parameter of the malloc,
 * so that the code is tailored to that malloc. */
#define ALLOC_ALLOCATOR_NAME(frag) frag ## _allocator
#define ALLOC_EVENT_INDEXING_DEFS2(allocator_namefrag, do_lifetime_policies) \
ALLOC_EVENT_ATTRIBUTES void ALLOC_EVENT(post_init)(void) {} \
ALLOC_EVENT_ATTRIBUTES \
void  \
ALLOC_EVENT(post_successful_alloc)(void *allocptr, size_t modified_size, size_t modified_alignment, \
		size_t requested_size, size_t requested_alignment, const void *caller) \
{ \
	__generic_malloc_index_insert(arena_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), allocptr), \
		allocptr /* == userptr */, requested_size, \
		__current_allocsite ? __current_allocsite : caller); \
} \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(pre_alloc)(size_t *p_size, size_t *p_alignment, const void *caller) \
{ \
	/* We increase the size by the amount of extra data we store,  \
	 * and possibly a bit more to allow for alignment.  */ \
	size_t orig_size = *p_size; \
	size_t size_to_allocate = CHUNK_SIZE_WITH_TRAILER(orig_size, struct extended_insert, void*); \
	assert(0 == size_to_allocate % ALIGNOF(void *)); \
	*p_size = size_to_allocate; \
} \
ALLOC_EVENT_ATTRIBUTES \
int ALLOC_EVENT(pre_nonnull_free)(void *userptr, size_t freed_usable_size) \
{ \
	if (do_lifetime_policies) /* always statically known but we can't #ifdef here */ \
	{ \
		lifetime_insert_t *lti = lifetime_insert_for_chunk(userptr); \
		*lti &= ~MANUAL_DEALLOCATION_FLAG; \
		if (*lti) return 1; /* Cancel free if we are still alive */ \
		__notify_free(userptr); \
	} \
	__generic_malloc_index_delete(arena_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), userptr/*, freed_usable_size*/); \
	return 0; \
} \
 \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(post_nonnull_free)(void *userptr) \
{} \
 \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(pre_nonnull_nonzero_realloc)(void *userptr, size_t size, const void *caller) \
{ \
	/* When this happens, we *may or may not be freeing an area* */ \
	/* -- i.e. if the realloc fails, we will not actually free anything. */ \
	/* However, when we were using trailers, and  */ \
	/* in the case of realloc()ing a *slightly smaller* region,  */ \
	/* the allocator might trash our insert (by writing its own data over it).  */ \
	/* So we *must* delete the entry first, */ \
	/* then recreate it later, as it may not survive the realloc() uncorrupted. */  \
	/* */ \
	/* Another complication: if we're realloc'ing a bigalloc, we might have to */ \
	/* move its children. BUT should the user ever do this? It's only sensible */ \
	/* to realloc a suballocated area if you know the realloc will happen in-place,  */ \
	/* i.e. if you're making it smaller (only).  */ \
	/*  */ \
	/* BUT some bigallocs are just big; they needn't have children.  */ \
	/* For those, does it matter if we delete and then re-create the bigalloc record? */ \
	/* I don't see why it should. */ \
	__generic_malloc_index_delete(arena_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), userptr/*, malloc_usable_size(ptr)*/); \
} \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(post_nonnull_nonzero_realloc)(void *userptr, \
	size_t modified_size,  \
	size_t old_usable_size, \
	const void *caller, void *new_allocptr) \
{ \
	/* FIXME: This requested size could be wrong. */ \
	/* The caller should give us the real requested size instead. */ \
	size_t requested_size = __current_allocsz ? __current_allocsz : \
		modified_size - sizeof(struct extended_insert); \
	__generic_malloc_index_reinsert_after_resize(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), \
		userptr, \
		modified_size, \
		old_usable_size, \
		requested_size, \
		caller, \
		new_allocptr \
	); \
} \
/* Now the allocator itself. */ \
extern struct allocator ALLOC_ALLOCATOR_NAME(allocator_namefrag); \
static struct big_allocation *ensure_big(void *addr, size_t size) \
{ \
	return __generic_malloc_ensure_big(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), addr, size); \
} \
static liballocs_err_t set_type(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *new_type) \
{ \
	return __generic_malloc_set_type(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), maybe_the_allocation, \
			obj, new_type); \
} \
static liballocs_err_t get_info( \
	void *obj, struct big_allocation *maybe_the_allocation, \
	struct uniqtype **out_type, void **out_base,  \
	unsigned long *out_size, const void **out_site) \
{ \
	return __generic_malloc_get_info(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), obj, maybe_the_allocation, \
		out_type, out_base, out_size, out_site); \
} \
 \
ALLOC_EVENT_ATTRIBUTES \
struct allocator ALLOC_ALLOCATOR_NAME(allocator_namefrag) = { \
	.name = #allocator_namefrag, \
	.get_info = get_info, \
	.is_cacheable = 1, \
	.ensure_big = ensure_big, \
	.set_type = set_type, \
	.free = (void (*)(struct allocated_chunk *)) free, \
};

#ifdef LIFETIME_POLICIES
#define __do_lp 1
#else
#define __do_lp 0
#endif
#define ALLOC_EVENT_INDEXING_DEFS(allocator_namefrag) \
  ALLOC_EVENT_INDEXING_DEFS2(allocator_namefrag, __do_lp)
