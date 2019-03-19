#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include "relf.h" /* for fake_dlsym, used by callee wrappers */

#ifndef NO_TLS
extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
extern __thread void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
extern __thread size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_allocating __attribute__((weak)); // defined by heap_index_hooks
#else // DOUBLE HACK: make weak *definitions* here
void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
int __currently_allocating __attribute__((weak)); // defined by heap_index_hooks
#endif

int  __index_small_alloc(void *ptr, int level, unsigned size_bytes); // defined by heap_index_hooks
void __unindex_small_alloc(void *ptr, int level); // defined by heap_index_hooks

struct liballocs_err;
typedef struct liballocs_err *liballocs_err_t;
extern struct liballocs_err __liballocs_err_unindexed_heap_object;
struct big_allocation;
struct uniqtype;
liballocs_err_t __generic_malloc_set_type(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *new_type);
liballocs_err_t __generic_malloc_set_site(struct big_allocation *maybe_the_allocation, void *obj, const void *new_site);
extern struct uniqtype __uniqtype____EXISTS1__1;

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

#ifdef TRACE_ALLOC_WRAPPERS
#define _ALLOC_WRAPPERS_TRACE( x... ) warnx(##args)
#else
#define _ALLOC_WRAPPERS_TRACE( x... )
#endif

#define make_caller_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __real_ ## name ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_caller_wrapper_init(name) \
		arglist_nocomma_ ## name (do_arginit) \
		type_for_argchar_ ## retchar real_retval; \
		_Bool set_currently_allocating = 0; \
		if (&__currently_allocating && !__currently_allocating) { \
			__currently_allocating = 1; \
			set_currently_allocating = 1; \
		} \
		/* only set the site if we don't have one already */ \
		if (!__current_allocsite) { \
			__current_allocsite = __builtin_return_address(0); \
			_ALLOC_WRAPPERS_TRACE("In caller-side wrapper of %s, latched __current_allocsite %p since we didn't have one", #name, __current_allocsite); \
		} else { \
			_ALLOC_WRAPPERS_TRACE("In caller-side wrapper of %s, did not latch __current_allocsite as we had one already", #name); \
		} \
		void *saved_allocfn = __current_allocfn; \
		size_t saved_allocsz = __current_allocsz; \
		__current_allocfn = &__real_ ## name; \
		__current_allocsz = size_arg_ ## name; \
		rev_arglist_nocomma_ ## name (pre_realarg) \
		pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
		void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		arglist_nocomma_ ## name (post_realarg) \
		/* __current_alloclevel = 0; */ \
		/* zero the site now the alloc action is completed, even if it was already set */ \
		if (__current_allocsite) { \
			/* This is our hint that the real allocator didn't get called */ \
			/* (e.g. a chunk-caching wrapper) or didn't heed our metadata */ \
			/* (e.g. if uninstrumented). We make another call to push */ \
			/* the metadata at liballocs more directly. FIXME: we should */ \
			/* really know which allocator we are stubbing for, rather than */ \
			/* hard-code the generic malloc here. */ \
			__generic_malloc_set_site(NULL, retval, __current_allocsite); \
			_ALLOC_WRAPPERS_TRACE("In caller-side wrapper of #s, zeroing __current_allocsite (was %p) consumed by %s", #name, __current_allocsite); \
			__current_allocsite = (void*)0; \
		} \
		__current_allocfn = saved_allocfn; \
		__current_allocsz = saved_allocsz; \
		if (set_currently_allocating) __currently_allocating = 0; \
		real_retval = retval; \
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
		void *saved_allocfn = __current_allocfn; \
		unsigned long saved_allocsz = __current_allocsz; \
		_Bool set_currently_allocating = 0; \
		set_currently_allocating = 0; \
		if (&__currently_allocating && !__currently_allocating) { \
			__currently_allocating = 1; \
			set_currently_allocating = 1; \
		} \
		/* only set the site if we don't have one already */ \
		if (!__current_allocsite) __current_allocsite = __builtin_return_address(0); \
		__current_allocfn = &__real_ ## name; \
		__current_allocsz = size_arg_ ## name; \
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
		if (saved_caller_allocfn) \
		{ \
			/* __current_alloclevel = 0; */ \
			/* zero the site now the alloc action is completed, even if it was already set */ \
			__current_allocsite = (void*)0; \
		} \
		__current_allocfn = current_allocfn; \
		__current_allocsz = current_allocsz; \
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
		/* FIXME: do something about clearing the metadata, in the chunk-caching case. */ \
		/* We can do this before the real free, so that we know the chunk is valid. */ \
		/* For now, perhaps as simple as a set_type(NULL) call on __generic_malloc? */ \
		__generic_malloc_set_type((void*)0, &__uniqtype____EXISTS1__1, /* HACK arglist_ ## name (make_argname)*/ arg0 ); \
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
