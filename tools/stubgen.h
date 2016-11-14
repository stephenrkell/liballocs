#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

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

/* these are our per-allocfn wrappers */

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

#define pre_realarg(num, c) \
	pre_realarg_ ## c (arg ## num)

#ifndef do_wrapper_init
#define do_wrapper_init(name)
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

#ifndef do_wrapper_fini
#define do_wrapper_fini(name)
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

#ifndef do_arginit
#define do_arginit(num, c) do_arginit_ ## c ( arg ## num )
#endif

#define make_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __real_ ## name ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_wrapper_init(name) \
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
			arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
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
			arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		} \
		do_wrapper_fini(name) \
		do_ret_ ## retchar (name) \
		return real_retval; \
	}

/* For "size-only" wrappers, we leave the size *set* on return. 
 * "Action-only" and "normal" wrappers are the same case: 
 * */
#define make_size_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __real_ ## name( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_wrapper_init(name) \
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
			arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
			/* __current_alloclevel = 0; */ \
			if (set_currently_allocating) __currently_allocating = 0; \
			/* *leave* the site to be picked up the the next alloc action, in case we're a helper */ \
			real_retval = retval; \
		} \
		else { \
			arglist_nocomma_ ## name (pre_realarg) \
			pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		} \
		do_wrapper_fini(name) \
		do_ret_ ## retchar (name) \
		return real_retval; \
	}
	
/* This is like the normal alloc wrapper but we allow for the fact that 
 * we're a nested allocator. */
#define make_suballocator_alloc_wrapper(name, retchar) \
	static int name ## _alloclevel; /* FIXME: thread-safety for access to this. */\
	type_for_argchar_ ## retchar __real_ ## name ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_wrapper_init(name) \
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
		arglist_nocomma_ ## name (pre_realarg) \
		pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
		void *real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
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
		do_wrapper_fini(name) \
		do_ret_ ## retchar (name) \
		return real_retval; \
	}

#define make_free_wrapper(name) /* HACK: assume void-returning for now */ \
	void __real_ ## name( arglist_ ## name (make_argdecl) ); \
	void __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		do_wrapper_init(name) \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		__real_ ## name( arglist_ ## name (make_argname) ); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
		do_wrapper_fini(name) \
	}

#define make_suballocator_free_wrapper(name, alloc_name) /* HACK: assume void-returning for now */ \
	void __real_ ## name( arglist_ ## name (make_argdecl) ); \
	void __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		assert(alloc_name ## _alloclevel); \
		do_wrapper_init(name) \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		arglist_nocomma_ ## name (pre_realarg) \
		pre_realcall( __real_ ## name, arglist_ ## name (make_argname) ) \
		__real_ ## name( arglist_ ## name (make_argname) ); \
		post_realcall ( __real_ ## name,  arglist_ ## name(make_argname) ) \
		__unindex_small_alloc(ptr_arg_ ## name, alloc_name ## _alloclevel); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
		do_wrapper_fini(name) \
	}
