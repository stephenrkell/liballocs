#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#ifndef NO_TLS
extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
extern __thread void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
extern __thread size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
#else // DOUBLE HACK: make weak *definitions* here
void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
#endif

int  __index_deep_alloc(void *ptr, int level, unsigned size_bytes); // defined by heap_index_hooks (and libcrunch_noop)
void __unindex_deep_alloc(void *ptr, int level); // defined by heap_index_hooks (and libcrunch_noop)

/* these are our per-allocfn wrappers */

#define type_for_argchar_z size_t
#define type_for_argchar_Z size_t

#define type_for_argchar_p void*
#define type_for_argchar_P void*

#define type_for_argchar_i int
#define type_for_argchar_I int

#define make_argdecl(num, char) \
	type_for_argchar_ ## char arg ## num

#define make_argname(num, char) \
	arg ## num

#define make_wrapper(name, retchar) \
	type_for_argchar_ ## retchar ( __attribute__((weak)) __real_ ## name ) ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		if (&__current_allocsite && !__current_allocsite) \
		{ \
			__current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &__real_ ## name; \
			__current_allocsz = size_arg_ ## name; \
			void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			/* __current_alloclevel = 0; */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
			return retval; \
		} \
		else return __real_ ## name( arglist_ ## name (make_argname) ); \
	}
	
/* This is like the normal alloc wrapper but we allow for the fact that 
 * we're a nested allocator. */
#define make_suballocator_alloc_wrapper(name, retchar) \
	static int name ## _alloclevel; /* FIXME: thread-safety for access to this. */\
	type_for_argchar_ ## retchar ( __attribute__((weak)) __real_ ## name ) ( arglist_ ## name (make_argdecl) ); \
	type_for_argchar_ ## retchar __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		_Bool have_caller_alloc; \
		if (&__current_allocsite && !__current_allocsite) /* This means we're not in any kind of alloc function yet */ \
		{ \
			__current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &__real_ ## name; \
			__current_allocsz = size_arg_ ## name; \
			have_caller_alloc = 0; \
		}  else have_caller_alloc = 1; \
		/* __current_alloclevel = 1; */ /* We're at least at level 1, i.e. below sbrk()/mmap(). pre_alloc increments this too */ \
		void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		if (/* __current_alloclevel > name ## _alloclevel*/ 0) \
		{ \
			/* Warn if we've already initialized our_alloclevel and saw a greater level */ \
			if (name ## _alloclevel != 0) \
			{ \
				fprintf(stderr, "Warning: __wrap_%s operating at alloclevel %d greater than previous level %d\n", \
					#name, name ## _alloclevel, /* __current_alloclevel */ 0); \
			} \
			name ## _alloclevel = 0/*__current_alloclevel*/; \
		} \
		int seen_alloclevel = __index_deep_alloc(retval, /* name ## _alloclevel */ -1, __current_allocsz); \
		assert(name ## _alloclevel == 0 || seen_alloclevel == name ## _alloclevel); \
		if (name ## _alloclevel == 0) name ## _alloclevel = seen_alloclevel; \
		if (!have_caller_alloc) \
		{ \
			/* __current_alloclevel = 0; */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
		} \
		return retval; \
	}

#define make_free_wrapper(name) /* HACK: assume void-returning for now */ \
	void ( __attribute__((weak)) __real_ ## name ) ( arglist_ ## name (make_argdecl) ); \
	void __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		__real_ ## name( arglist_ ## name (make_argname) ); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
	}

#define make_suballocator_free_wrapper(name, alloc_name) /* HACK: assume void-returning for now */ \
	void ( __attribute__((weak)) __real_ ## name ) ( arglist_ ## name (make_argdecl) ); \
	void __wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		assert(alloc_name ## _alloclevel && "should have observed alloclevel of corresponding suballoc fn"); \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		__real_ ## name( arglist_ ## name (make_argname) ); \
		__unindex_deep_alloc(ptr_arg_ ## name, alloc_name ## _alloclevel); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
	}
