#include <stdlib.h>

extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
extern __thread void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
extern __thread size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
void __check_alloc_indexed(void *ptr) __attribute__((weak)); // defined by heap_index_hooks

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
			__check_alloc_indexed(retval); \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
			return retval; \
		} \
		else return __real_ ## name( arglist_ ## name (make_argname) ); \
	}

#define arglist_xcalloc(make_arg) make_arg(0, z), make_arg(1, Z)
