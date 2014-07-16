/* the functions are *not* weak -- they're defined in the noop library. 
 * we would like the noop library not to be necessary. */
int __liballocs_global_init (void);
/* This is not weak. */
void __assert_fail();

void __liballocs_unindex_stack_objects_below(void *);

extern inline void (__attribute__((always_inline,gnu_inline)) __liballocs_alloca_caller_frame_cleanup)(void *ignored);
extern inline void (__attribute__((always_inline,gnu_inline)) __liballocs_alloca_caller_frame_cleanup)(void *ignored)
{
	__liballocs_unindex_stack_objects_below(__builtin_frame_address(0));
}

/* alloca helpers */
extern inline void *(__attribute__((always_inline,gnu_inline)) __liballocs_alloca)(unsigned long size);
extern inline void *(__attribute__((always_inline,gnu_inline)) __liballocs_alloca)(unsigned long size)
{
	/* FIXME: insert heap trailer etc..
	 * Basically we have to do everything that  */
	return __builtin_alloca(size);
}


void __liballocs_unindex_stack_objects_below(void *);

extern _Bool __liballocs_is_initialized __attribute__((weak));
