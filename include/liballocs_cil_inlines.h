/* The functions are *not* weak -- they're defined in the noop library. 
 * we would like the noop library not to be necessary. */
int __liballocs_global_init (void);
/* This is not weak. */
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
/* Heap index hooks -- these also aren't weak, for the usual reason. */
void __liballocs_index_insert(void *new_userchunkaddr, unsigned long modified_size, 
		const void *caller);
void __liballocs_index_delete(void*);
struct uniqtype; /* forward decl */

/* This *must* match the size of 'struct insert' in heap_index! But we don't
 * include that header right now, to avoid perturbing the inclusion order
 * of the rest of this translation unit. */
#ifndef ALLOCA_TRAILER_SIZE
#define ALLOCA_TRAILER_SIZE (sizeof (void*))
#endif

/* This *must* match the treatment of "early_malloc"'d chunks in malloc_hook_stubs.c. 
 * */
#ifndef ALLOCA_HEADER_SIZE
#define ALLOCA_HEADER_SIZE (sizeof (unsigned long))
#endif

#ifndef NO_TLS
extern __thread void *__current_allocsite __attribute__((weak));
#else
extern void *__current_allocsite __attribute__((weak));
#endif

void __liballocs_unindex_stack_objects_counted_by(unsigned long *, void *frame_addr);

extern inline void (__attribute__((always_inline,gnu_inline)) __liballocs_alloca_caller_frame_cleanup)(void *counter);
extern inline void (__attribute__((always_inline,gnu_inline)) __liballocs_alloca_caller_frame_cleanup)(void *counter)
{
	__liballocs_unindex_stack_objects_counted_by((unsigned long *) counter, __builtin_frame_address(0));
}

/* alloca helpers */
extern inline void *(__attribute__((always_inline,gnu_inline)) __liballocs_alloca)(unsigned long size, unsigned long *frame_counter);
extern inline void *(__attribute__((always_inline,gnu_inline)) __liballocs_alloca)(unsigned long size, unsigned long *frame_counter)
{
	/* Insert heap trailer etc..
	 * Basically we have to do everything that our malloc hooks, allocator wrappers
	 * and heap indexing code does. ARGH. Maintenance nightmare.... 
	 * 
	 * AND only do the indexing things if liballocs is preloaded. Otherwise.... */
	void *alloc = __builtin_alloca(ALLOCA_HEADER_SIZE + size + ALLOCA_TRAILER_SIZE);
	/* write the usable size into the first word, then return the rest. */
	*(unsigned long *)alloc = size + ALLOCA_HEADER_SIZE;
	
	/* We add only the "usable size" part, because that is what the heap index code
	 * can see, and that is the code that will be consuming this value. */
	*frame_counter += size + ALLOCA_TRAILER_SIZE;
	
	void *userptr = (char*) alloc + ALLOCA_HEADER_SIZE;
	
	void *caller;
	if (&__current_allocsite) caller = __current_allocsite;
	else caller = (void*) 0;
	
	__liballocs_index_insert(userptr, size + ALLOCA_TRAILER_SIZE, caller);
	
	if (&__current_allocsite) __current_allocsite = (void*)0;
	
	return userptr;
}


void __liballocs_unindex_stack_objects_below(void *);

extern _Bool __liballocs_is_initialized __attribute__((weak));
