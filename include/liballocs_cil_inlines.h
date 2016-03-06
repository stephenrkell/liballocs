/* The functions are *not* weak -- they're defined in the noop library. 
 * we would like the noop library not to be necessary. */
int __liballocs_global_init (void);
/* This is not weak. */
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
/* Heap index hooks -- these also aren't weak, for the usual reason. */
void __alloca_allocator_notify(void *new_userchunkaddr, unsigned long modified_size, 
		unsigned long *frame_counter, const void *caller, 
		const void *caller_sp, const void *caller_bp);
void __liballocs_index_delete(void*);
struct uniqtype; /* forward decl */

/* This *must* match the size of 'struct insert' in heap_index! But we don't
 * include that header right now, to avoid perturbing the inclusion order
 * of the rest of this translation unit. */
#ifndef ALLOCA_TRAILER_SIZE
#define ALLOCA_TRAILER_SIZE (sizeof (void*))
#endif

/* HACK: copied from memtable.h. */
/* Thanks to Martin Buchholz -- <http://www.wambold.com/Martin/writings/alignof.html> */
#define ALIGNOF(type) offsetof (struct { char c; type member; }, member)
#define PAD_TO_ALIGN(n, a) 	((0 == ((n) % (a))) ? (n) : (n) + (a) - ((n) % (a)))

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
extern inline const void *(__attribute__((always_inline,gnu_inline)) __liballocs_get_sp)(void);
extern inline const void *(__attribute__((always_inline,gnu_inline)) __liballocs_get_sp)(void)
{
	unsigned long our_sp;
	#ifdef UNW_TARGET_X86
		__asm__ volatile ("movl %%esp, %0\n" :"=r"(our_sp));
	#else // assume X86_64 for now
		__asm__ volatile ("movq %%rsp, %0\n" : "=r"(our_sp));
	#endif
	return (const void*) our_sp;
}

extern inline const void *(__attribute__((always_inline,gnu_inline)) __liballocs_get_bp)(void);
extern inline const void *(__attribute__((always_inline,gnu_inline)) __liballocs_get_bp)(void)
{
	return (const void *) __builtin_frame_address(0);
}

extern inline void *(__attribute__((always_inline,gnu_inline)) __liballocs_alloca)(unsigned long size, unsigned long *frame_counter, void *caller);
extern inline void *(__attribute__((always_inline,gnu_inline)) __liballocs_alloca)(unsigned long size, unsigned long *frame_counter, void *caller)
{
	/* Insert heap trailer etc..
	 * Basically we have to do everything that our malloc hooks, allocator wrappers
	 * and heap indexing code does. ARGH. Maintenance nightmare.... 
	 * 
	 * AND only do the indexing things if liballocs is preloaded. Otherwise.... */
	unsigned long chunk_size = PAD_TO_ALIGN(size + ALLOCA_TRAILER_SIZE, ALLOCA_TRAILER_SIZE);
	void *alloc = __builtin_alloca(ALLOCA_HEADER_SIZE + chunk_size);
	/* write the usable size into the first word, then return the rest. */
	*(unsigned long *)alloc = chunk_size;
	
	/* We add only the "usable size" part, because that is what the heap index code
	 * can see, and that is the code that will be consuming this value. */
	*frame_counter += chunk_size;
	
	/* Note that we pass the caller directly; __current_allocsite is not required. */
	void *userptr = (char*) alloc + ALLOCA_HEADER_SIZE;
	__alloca_allocator_notify(userptr, chunk_size, frame_counter, caller,
		__liballocs_get_sp(), __liballocs_get_bp());
	
	return userptr;
}


void __liballocs_unindex_stack_objects_below(void *);

extern _Bool __liballocs_is_initialized __attribute__((weak));
