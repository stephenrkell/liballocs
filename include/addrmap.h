#ifndef PMIRROR_ADDRMAP_H_
#define PMIRROR_ADDRMAP_H_

/* x86_64 only, for now */
#if !defined(__x86_64__) && !defined(X86_64) && !defined(i386) && !defined(__i386__)
#error Unsupported architecture.
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned long end; // NOTE: man page just uses "extern end", meaning "int"!
enum object_memory_kind
{
	UNKNOWN,
	STATIC,
	STACK,
	HEAP,
	ANON
};
	
typedef enum object_memory_kind memory_kind;

/* To stay self-contained, we define our own sbrk proto. */
void *sbrk(intptr_t incr);

#if defined (X86_64) || (defined (__x86_64__))
#define STACK_BEGIN 0x800000000000UL
#else
#define STACK_BEGIN 0xc0000000UL
#endif

/* HACK: on my system, shared libraries are always loaded at the top,
 * from 0x7eff00000000....
 * EXCEPT when we run ldd from a Makefile running dash, in which case
 * they show up at 0x2aaaa00000000+delta, which is weird. I should really
 * check the source of ld-linux.so, but for now, go with the lower addr. */
#if defined (X86_64) || (defined (__x86_64__))
#define SHARED_LIBRARY_MIN_ADDRESS 0x2aaa00000000UL
#else
#define SHARED_LIBRARY_MIN_ADDRESS 0xb0000000
#endif
inline enum object_memory_kind get_object_memory_kind(const void *obj)
{
	/* For x86-64, we do this in a rough-and-ready way. 
	 * In particular, SHARED_LIBRARY_MIN_ADDRESS is not guaranteed. 
	 * However, we can detect violations of this statically using our ldd output. */
	
	/* We use gcc __builtin_expect to hint that heap is the likely case. */ 
	
	unsigned long addr = (unsigned long) obj;
	
	/* If the address is below the end of the program BSS, it's static. */
	if (__builtin_expect(addr < end, 0)) return STATIC;
	
	/* If the address is greater than RSP and less than top-of-stack,
	 * it's stack. */
	unsigned long current_sp;
#if defined (X86_64) || (defined (__x86_64__))
	__asm__("movq %%rsp, %0\n" : "=r"(current_sp));
#else
	__asm__("movl %%esp, %0\n" : "=r"(current_sp));
#endif
	if (__builtin_expect(addr >= current_sp && addr < STACK_BEGIN, 0)) return STACK;
	
	/* It's between HEAP and STATIC. */
#ifdef USE_SHARED_LIBRARY_MIN_ADDRESS_HACK
	/* HACK: on systems where shared libs are loaded far away from heap regions, 
	 * use a fixed boundary at SHARED_LIBRARY_MIN_ADDRESS. */
	if (__builtin_expect(addr >= SHARED_LIBRARY_MIN_ADDRESS, 0)) return STATIC;
	return HEAP;
#else
	/* We don't know. The caller has to fall back to some more expensive method. */
	return UNKNOWN;
#endif
}

#ifdef __cplusplus
} // end extern "C"
#endif

#endif
