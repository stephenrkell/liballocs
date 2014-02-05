#ifndef PMIRROR_ADDRMAP_H_
#define PMIRROR_ADDRMAP_H_

/* x86_64 only, for now */
#if !defined(__x86_64__) && !defined(X86_64) && !defined(i386) && !defined(__i386__)
#error Unsupported architecture.
#endif

#include <stdio.h> // hACK
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* we can't use these, because if we're compiled in a shared library, we 
 * get the *library's* end addr, whereas we want the executable's.
 */
extern int end;   // man page just uses "extern end", meaning "int"
extern int edata; // ditto
// this is what we use instead -- defined only in libcrunch (for now!)
extern void *__addrmap_executable_end_addr __attribute__((weak));
// use for fast "is it our stack?" check
extern unsigned long __addrmap_max_stack_size __attribute__((weak));

extern intptr_t startup_brk __attribute__((weak)); // defined in addrmap.c

enum object_memory_kind
{
	UNKNOWN,
	STATIC,
	STACK,
	HEAP,
	ANON,
	MAPPED_FILE
};

inline
const char *name_for_memory_kind (enum object_memory_kind k)__attribute__((always_inline));

inline
const char *name_for_memory_kind(enum object_memory_kind k)
{
	switch (k)
	{
		default:
		case UNKNOWN: return "unknown";
		case STATIC:  return "static";
		case STACK:   return "stack";
		case HEAP:    return "heap";
		case ANON:    return "anon";
	}
}
	
typedef enum object_memory_kind memory_kind;

/* To stay self-contained, we declare sbrk ourselves. */
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
	 * In particular, SHARED_LIBRARY_MIN_ADDRESS is not guaranteed, but 
	 * "seems to hold" for current ld-linux.so. */
	
	/* We use gcc __builtin_expect to hint that heap is the likely case. */ 
	
	uintptr_t addr = (uintptr_t) obj;
	
	/* If the address is below the end of the program BSS, it's static. 
	 * PROBLEM: on some systems, "&end" is 0, so we approximate it with 
	 * startup_sbrk. ALSO, we want the executable's 'end', so to get
	 * this under dynamic linking, we need to dlsym() it in our own. We
	 * don't do that here, but assume the host library does so by the time
	 * we're called (e.g. libcrunch does it in its initialization).
	 */
#ifndef USE_STARTUP_BRK 
	// ... try to use the simpler "end" approach
	if (__builtin_expect(&__addrmap_executable_end_addr != 0 && __addrmap_executable_end_addr != 0, 1)) 
	{
#endif
		// fprintf(stderr, "obj is %p, __addrmap_executable_end_addr is %p\n", obj, __addrmap_executable_end_addr);
		if (__builtin_expect(addr <  (uintptr_t) __addrmap_executable_end_addr, 0)) return STATIC;
		/* expect this to succeed, i.e. brk-delimited heap region is the common case. */
		if (__builtin_expect(addr >=  (uintptr_t) __addrmap_executable_end_addr && addr 
			< (uintptr_t) sbrk(0), 1)) return HEAP;
#ifndef USE_STARTUP_BRK
	}
	else 
	{
#endif
		/* imprecise startup_brk version -- always compiled in, but usually bypassed */
		if (__builtin_expect(addr < startup_brk, 0)) return STATIC;
		/* expect this to succeed, i.e. brk-delimited heap region is the common case. */
		if (__builtin_expect(addr >= startup_brk && addr < (uintptr_t) sbrk(0), 1)) return HEAP;
#ifndef USE_STARTUP_BRK
	}
#endif
	
	/* If the address is greater than RSP and less than top-of-stack
	 * and the distance from top-of-stack is less than the maximum stack size, 
	 * it's stack. */
	uintptr_t current_sp;
#if defined (X86_64) || (defined (__x86_64__))
	__asm__("movq %%rsp, %0\n" : "=r"(current_sp));
#else
	__asm__("movl %%esp, %0\n" : "=r"(current_sp));
#endif
	if (__builtin_expect(
		addr >= current_sp && addr < STACK_BEGIN 
		&& (!&__addrmap_max_stack_size || // it's weak
			(STACK_BEGIN - addr) < (signed long) __addrmap_max_stack_size), 0)) return STACK;
	
	/* FIXME: other threads' stacks! */

	/* It's between HEAP and STATIC. */
#ifdef USE_SHARED_LIBRARY_MIN_ADDRESS_HACK
#error "Please don't USE_SHARED_LIBRARY_MIN_ADDRESS_HACK"
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
