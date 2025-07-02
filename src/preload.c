/* What we don't (yet) trap: 
 * 
 *  fork(), vfork(), clone()     -- FIXME: do we care about the fork-without-exec case?
 */


#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <assert.h>
#include <sys/types.h>
/* Some libc versions of mman.h will create 'mmap' with linkage name 'mmap64', which
 * messes with our ability to define/override both 'mmap' and 'mmap64'. It's important for
 * preload coverage that we do this, since there is no guarantee that some other DSO
 * in the link does not use plain 'mmap', say. */
// #include <sys/mman.h>
#define MAP_FAILED ((void*)-1)
#ifdef __linux__
// HACK: just include the bits
#define _SYS_MMAN_H
#include <bits/mman-shared.h>
#else
#error "Unrecognised operating system (need to know MREMAP_FIXED)"
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "raw-syscalls-defs.h" /* declares raw_write, no? */
#include "librunt.h"
#include "relf.h"
#include "liballocs_private.h"
#include "allocmeta.h"

/* On some glibcs,
 * including signal.h breaks asm includes, so just supply the decls here. */
#ifdef AVOID_LIBC_SIGNAL_H_
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
struct __libc_sigaction;
int sigaction(int signum, const struct __libc_sigaction *act,
             struct __libc_sigaction *oldact);
#else
#include <signal.h>
#define __libc_sigaction sigaction
#endif

/* NOTE that our wrappers are all init-on-use. This is because 
 * we might get called very early, and even if we're not trying to
 * intercept the early calls, we still need to be able to delegate. 
 * For that, we need our underyling function pointers. */

/* In addition to librunt's preload wrappers, we add some mmap-flavoured
 * ones.
 *
 * NOTE / HACK / glibc-specificity: we know about two different mmap entry 
 * points: mmap and mmap64. 
 * 
 * on x86-64, mmap64 has 8-byte size_t length and 8-byte off_t offset.
 * on x86-64, mmap has 8-byte size_t length and 8-byte off_t offset.
 * So I think the differences are only on 32-bit platforms. 
 * For now, just alias mmap64 to mmap. */

extern void *__curbrk;
/* Stop gcc from tail-call-opt'ing the __mallochooks_ call, because 
 * it has made it impossible to debug linkage problems. */
#pragma GCC push_options
#pragma GCC optimize("no-optimize-sibling-calls")
size_t malloc_or_alloca_usable_size(void *ptr)
{
	/* Since generic_malloc_index addresses can be on the stack too, 
	 * in the case of alloca, we need to intercept this case
	 * and handle it appropriately. 
	 *
	 * We used to use this function all the time in generic_malloc_index.
	 * But now it's just a debugging utility.
	 * The generic indexing inlines are now parameterised by a size-getting
	 * function appropriate to the allocator.
	 * We also override malloc_usable_size, below, to return whatever
	 * the allocator says is the usable size (often smaller than what
	 * malloc_usable_size() would return, owing to inserts).
	 * 
	 * How can we detect the stack case quickly?
	 * We could just ask the pageindex.
	 * 
	 * If we wanted a faster-but-less-general common case, 
	 * - If ptr is on the same page as our thread's rsp, 
	 *   it's definitely a stack pointer.
	 * - If ptr is within MAXIMUM_STACK_SIZE of our thread's rsp, 
	 *   it's *probably* a stack ptr, but to be certain it seems
	 *   that we still have to consult the l0 index.
	 * - Can we *rule out* the stack case quickly?
	 *   HMM... all this is only using the same tricks we have in 
	 *   get_object_memory_kind, so use that.
	 * 
	 */
	void *sp;
	 #ifdef UNW_TARGET_X86
		__asm__ ("movl %%esp, %0\n" :"=r"(sp));
	#else // assume X86_64 for now
		__asm__("movq %%rsp, %0\n" : "=r"(sp));
	#endif

	/* The only time a stack address (any suballocator) can be valid for us
	 * is if the arg is the base of an alloca. If so, we stored the size
	 * one word below the base. */
	// FIXME: none of this should be necessary. Use a separate memtable for alloca?
	// NOTE: this isn't as unsound as it looks, since our mmap nudger won't ever place
	// a new mapping here
#define INITIAL_STACK_MINIMUM_SIZE 81920
	_Bool is_definitely_not_stack = (char*) ptr <= (char*) __curbrk
			|| 
			big_allocations[pageindex[(uintptr_t) ptr >> LOG_PAGE_SIZE]].allocated_by
				== &__mmap_allocator
			||
			big_allocations[pageindex[(uintptr_t) ptr >> LOG_PAGE_SIZE]].allocated_by
				== &__global_malloc_allocator
			;
	_Bool is_definitely_stack = 
		(   // anywhere on the initial stack
			/* Austin-style unsigned wrap-around hack... */
			((uintptr_t) __top_of_initial_stack - (uintptr_t) ptr)
			< (__stack_lim_cur == RLIM_INFINITY ? INITIAL_STACK_MINIMUM_SIZE : __stack_lim_cur)
		)
		|| // same page on the current stack
		(
			(((uintptr_t) ptr & ~(PAGE_SIZE - 1))
			    == ((uintptr_t) sp & ~(PAGE_SIZE - 1)))
		);
	
	if (is_definitely_stack)
	{
		return __alloca_usable_size(ptr);
	}
	if (is_definitely_not_stack)
	{
		return malloc_usable_size(ptr);
	}
	return (__liballocs_get_allocator_upper_bound(ptr) == &__stack_allocator)
		? __alloca_usable_size(ptr)
		: malloc_usable_size(ptr);
}
#pragma GCC pop_options

/* Cross-DSO calls to malloc_usable_size() land here.
 * FIXME: libmallochooks should really hook this. We need a way
 * to handle the case where the exe includes its own malloc
 * defining malloc_usable_size. */
size_t malloc_usable_size(void *ptr)
{
	/* How do we get the allocator? We can't ask for the deepest
	 * allocator because malloc chunks can be suballocated.
	 * Instead we query the address *one before*. This should
	 * get us the parent allocator -- we assume that a malloc
	 * cannot allocate the very first address in its arena.
	 *
	 * How do we know the allocator we get is a malloc? Since
	 * the 'struct allocator's functions are generated wrappers
	 * around the inlines (which have a wider argument signature)
	 * this is non-trivial. So let's not do it. Just call a size
	 * function if one exists.
	 */
	struct big_allocation *b = __lookup_deepest_bigalloc((void*)(((uintptr_t) ptr) - 1));
	if (!b) return (size_t) -1;
	if (!b->suballocator) return (size_t) -1;
	if (!b->suballocator->get_size) return (size_t) -1;
	return b->suballocator->get_size(ptr);
}

extern int _etext;
static 
_Bool
is_self_call(const void *caller)
{
	static char *our_load_addr;
	if (!our_load_addr) our_load_addr = (char*) get_highest_loaded_object_below(is_self_call)->l_addr;
	if (!our_load_addr) abort(); /* we're supposed to be preloaded, not executable */
	static char *text_segment_end;
	if (!text_segment_end) text_segment_end = get_local_text_segment_end();
	return ((char*) caller >= our_load_addr && (char*) caller < text_segment_end);
}

/* Libraries that extend us can define this to control mmap placement policy. */
void __liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller) __attribute__((weak));

/* For most of the process we rely on symbol overriding to observe mmap calls. 
 * However, we have another trick for ld.so and libc mmap syscalls.
 * We *never* delegate to the underlying (RTLD_NEXT) mmap; we always do it
 * ourselves. This ensures that the handling is an either-or; exactly one of these
 * paths (preload or systrap) should be hit. We must take care to do the
 * (logically) same things in both. */
#undef mmap
void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	/* We always nudge, even for mmaps we do ourselves. This is because 
	 * the nudge function implements some global placement policy that even
	 * our memtables must adhere to. */
	if (&__liballocs_nudge_mmap)
	{
		__liballocs_nudge_mmap(&addr, &length, &prot, &flags, &fd, &offset, __builtin_return_address(0));
	}

	void *ret = raw_mmap(addr, length, prot, flags, fd, offset);
	if (MMAP_RETURN_IS_ERROR(ret))
	{
		errno = -(int) (size_t) ret;
		ret = MAP_FAILED;
	}
	if (length > BIGGEST_BIGALLOC)
	{
		// skip hooking logic
		return ret;
	}

	/* We want to hook our own mmaps. However,
	 *
	 * - The mmap allocator does call malloc itself, for its metadata, so we might
	 * become reentrant at this point, which we *don't* want. E.g. since
	 * right now we haven't yet returned the mapping we just made
	 * to the malloc that is calling us, doing another private malloc
	 * will reentrantly do another mmap.
	 *
	 * Current approach: mmap allocator tests for private malloc active, and 
	 * just does a more minimalist metadata-free bigalloc creation in such cases.
	 * FIXME: whatever we decide to do here, also do it for mremap and munmap
	 *
	 * Note that we're
	 * not in a signal handler here; this path is only for LD_PRELOAD-based hooking,
	 * and we don't trap our own mmap syscalls, so things are slightly less hairy than
	 * they otherwise might be.
	 *
	 * However, what about early calls? When !__liballocs_systrap_is_initialized,
	 * we will have to later do a /proc/.../maps pass to fill in bigallocs. If we
	 * hook our own calls now, we will get finer-grained partial information
	 * which we then can't reconcile with the coarser-grained full information
	 * that we get when walking /proc. E.g. the /proc line will merge two adjacent
	 * anonymous mappings even though one of ours will have 'caller' set so will
	 * not be mergeable by the mapping_sequence code.
	 *
	 * We want to trap the early mmap self-calls because we need to see the bigalloc
	 * that our private malloc
	 */

	if (!MMAP_RETURN_IS_ERROR(ret))
	{
		if (!__liballocs_systrap_is_initialized) return ret; // HACK
		(__liballocs_systrap_is_initialized
			? __mmap_allocator_notify_mmap
			: __mmap_allocator_notify_mmap/*_no_private_malloc*/)
		(ret, addr, length, prot, flags, fd, offset, __builtin_return_address(0));
	}
	else
	{
		errno = -(intptr_t)ret;
		ret = (void*) -1;
	}
	return ret;
}

// XXX: mysterious error with GCC 10.2.1: `mmap64' aliased to undefined symbol `mmap'
// I thought this could be caused by a glibc header #define-ing mmap as mmap64, but
// it's actually caused by sys/mman.h having a declaration of mmap with __asm__("mmap64")
// (made by __REDIRECT_NTH, where "NTH" means "nothrow"). We have hacked around this
// above by not including sys/mman.h, so hopefully this will no longer emerge.
void *mmap64(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset) __attribute__((alias("mmap")));

int munmap(void *addr, size_t length)
{
	static int (*orig_munmap)(void *, size_t);
	if (!orig_munmap)
	{
		orig_munmap = dlsym(RTLD_NEXT, "munmap");
		assert(orig_munmap);
	}
	
	if (!__liballocs_systrap_is_initialized)
	{
		return orig_munmap(addr, length);
	}
	else
	{
		int ret = orig_munmap(addr, length);
		if (ret == 0)
		{
			__mmap_allocator_notify_munmap(addr, length, __builtin_return_address(0));
		}
		return ret;
	}
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ... /* void *new_address */)
{
	static void *(*orig_mremap)(void *, size_t, size_t, int, ...);
	va_list ap;
	if (!orig_mremap)
	{
		orig_mremap = dlsym(RTLD_NEXT, "mremap");
		assert(orig_mremap);
	}
	
	void *new_address = MAP_FAILED;
	if (flags & MREMAP_FIXED)
	{
		va_start(ap, flags);
		new_address = va_arg(ap, void *);
		va_end(ap);
	}
	
#define DO_ORIG_CALL ((flags & MREMAP_FIXED)  \
			? orig_mremap(old_addr, old_size, new_size, flags, new_address) \
			: orig_mremap(old_addr, old_size, new_size, flags))
	
	if (!__liballocs_systrap_is_initialized)
	{
		return DO_ORIG_CALL;
	}
	else
	{
		void *ret = DO_ORIG_CALL;
		if (ret != MAP_FAILED)
		{
			__mmap_allocator_notify_mremap_after(ret, old_addr, old_size, 
					new_size, flags, new_address, __builtin_return_address(0));
		}
		return ret;
	}
#undef orig_call
}

static void init(void) __attribute__((constructor));
static void init(void)
{
	/* We have to initialize these in a constructor, because if we 
	 * do it lazily we might find that the first call is in an 
	 * "avoid libdl" context. HMM, but then we just use fake_dlsym
	 * to get the original pointer and call that. so doing it lazily
	 * is okay, it seems. */
	// write_string("Hello from preload init!\n");
	
}

#ifndef NDEBUG
static void write_decint(int val)
{
	char a;
	_Bool written = 0;
	a = '0' + ((val / 1000000000) % 10); if (a != '0') { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 100000000) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 10000000) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 1000000) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 100000) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 10000) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 1000) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 100) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + ((val / 10) % 10); if (a != '0' || written) { raw_write(2, &a, 1); written = 1; }
	a = '0' + (val % 10); raw_write(2, &a, 1);
}

void abort(void) __attribute__((visibility("protected")));
void abort(void)
{
	/* Give ourselves time to attach a debugger. */
	write_string("Aborting program ");
	raw_write(2, get_exe_command_basename(), strlen(get_exe_command_basename()));
	write_string(", pid ");
	int pid = raw_getpid();
	write_decint(pid);
	write_string(", from address ");
	write_ulong((unsigned long) __builtin_return_address(0));
	write_string(", in 10 seconds\n");

	sleep(10);
	raw_kill(pid, 6);
	/* What happens now? */
	for (;;);
}
/* We need our own __assert_fail that we can be sure does not mmap,
 * to avoid reentrancy problems that hinder debugging of assertion
 * failures. glibc's version does dcgettext which does mmap. */
__attribute__((visibility("protected")
#if __STDC_VERSION__ >= 201112L
,__noreturn__
#endif
))
#if __STDC_VERSION__ >= 201112L
_Noreturn
#endif
/* musl's 'line' is signed, but glibc's is unsigned. It doesn't matter
 * in practice but the compiler will throw a fit. */
void
__assert_fail (
const char *assertion, const char *file,
#if !defined(__musl__) && !defined(ASSERT_FAIL_LINE_SIGNED)
	unsigned
#endif
	int line, const char *function
)
{
	write_string("Assertion failed at file ");
	raw_write(2, file, strlen(file));
	write_string(":");
	write_decint((int) line);
	write_string(": ");
	raw_write(2, assertion, strlen(assertion));
	write_string("\n");
	abort();
}
#endif /* NDEBUG */

sighandler_t signal(int signum, sighandler_t handler)
{
	static sighandler_t (*orig_signal)(int, sighandler_t);
	
	sighandler_t ret;
	if (!orig_signal)
	{
		orig_signal = fake_dlsym(RTLD_NEXT, "signal");
		if (!orig_signal) abort();
	}

	if (signum == SIGILL)
	{
		debug_printf(0, "Ignoring program's request to install a SIGILL handler.\n");
		errno = ENOTSUP;
		ret = SIG_ERR;
	} else ret = orig_signal(signum, handler);
out:
	return ret;
}

int sigaction(int signum, const struct __libc_sigaction *act,
                     struct __libc_sigaction *oldact)
{
	static int (*orig_sigaction)(int, const struct __libc_sigaction *, struct __libc_sigaction *);
	
	int ret;
	if (!orig_sigaction)
	{
		orig_sigaction = fake_dlsym(RTLD_NEXT, "sigaction");
		if (!orig_sigaction) abort();
	}
	
	if (signum == SIGILL && act != NULL)
	{
		debug_printf(0, "Ignoring program's request to install a SIGILL handler.\n");
		ret = orig_sigaction(SIGILL, NULL, oldact);
	} else ret = orig_sigaction(signum, act, oldact);
out:
	return ret;
}

void *memcpy(void *dest, const void *src, size_t n)
{
	static void *(*orig_memcpy)(void *, const void *, size_t);
	if (!orig_memcpy)
	{
		/* Use fake_dlsym because it understands ifuncs. */
		orig_memcpy = fake_dlsym(RTLD_NEXT, "memcpy");
		assert(orig_memcpy);
	}
	
	__notify_copy(dest, src, n);

	return orig_memcpy(dest, src, n);
}

void *(*orig_memmove)(void *, const void *, size_t);
void *memmove(void *dest, const void *src, size_t n)
{
	if (!orig_memmove)
	{
		/* Use fake_dlsym because it understands ifuncs. */
		orig_memmove = fake_dlsym(RTLD_NEXT, "memmove");
		assert(orig_memmove);
	}
	
	__notify_copy(dest, src, n);

	return orig_memmove(dest, src, n);
}
