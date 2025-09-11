#ifndef LIBALLOCS_CIL_INLINES_H_
#define LIBALLOCS_CIL_INLINES_H_

/* NOTE: this file gets included into user code,
 * so needs to be written to be tolerant of old-ish versions of C.
 * Ditto for anything it includes. */

/* This file should also not include any standard headers.
 * Soem codebases will replace them with their own version that
 * does not like being included first, e.g. before a config.h.
 * See GitHub issue #125. */
#include "liballocs_config.h"
#include "malloc-meta.h"

#ifndef unlikely
#define __liballocs_defined_unlikely
#define unlikely(cond) (__builtin_expect( (cond), 0 ))
#endif
#ifndef likely
#define __liballocs_defined_likely
#define likely(cond)   (__builtin_expect( (cond), 1 ))
#endif
#ifndef assert
#define __liballocs_defined_assert
/* #ifdef DEBUG */
#define assert(cond) \
	if (!(cond)) abort()
/* #else */
/* #define assert(cond) */
/* #endif */
#endif

/* Prototypes we omit. */
void abort(void) __attribute__((noreturn));

/* The functions are *not* weak -- they're defined in the noop library. 
 * we would like the noop library not to be necessary. */
int (__attribute__((constructor(103))) __liballocs_global_init) (void);
/* This is not weak. */
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
/* Heap index hooks -- these also aren't weak, for the usual reason. */
void __alloca_allocator_notify(void *new_userchunkaddr,
		unsigned long requested_size, unsigned long *frame_counter,
		const void *caller, const void *caller_sp, const void *caller_bp);
struct big_allocation;
struct uniqtype; /* forward decl */

/* This *must* match the size of 'struct extended_insert' in generic_malloc_index!
 * But we don't include that header right now, to avoid perturbing the
 * inclusion order of the rest of this translation unit.
 * HACK: We do not need the lifetime insert for alloca so it is never included. */
#ifndef ALLOCA_TRAILER_SIZE
# ifdef PRECISE_REQUESTED_ALLOCSIZE
#  define ALLOCA_TRAILER_SIZE (1 + sizeof (void*))
# else
#  define ALLOCA_TRAILER_SIZE (sizeof (void*))
# endif
#endif

/* This must match the required alignment of an allocation after the insert is added */
#ifndef ALLOCA_ALIGN
#define ALLOCA_ALIGN 16
#endif

/* This *must* match the treatment of "early_malloc"'d chunks in malloc_hook_stubs.c. 
 * */
#ifndef ALLOCA_HEADER_SIZE
#define ALLOCA_HEADER_SIZE (sizeof (unsigned long))
#endif

#ifndef CURRENT_ALLOC_VARS_QUALIFIERS
/* TLS can be disabled */
#ifndef NO_TLS
#define CURRENT_ALLOC_VARS_QUALIFIERS extern __thread
#define CURRENT_ALLOC_VARS_QUALIFIERS_POST  __attribute__((weak))
#else
#define CURRENT_ALLOC_VARS_QUALIFIERS extern
#define CURRENT_ALLOC_VARS_QUALIFIERS_POST  __attribute__((weak))
#endif
/* */
#else
/* the include context needs to have defined CURRENT_ALLOC_VARS_QUALIFIERS{,_POST} */
#endif
CURRENT_ALLOC_VARS_QUALIFIERS void *__current_allocsite CURRENT_ALLOC_VARS_QUALIFIERS_POST;

void __liballocs_unindex_stack_objects_counted_by(unsigned long *, void *frame_addr);

extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_alloca_caller_frame_cleanup)(void *counter);
extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_alloca_caller_frame_cleanup)(void *counter)
{
	__liballocs_unindex_stack_objects_counted_by((unsigned long *) counter, __builtin_frame_address(0));
}

/* alloca helpers */
extern inline const void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_sp)(void);
extern inline const void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_sp)(void)
{
	unsigned long our_sp;
	#ifdef UNW_TARGET_X86
		__asm__ volatile ("movl %%esp, %0\n" :"=r"(our_sp));
	#else /* assume X86_64 for now */
		__asm__ volatile ("movq %%rsp, %0\n" : "=r"(our_sp));
	#endif
	return (const void*) our_sp;
}

extern inline const void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_bp)(void);
extern inline const void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_bp)(void)
{
	return (const void *) __builtin_frame_address(0);
}

#ifndef PAD_TO_ALIGN
#define PAD_TO_ALIGN(n, a) 	((0 == ((n) % (a))) ? (n) : (n) + (a) - ((n) % (a)))
#endif
/* We have to pad the alloca chunk at both ends: prepend a header
 * that lets us retrieve the size, and then append our usual trailer
 * for the allocation site / type metadata. We call a helper to get
 * the *overall* size, and then the __liballocs_notify_and_adjust_alloca()
 * function will fill in both the header and the trailer. */
extern inline unsigned long (__attribute__((always_inline,gnu_inline,used)) __liballocs_alloca_size)(unsigned long orig_size);
extern inline unsigned long (__attribute__((always_inline,gnu_inline,used)) __liballocs_alloca_size)(unsigned long orig_size)
{
	/* Insert heap trailer etc..
	 * Basically we have to do everything that our malloc hooks, allocator wrappers
	 * and heap indexing code does. ARGH. Maintenance nightmare.... 
	 * 
	 * AND only do the indexing things if liballocs is preloaded. Otherwise....
	 *
	 * We need to ensure 16-byte alignment, equivalently with malloc. */
	unsigned long size_with_trailer = PAD_TO_ALIGN(orig_size + ALLOCA_TRAILER_SIZE, ALLOCA_ALIGN);
	unsigned long size_with_trailer_and_header
	 = PAD_TO_ALIGN(ALLOCA_HEADER_SIZE, ALLOCA_ALIGN) + size_with_trailer;
	return size_with_trailer_and_header;
	/* The alloca-returned pointer may be only 8-byte-aligned. Since we asked for
	 * 16 extra bytes but we only need 8, we *will* waste 8 bytes, either at the
	 * beginning or the end of the returned chunk. They just become a hole on the stack;
	 * we don't track them. */
}

extern inline void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_notify_and_adjust_alloca)(void *allocated, unsigned long orig_size, unsigned long tweaked_size, unsigned long *frame_counter, void *caller);
extern inline void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_notify_and_adjust_alloca)(void *allocated, unsigned long orig_size, unsigned long tweaked_size, unsigned long *frame_counter, void *caller)
{
#ifndef LIBALLOCS_NO_ZERO
	__builtin_memset(allocated, 0, tweaked_size);
#endif
	void *userchunk = (void*)(PAD_TO_ALIGN((unsigned long) allocated + ALLOCA_HEADER_SIZE, ALLOCA_ALIGN));
	unsigned long header_effective_size = (unsigned long) userchunk - (unsigned long) allocated;
	unsigned long non_header_size = tweaked_size - header_effective_size;
	/* The non-header size is like the size returned by the system malloc_usable_size(),
	 * i.e. it includes the trailer (but not our special alloca header, which a normal
	 * malloc provides its own equivalent of). */

	/* write the non-header size into the word preceding the userchunk, then return the userchunk. */
	*((unsigned long *)userchunk - 1) = non_header_size;
	
	/* FIXME: this byte-counting approach works for GCC but not Clang. GitHub issue #107.
	 * But maybe it's overkill anyway?
	 * Can we not say "unindex everything starting below <frame base> up to <stack limit>?"
	 * We add only the "usable size" part, because that is what the heap index code
	 * can see, and that is the code that will be consuming this value.
	 * XXX: for now, hope that our modified instrumentation pass that leaks every alloca
	 * ptr, will prevent Clang from doing any funky optimisations that drop an alloca'd
	 * chunk early. */
	*frame_counter += non_header_size;
	
	/* Note that we pass the caller directly; __current_allocsite is not required. */
	__alloca_allocator_notify(userchunk, orig_size, frame_counter, caller,
		__liballocs_get_sp(), __liballocs_get_bp());
	
	return userchunk;
}

void __liballocs_unindex_stack_objects_below(void *);

extern _Bool __liballocs_is_initialized __attribute__((weak));

/* tentative cache entry redesign to integrate bounds and types:
 * 
 * - lower
 * - upper     (one-past)
 * - t         (may be null, i.e. bounds only)
 * - sz        (size of t)
 * - period    (need not be same as period, i.e. if T is int, alloc is array of stat, say)
 *                 ** ptr arithmetic is only valid if sz == period
 *                 ** entries with sz != period are still useful for checking types 
 */

struct __liballocs_memrange_cache_entry_s
{
	const void *obj_base;
	const void *obj_limit;
	struct uniqtype *uniqtype;
	unsigned period;
	signed short depth; /* 0 means leaf-level; 1, 2... inside uniqtype; -1, ... bigalloc */
	unsigned char prev_mru;
	unsigned char next_mru;
	/* TODO: do inline uniqtype cache word check? */
} __attribute__((aligned(64)));

#ifndef LIBALLOCS_MEMRANGE_CACHE_MAX_SIZE
#define LIBALLOCS_MEMRANGE_CACHE_MAX_SIZE 8
#endif
struct __liballocs_memrange_cache
{
	unsigned int validity; /* does *not* include the null entry */
	const unsigned short size_plus_one; /* i.e. including the null entry */
	unsigned short next_victim;
	unsigned char head_mru;
	unsigned char tail_mru;
	/* We use index 0 to mean "unused" / "null". */
	struct __liballocs_memrange_cache_entry_s entries[1 + LIBALLOCS_MEMRANGE_CACHE_MAX_SIZE];
};
extern struct __liballocs_memrange_cache /* __thread */ __liballocs_ool_cache;

extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_check_cache_sanity )(struct __liballocs_memrange_cache *cache __attribute__((unused)));
extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_check_cache_sanity )(struct __liballocs_memrange_cache *cache __attribute__((unused)))
{
#ifdef DEBUG
	unsigned visited_linear = 0u;
	for (int i = 1; i < cache->size_plus_one; ++i)
	{
		if (cache->validity & (1<<(i-1)))
		{
			visited_linear |= (1<<(i-1));
		}
	}
	unsigned visited_mru = 0u;
	for (unsigned char i = cache->head_mru; i != 0; i = cache->entries[i].next_mru)
	{
		assert(cache->validity & (1<<(i-1)));
		/* assert we haven't been here before */
		assert(!(visited_mru & (1<<(i-1))));
		visited_mru |= (1<<(i-1));
	}
	assert(visited_linear == visited_mru);
	/* go the other way too */
	unsigned visited_lru = 0u;
	for (unsigned char i = cache->tail_mru; i != 0; i = cache->entries[i].prev_mru)
	{
		assert(cache->validity & (1<<(i-1)));
		/* assert we haven't been here before */
		assert(!(visited_lru & (1<<(i-1))));
		visited_lru |= (1<<(i-1));
	}
	assert(visited_linear == visited_lru);
#endif
}

extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_unlink )(struct __liballocs_memrange_cache *cache, unsigned i);
extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_unlink )(struct __liballocs_memrange_cache *cache, unsigned i)
{
	__liballocs_check_cache_sanity(cache);
	/* unset validity and make this the next victim */
	cache->validity &= ~(1u<<(i-1));
	cache->next_victim = i;
	/* unhook us from the mru list */
	unsigned char our_next = cache->entries[i].next_mru;
	unsigned char our_prev = cache->entries[i].prev_mru;
	if (our_prev) cache->entries[our_prev].next_mru = our_next;
	if (our_next) cache->entries[our_next].prev_mru = our_prev;
	if (cache->head_mru == i) cache->head_mru = our_next;
	if (cache->tail_mru == i) cache->tail_mru = our_prev;
	/* We're definitely invalid. */
	cache->validity &= ~(1u<<(i-1));
	__liballocs_check_cache_sanity(cache);
}

extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_push_head_mru )(struct __liballocs_memrange_cache *cache, unsigned i);
extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_push_head_mru )(struct __liballocs_memrange_cache *cache, unsigned i)
{
	__liballocs_check_cache_sanity(cache);
	/* Put us at the head of the LRU chain. */
	cache->entries[i].prev_mru = 0;
	cache->entries[i].next_mru = cache->head_mru;
	/* Link us in at the head. */
	if (cache->head_mru != 0) cache->entries[cache->head_mru].prev_mru = (unsigned char) i;
	cache->head_mru = (unsigned char) i;
	/* Set the tail, if we didn't already have one. */
	if (cache->tail_mru == 0) cache->tail_mru = i;
	/* We're definitely valid. */
	cache->validity |= (1u<<(i-1));
	/* Should be sane again now. */
	__liballocs_check_cache_sanity(cache);
}	

extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_bump_victim )(struct __liballocs_memrange_cache *cache, unsigned i);
extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_bump_victim )(struct __liballocs_memrange_cache *cache, unsigned i)
{
	__liballocs_check_cache_sanity(cache);
	/* make sure we're not the next victim */
	if (unlikely(cache->next_victim == i))
	{
		if (cache->size_plus_one > 1)
		{
			cache->next_victim = 1 + ((i + 1 - 1) % (cache->size_plus_one - 1));
		}
	}
	__liballocs_check_cache_sanity(cache);
}

extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_bump_mru )(struct __liballocs_memrange_cache *cache, unsigned i);
extern inline void (__attribute__((always_inline,gnu_inline,used)) __liballocs_cache_bump_mru )(struct __liballocs_memrange_cache *cache, unsigned i)
{
	__liballocs_check_cache_sanity(cache);
	if (cache->head_mru != i)
	{
		if (cache->validity & (1u<<(i-1))) __liballocs_cache_unlink(cache, i);
		__liballocs_cache_push_head_mru(cache, i);
	}
	__liballocs_check_cache_sanity(cache);
}

extern inline
struct __liballocs_memrange_cache_entry_s *(__attribute__((always_inline,gnu_inline,used))
__liballocs_memrange_cache_lookup )(struct __liballocs_memrange_cache *cache, const void *obj, struct uniqtype *t, unsigned long require_period);
extern inline
struct __liballocs_memrange_cache_entry_s *(__attribute__((always_inline,gnu_inline,used))
__liballocs_memrange_cache_lookup )(struct __liballocs_memrange_cache *cache, const void *obj, struct uniqtype *t, unsigned long require_period)
{
#ifndef LIBALLOCS_NOOP_INLINES
	__liballocs_check_cache_sanity(cache);
#ifdef LIBALLOCS_CACHE_LINEAR
	for (unsigned char i = 1; i < cache->size_plus_one; ++i)
#else
	for (unsigned char i = cache->head_mru; i != 0; i = cache->entries[i].next_mru)
#endif
	{
		if (cache->validity & (1<<(i-1)))
		{
			struct uniqtype *cache_uniqtype = cache->entries[i].uniqtype;
			/* We test whether the difference is divisible by the period and within the bounds */
			signed long long diff = (char*) obj - (char*) cache->entries[i].obj_base;
			if (cache_uniqtype == t
					&& (char*) obj >= (char*)cache->entries[i].obj_base
					&& (char*) obj < (char*)cache->entries[i].obj_limit
					&& 
					((diff == 0)
						|| (cache->entries[i].period != 0
							&& (!require_period || cache->entries[i].period == require_period)
							&& diff % cache->entries[i].period == 0)))
			{
				/* hit */
				__liballocs_cache_bump_mru(cache, i);
				return &cache->entries[i];
			}
		}
	}
#endif
	__liballocs_check_cache_sanity(cache);
	return (struct __liballocs_memrange_cache_entry_s *)(void*)0;
}

extern inline
struct __liballocs_memrange_cache_entry_s *(__attribute__((always_inline,gnu_inline,used))
__liballocs_memrange_cache_lookup_notype )(struct __liballocs_memrange_cache *cache, const void *obj, unsigned long require_period);
extern inline
struct __liballocs_memrange_cache_entry_s *(__attribute__((always_inline,gnu_inline,used))
__liballocs_memrange_cache_lookup_notype )(struct __liballocs_memrange_cache *cache, const void *obj, unsigned long require_period)
{
#ifndef LIBALLOCS_NOOP_INLINES
	__liballocs_check_cache_sanity(cache);
#ifdef LIBALLOCS_CACHE_LINEAR
	for (unsigned char i = 1; i < cache->size_plus_one; ++i)
#else
	for (unsigned char i = cache->head_mru; i != 0; i = cache->entries[i].next_mru)
#endif
	{
		if (cache->validity & (1<<(i-1)))
		{
			/* We test whether the difference is divisible by the period and within the bounds */
			signed long long diff = (char*) obj - (char*) cache->entries[i].obj_base;
			if ((char*) obj >= (char*)cache->entries[i].obj_base
					&& (char*) obj < (char*)cache->entries[i].obj_limit
					&& 
					((diff == 0 && !require_period)
						|| (cache->entries[i].period != 0
							&& (!require_period || cache->entries[i].period == require_period)
							&& diff % cache->entries[i].period == 0)))
			{
				/* hit */
				__liballocs_cache_bump_mru(cache, i);
				return &cache->entries[i];
			}
		}
	}
#endif
	__liballocs_check_cache_sanity(cache);
	return (struct __liballocs_memrange_cache_entry_s *)(void*)0;
}

extern inline struct uniqtype *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_cached_object_type)(const void *addr);
extern inline struct uniqtype *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_cached_object_type)(const void *addr)
{
	struct __liballocs_memrange_cache_entry_s *found = __liballocs_memrange_cache_lookup_notype(
		&__liballocs_ool_cache,
		addr, 0);
	/* This will give us "zero-offset matches", but not contained matches. 
	 * I.e. we know that "addr" is a "found->uniqtype", but we pass over
	 * cases where some cached allocation spans "addr" at a non-zero offset. */
	if (found) return found->uniqtype;
	return (struct uniqtype *)(void*)0;
}

void __liballocs_uncache_all(const void *allocptr, unsigned long size);

extern inline void
(__attribute__((always_inline,gnu_inline)) __liballocs_cache_with_type)(
	struct __liballocs_memrange_cache *c,
	const void *obj_base, const void *obj_limit, const struct uniqtype *t, 
	short depth, unsigned short period, const void *alloc_base)
{
	assert((__liballocs_check_cache_sanity(&__liballocs_ool_cache), 1));
#ifdef LIBALLOCS_CACHE_REPLACE_FIFO
	unsigned pos = c->next_victim;
#else
	/* "one plus the index of the least significant 0-bit" of validity */
	unsigned pos = __builtin_ffs(~(c->validity));
	assert(pos <= c->size_plus_one);
	if (pos == c->size_plus_one)
	{
		pos = c->tail_mru;
		assert(pos != 0);
	}
#endif
	/* unsigned pos = __liballocs_ool_cache.next_victim; */
	c->entries[pos] = (struct __liballocs_memrange_cache_entry_s) {
		.obj_base = obj_base,
		.obj_limit = obj_limit,
		.uniqtype = (struct uniqtype *) t,
		.period = period,
		.depth = depth,
		.prev_mru = c->entries[pos].prev_mru,
		.next_mru = c->entries[pos].next_mru
	};
	/* bump us to the top */
	__liballocs_cache_bump_mru(c, pos);
	__liballocs_cache_bump_victim(c, pos);
	assert((__liballocs_check_cache_sanity(c), 1));
}

#ifdef __liballocs_defined_unlikely
#undef unlikely
#endif
#ifdef __liballocs_defined_likely
#undef likely
#endif
#ifdef __liballocs_defined_assert
#undef assert
#endif

#endif
