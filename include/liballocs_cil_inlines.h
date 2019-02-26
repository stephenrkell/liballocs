#ifndef LIBALLOCS_CIL_INLINES_H_
#define LIBALLOCS_CIL_INLINES_H_

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
//#ifdef DEBUG
#define assert(cond) \
	if (!(cond)) abort()
//#else
//#define assert(cond)
//#endif
#endif

/* Prototypes we omit. */
void abort(void) __attribute__((noreturn));

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
#ifndef ALIGNOF
#define ALIGNOF(type) offsetof (struct { char c; type member; }, member)
#endif
#ifndef PAD_TO_ALIGN
#define PAD_TO_ALIGN(n, a) 	((0 == ((n) % (a))) ? (n) : (n) + (a) - ((n) % (a)))
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
	#else // assume X86_64 for now
		__asm__ volatile ("movq %%rsp, %0\n" : "=r"(our_sp));
	#endif
	return (const void*) our_sp;
}

extern inline const void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_bp)(void);
extern inline const void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_get_bp)(void)
{
	return (const void *) __builtin_frame_address(0);
}

extern inline void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_alloca)(unsigned long size, unsigned long *frame_counter, void *caller);
extern inline void *(__attribute__((always_inline,gnu_inline,used)) __liballocs_alloca)(unsigned long size, unsigned long *frame_counter, void *caller)
{
	/* Insert heap trailer etc..
	 * Basically we have to do everything that our malloc hooks, allocator wrappers
	 * and heap indexing code does. ARGH. Maintenance nightmare.... 
	 * 
	 * AND only do the indexing things if liballocs is preloaded. Otherwise.... */
	unsigned long chunk_size = PAD_TO_ALIGN(size + ALLOCA_TRAILER_SIZE, ALLOCA_TRAILER_SIZE);
	void *alloc = __builtin_alloca(ALLOCA_HEADER_SIZE + chunk_size);
#ifndef LIBALLOCS_NO_ZERO
	__builtin_memset((char*) alloc + ALLOCA_HEADER_SIZE, 0, chunk_size);
#endif
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
		// assert we haven't been here before
		assert(!(visited_mru & (1<<(i-1))));
		visited_mru |= (1<<(i-1));
	}
	assert(visited_linear == visited_mru);
	// go the other way too
	unsigned visited_lru = 0u;
	for (unsigned char i = cache->tail_mru; i != 0; i = cache->entries[i].prev_mru)
	{
		assert(cache->validity & (1<<(i-1)));
		// assert we haven't been here before
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
	// unset validity and make this the next victim
	cache->validity &= ~(1u<<(i-1));
	cache->next_victim = i;
	// unhook us from the mru list
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
	// make sure we're not the next victim
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
				// hit
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
				// hit
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
	// "one plus the index of the least significant 0-bit" of validity
	unsigned pos = __builtin_ffs(~(c->validity));
	assert(pos <= c->size_plus_one);
	if (pos == c->size_plus_one)
	{
		pos = c->tail_mru;
		assert(pos != 0);
	}
#endif
	// unsigned pos = __liballocs_ool_cache.next_victim;
	c->entries[pos] = (struct __liballocs_memrange_cache_entry_s) {
		.obj_base = obj_base,
		.obj_limit = obj_limit,
		.uniqtype = (struct uniqtype *) t,
		.period = period,
		.depth = depth,
		.prev_mru = c->entries[pos].prev_mru,
		.next_mru = c->entries[pos].next_mru
	};
	// bump us to the top
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
