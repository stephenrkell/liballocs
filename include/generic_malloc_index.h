#ifndef _GENERIC_MALLOC_INDEX_H
#define _GENERIC_MALLOC_INDEX_H

/* Note: you have to be _GNU_SOURCE to use this file. */

#include <stdbool.h>
#include <pthread.h>
#include "liballocs_config.h"
#include "liballocs.h"
#include "liballocs_ext.h"
#include "pageindex.h"
#include "malloc-meta.h"
#include "bitmap.h"

/* A thread-local variable to override the "caller" arguments. 
 * Platforms without TLS have to do without this feature. */
#ifndef NO_TLS
extern __thread void *__current_allocsite;
extern __thread void *__current_allocfn;
extern __thread size_t __current_allocsz;
extern __thread int __currently_freeing;
extern __thread int __currently_allocating;
#else
#warning "Using thread-unsafe __current_allocsite variable."
extern void *__current_allocsite;
extern void *__current_allocfn;
extern size_t __current_allocsz;
extern int __currently_freeing;
extern int __currently_allocating;
#endif

/* HACK while we can't create protected symbols in linker scripts
 * (__liballocs_private_malloc = __private_malloc and so on ). */
#ifdef IN_LIBALLOCS_DSO
//void *__private_malloc(size_t);
#define __liballocs_private_malloc __private_malloc
//void *__private_realloc(void *, size_t);
#define __liballocs_private_realloc __private_realloc
//void *__private_calloc(size_t, size_t);
#define __liballocs_private_calloc __private_calloc
//void *__private_free(void *);
#define __liballocs_private_free __private_free
//void __free_arena_bitmap_and_info(void *info);
#define __liballocs_free_arena_bitmap_and_info __free_arena_bitmap_and_info
#define __liballocs_extract_and_output_alloc_site_and_type extract_and_output_alloc_site_and_type
#endif

/* Generic heap indexing implementation.
 * This can index any malloc-like heap, and do so pretty quickly.
 *
 * The main idea is to increment the size requested by the caller,
 * to leave room for an 'insert'. Currently the insert lives at the
 * end of the chunk, so is sometimes called a trailer. Using a trailer
 * is more robust than using a header, because it doesn't change the
 * chunk start address. Many malloc API calls take and return chunk
 * start addresses, and we'd have to wrap them all to translate
 * the start address. Instead, we never change the start address and
 * we wrap only the ones that do allocation or free, but not, say
 * mprobe() (or whatever non-standard per-chunk functions are provided).
 *
 * We have to be careful about sizes:
 *    ____________________....________.._______..
 *   |____________________....______|_.._|_____..|
 *   |<----------------------------------------->|  malloc-usable
 *   |<------------------------------------>|    :  caller-usable (this is not a mistake -- see below)
 *   |<---------------------------->|    :  :    :  requested by caller
 *                                  |<--->| :    :  padding to _Alignof (struct insert)  (maybe empty)
 *                                  :    :|<-->| :  size of insert
 *   |<--------------------------------------->| :  how much we actually request from malloc
 *                                  :    :  :  |z|  possible padding added by malloc     (maybe empty)
 *                                  :    :  |<-->|  **the actual insert** is always at base + malloc_usable - sizeof insert
 *
 *   FIXME: this means inserts may be misaligned.
 *   In practice this seems not to happen, because
 *   malloc pads to a #words and inserts are word-sized.
 *   We can easily fix this by rounding down to _Alignof (struct insert).
 *   (A perverse malloc might pad even more, s.t. this rounding-down
 *   doesn't hit the boundary we rounded up to, but a later one. That's fine.)
 *
 * - 'requested size' means the size requested by the caller
 * - 'malloc usable size' means the size returned by malloc_usable_size() or
 *      any comparable size-getting function (we parameterise on this).
 *      This size includes our trailer space
 *      (and just unqualified 'usable size' by default also means this)
 * - 'caller-usable size' means the size that the caller is actually free to use
 *      (our malloc-usable-size wrapper returns *this*).
 *
 *    requested size <= caller-usable size < malloc_usable_size
 *
 *                      caller_usable_size <= malloc_usable_size - insert_size
 *
 *    ... where insert_size is >= sizeof (struct insert) and depends on some
 * compile-time options (whether Guillaume's lifetime policies stuff is enabled).
 * Some clients, including Guillaume's code, really want to be able to recover
 * the *requested* size. (FIXME: does Guillaume's really need this, or is the
 * caller-usable size good enogh?)
 *
 * In fact our own code for creating precise array types in liballocs core, does
 * this. However, probably that code is at fault. A client of malloc is perfectly
 * entitled to opportunistically use extra space that it learns about from
 * malloc_usable_size. So the allocation size returned by liballocs should reflect
 * that. So we should round down the size at the point of sizing the array.
 */
typedef size_t sizefn_t(void*);
static inline size_t allocsize_to_usersize(size_t usersize) { return usersize; }
static inline size_t usersize_to_allocsize(size_t allocsize) { return allocsize; }
static inline size_t usersize(void *userptr, sizefn_t *sizefn) { return allocsize_to_usersize(sizefn(userptr)); }
static inline size_t allocsize(void *allocptr, sizefn_t *sizefn) { return sizefn(allocptr); }

struct arena_bitmap_info
{
	unsigned long nwords;
	bitmap_word_t *bitmap;
	void *bitmap_base_addr;
	pthread_mutex_t mutex;
	unsigned long bitmap_insert_count;
	unsigned long biggest_allocated_object;
	unsigned long biggest_unpromoted_object;
#ifdef TRACE_GENERIC_MALLOC_INDEX
	/* Size the circular buffer of recently freed chunks */
#define RECENTLY_FREED_SIZE 100
	/* Keep a circular buffer of recently freed chunks */
	void *recently_freed[RECENTLY_FREED_SIZE];
	void **next_recently_freed_to_replace; = &recently_freed[0];
#endif
};
void __free_arena_bitmap_and_info(void *info  /* really struct arena_bitmap_info * */);

/* Chunks can also have lifetime policies attached, if we are built
 * with support for this.
 *
 * Ideally we could pack all this into 64 bits:
 * -uniqtype        (44 bits)
 * -allocsite idx   (~14 bits? not sure how many bona-fide allocation sites large programs may have)
 *      -- one trick might be to bin the allocation sites by uniqtype, so that
 *         when the uniqtype is present, only a per-uniqtype idx is needed.
 *         Currently allocsites are sorted by address, so we can bsearch them,
 *         so we'd need a separate set of indexes grouping by type. Maybe the uniqtype
 *         can even point to its allocsites?
 * -one bit per lifetime policy (~6 bits?).
 *
 * When we get rid of the memtable in favour of the bitmap,
 * we should be able to fit this in.
 * For now, strip out the lifetime policies support.
 */
typedef /*LIFETIME_INSERT_TYPE*/ uint8_t lifetime_insert_t;
#define LIFETIME_POLICY_FLAG(id) (0x1 << (id))
// By convention lifetime policy 0 is the manual deallocation policy
#define MANUAL_DEALLOCATION_POLICY 0
#define MANUAL_DEALLOCATION_FLAG LIFETIME_POLICY_FLAG(MANUAL_DEALLOCATION_POLICY)
// Manual deallocation is not an "attached" policy
#define HAS_LIFETIME_POLICIES_ATTACHED(lti) ((lti) & ~(MANUAL_DEALLOCATION_FLAG))

struct extended_insert
{
	lifetime_insert_t lifetime;
#ifdef PRECISE_REQUESTED_ALLOCSIZE
	/* Include any padding inserted such that
	 * usable_size - insert_size = requested_size */
	uint8_t insert_size;
#endif
	/* The base insert is at the end because we want interoperabiliy between
	 * allocators using extended_insert and allocators only using insert.
	 * See insert_for_chunk. */
	struct insert base;
} __attribute__((packed)); // Alignment from the end guaranteed by ourselves

static inline size_t caller_usable_size_for_chunk_and_usable_size(void *userptr,
	size_t alloc_usable_size)
{
	return alloc_usable_size - sizeof (struct insert);
}

static inline struct insert *
insert_for_chunk_and_caller_usable_size(void *userptr, size_t caller_usable_size)
{
	uintptr_t insertptr = (uintptr_t)((char*) userptr + caller_usable_size);

	// Check alignment
	assert(insertptr % ALIGNOF(struct insert) == 0);

	return (struct insert *)insertptr;
}
static inline size_t caller_usable_size_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return caller_usable_size_for_chunk_and_usable_size(userptr,
			sizefn(userptr));
}
static inline struct insert *insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return insert_for_chunk_and_caller_usable_size(userptr,
		caller_usable_size_for_chunk(userptr, sizefn));
}

static inline struct extended_insert *extended_insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return NULL; /* FIXME: restore this */
}
static inline lifetime_insert_t *lifetime_insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return &extended_insert_for_chunk(userptr, sizefn)->lifetime;
}

// this is only used for promotion
static inline struct big_allocation *__generic_malloc_fresh_big(struct allocator *a, void *allocptr, size_t bigalloc_size,
	struct big_allocation *containing_bigalloc)
{
	struct big_allocation *b = __liballocs_new_bigalloc(
		allocptr,
		bigalloc_size,
		NULL /* allocator private */,
		NULL /* allocator_private_free */,
		containing_bigalloc,
		a
	);
	if (!b) abort();
	return b;
}
static inline struct big_allocation *__generic_malloc_ensure_big(struct allocator *a, void *addr, size_t size)
{
	void *start;
	struct big_allocation *maybe_already = __lookup_bigalloc_from_root(addr,
		a, &start);
	if (maybe_already) return maybe_already;
	return __generic_malloc_fresh_big(a, addr, size, __lookup_deepest_bigalloc(addr));
}

static inline struct arena_bitmap_info *ensure_arena_has_info(struct big_allocation *arena);

static inline
struct big_allocation *arena_for_userptr(struct allocator *a, void *userptr)
{
	struct big_allocation *b = __lookup_bigalloc_from_root_by_suballocator(userptr,
		a, NULL);
	/* What if we get no b? probably means we're not initialized, e.g. a malloc
	 * happening during __runt_files_init.
	 * What about a fresh arena? How does its suballocator get set up? */
	if (!b)
	{
		b = __lookup_deepest_bigalloc(userptr);
		assert(!b->suballocator);
		b->suballocator = a;
		ensure_arena_has_info(b);
	}
	return b;
}

#ifndef NO_BIGALLOCS
static inline
struct arena_bitmap_info *arena_info_for_userptr(struct allocator *a, void *userptr)
{
	struct big_allocation *b = arena_for_userptr(a, userptr);
	return b ? (struct arena_bitmap_info *) b->suballocator_private : NULL;

}

static inline struct arena_bitmap_info *ensure_arena_info_for_userptr(
	struct allocator *a,
	void *userptr)
{
	struct big_allocation *arena = arena_for_userptr(a, userptr);
	return ensure_arena_has_info(arena);
}
#else
/* A no-bigallocs include context will have to provide its own definitions
 * of these functions, perhaps using a static arena_bitmap_info structure. */
#endif

/* We use a big lock to protect access to our bitmap. Ideally we would
 * just do lock-free CAS for bitmap updates. */
#ifndef NO_PTHREADS
#define BIG_LOCK \
	lock_ret = pthread_mutex_lock(&info->mutex); \
	assert(lock_ret == 0);
#define BIG_UNLOCK \
	lock_ret = pthread_mutex_unlock(&info->mutex); \
	assert(lock_ret == 0);
#else
#define BIG_LOCK
#define BIG_UNLOCK
#endif

#define SHOULD_PROMOTE_TO_BIGALLOC(userchunk, usable_size) \
	((usable_size) > /* HACK: default glibc lower mmap threshold: 128 kB */ 131072)

/* If this is being linked into a client exe, as part of our malloc-hooking
 * approach (the in-exe case), we are generating a load of outgoing references
 * to liballocs. They all need to be stubbed out in the not-preloaded case.
 * What's a better way of doing that?
 *
 * I think the only symbols are __private_malloc, __private_realloc, __private_free,
 * big_allocations, __free_arena_bitmap_and_info. They should all be 'protected'
 * or have protected aliases that are used in this function.
 *
 * If indexing is built in to a binary, it should link -lallocs. Then, references
 * to liballocs are all ifuncs which resolve to the real routines if liballocs.so
 * is in the preload position, or dummy ones otherwise. allocsld.so is just a
 * link to liballocs.so. Allocsld does *not* force liballocs.so into the preload
 * position, because it is the interpreter of liballocs-built binaries. Perhaps
 * it should do this if it is 'invoked' but not if 'requested'.
 *
 * To generate these ifuncs, and the dummy functions, we still need a spec of
 * the liballocs binary interface.
 * We could have a version script that does this. Or we could have a dwarfidl file
 * that does it.*/

static inline struct arena_bitmap_info *ensure_arena_has_info(struct big_allocation *arena)
{
	if (__builtin_expect(!arena->suballocator_private, 0))
	{
		struct arena_bitmap_info *info;
		arena->suballocator_private = info = __liballocs_private_malloc(sizeof (*info));
		arena->suballocator_private_free = __liballocs_free_arena_bitmap_and_info;
		info->nwords = 0;
		info->bitmap = NULL;
		/* Mutex is recursive only because assertion failures sometimes want to do
		 * asprintf, so try to re-acquire our mutex. */
		info->mutex = (pthread_mutex_t) PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
		info->bitmap_insert_count = 0;
		info->biggest_allocated_object = 0;
		info->biggest_unpromoted_object = 0;
#ifdef TRACE_GENERIC_MALLOC_INDEX
		info->next_recently_freed_to_replace = &info->recently_freed[0];
		bzero(info->recently_freed, sizeof info->recently_freed);
#endif
		info->bitmap_base_addr = ROUND_DOWN_PTR(arena->begin, MALLOC_ALIGN*BITMAP_WORD_NBITS);
		/* The base addr is rounded down to MALLOC_ALIGN * BITMAP_WORD_NBITS.
		 * E.g. if a bitmap word if 64 bits / 8 bytes, and malloc align is 16,
		 * the bitmap base is at the 512-byte boundary that precedes the arena base.
		 * Why? It's because there is one bit in the bitmap for every MALLOC_ALIGN bytes
		 * in the arena. So the number of bytes covered by one bitmap word is the product
		 * of the two and is the unit of alignment for our region of coverage. */
	}
	return arena->suballocator_private;
}

static inline void ensure_has_bitmap_to(struct allocator *a,
		struct arena_bitmap_info *info,
		void *end)
{
	/* Assert the beginning hasn't changed. */
	/* FIXME: I think bigallocs can grow at the beginning as well as at the end.
	 * That would really screw up our bitmap. Figure out whether that could affect us...
	 * only some bigallocs, like mapping sequences maybe, can do this. */
#ifndef NO_BIGALLOCS
	struct big_allocation *arena = __lookup_bigalloc_under_by_suballocator((char*)end - 1, a,
		/*arena*/ NULL, NULL);
	assert(arena);
	uintptr_t bitmap_base_addr = (uintptr_t)ROUND_DOWN_PTR(arena->begin, MALLOC_ALIGN*BITMAP_WORD_NBITS);
	assert(bitmap_base_addr == (uintptr_t) info->bitmap_base_addr);
#endif
	unsigned long total_words =
		((uintptr_t)(ROUND_UP_PTR((char*)end, MALLOC_ALIGN*BITMAP_WORD_NBITS))
			 - (uintptr_t) info->bitmap_base_addr)
		/ (MALLOC_ALIGN * BITMAP_WORD_NBITS);
	if (__builtin_expect(info->nwords < total_words, 0))
	{
		info->bitmap = __liballocs_private_realloc(info->bitmap,
			total_words * sizeof (bitmap_word_t));
		if (!info->bitmap) abort();
		bzero(info->bitmap + info->nwords, (total_words - info->nwords) * sizeof (bitmap_word_t));
		info->nwords = total_words;
	}
}

static inline void __generic_malloc_index_insert(
	struct allocator *a,
	struct arena_bitmap_info *info,
	void *allocptr, size_t caller_requested_size, const void *caller,
	sizefn_t *sizefn)
		/* Technically we needn't pass sizefn, but this is faster
		 * than b->suballocator->get_size
		 * because the compiler will know which function it is. */
{
	int lock_ret;
	BIG_LOCK
	// first check our bitmap is big enough
	ensure_has_bitmap_to(a, info, (char*) allocptr + caller_requested_size);
	bitmap_word_t *bitmap = info->bitmap;
	/* The address *must* be in our tracked range. Assert this. */
#ifndef NO_BIGALLOCS
	struct big_allocation *arena = __lookup_bigalloc_under_by_suballocator(
		allocptr, /*arena->suballocator*/ a,
		/*arena*/ NULL, NULL);
	assert(info->bitmap_base_addr == ROUND_DOWN_PTR(arena->begin, MALLOC_ALIGN*BITMAP_WORD_NBITS)); // start of coverage (not of bitmap)
	void *bitmap_end_addr = (void*)((uintptr_t) info->bitmap_base_addr +       // limit of coverage
		((struct arena_bitmap_info *) arena->suballocator_private)->nwords * MALLOC_ALIGN * BITMAP_WORD_NBITS);
	assert((uintptr_t) allocptr <= (uintptr_t) bitmap_end_addr);
#endif

#ifdef TRACE_GENERIC_MALLOC_INDEX
	/* Check the recently freed list for this pointer. Delete it if we find it. */
	for (int i = 0; i < RECENTLY_FREED_SIZE; ++i)
	{
		if (info->recently_freed[i] == allocptr)
		{
			info->recently_freed[i] = NULL;
			info->next_recently_freed_to_replace = &recently_freed[i];
		}
	}
#endif
	size_t alloc_usable_size = sizefn(allocptr);
	size_t caller_usable_size = caller_usable_size_for_chunk_and_usable_size(allocptr,
			alloc_usable_size);
	struct insert *p_insert = insert_for_chunk_and_caller_usable_size(allocptr,
		caller_usable_size);
	/* Populate our extra in-chunk fields */
	p_insert->alloc_site_flag = 0U;
	p_insert->alloc_site = (uintptr_t) caller;

#if 0 // def PRECISE_REQUESTED_ALLOCSIZE
	/* FIXME: this isn't really the insert size. It's the insert plus padding.
	 * I'm not sure why/whether we need this. */
	ext_insert->insert_size = alloc_usable_size - caller_requested_size;
#define insert_size ext_insert->insert_size
#else
/* In this case, alignment might mean that we padded the actual request
 * to *more* than requested_size + insert_size.
 * In general caller_requested_size <= alloc_usable_size - insert_size */
#define insert_size (sizeof (struct insert))
#endif
#if 0 // def LIFETIME_POLICIES
	// alloca does not have a lifetime_insert
	if (arena->suballocator != &__alloca_allocator)
	{
		ext_insert->lifetime = MANUAL_DEALLOCATION_FLAG;
	}
#endif
	/* Metadata remains in the chunk */
	info->biggest_allocated_object = /* max */ (caller_usable_size > info->biggest_allocated_object) ?
		caller_usable_size : info->biggest_allocated_object;
#ifndef NO_BIGALLOCS
	if (__builtin_expect(SHOULD_PROMOTE_TO_BIGALLOC(allocptr, alloc_usable_size), 0))
	{
		void *bigalloc_begin = allocptr;
		assert(caller_requested_size <= alloc_usable_size - insert_size);
		// bigalloc size was the caller-usable size -- WHY? requested size seems better,
		// because then e.g. if caller is creating an arena, it knows how big it is
		struct big_allocation *this_chunk_b = __generic_malloc_fresh_big(arena->suballocator,
			allocptr, caller_requested_size, arena);
		if (!this_chunk_b) abort();
	}
	else
	{
#endif
		info->biggest_unpromoted_object = /* max */ (caller_usable_size > info->biggest_unpromoted_object)
			? caller_usable_size : info->biggest_unpromoted_object;
#ifndef NO_BIGALLOCS
	}
#endif

#undef insert_size
#ifdef TRACE_GENERIC_MALLOC_INDEX
	fprintf(stderr, "***[%09ld] Inserting user chunk at %p into bitmap at %p\n",
		info->bitmap_insert_count, allocptr, bitmap);
#endif
#if !defined(NDEBUG) || defined(TRACE_GENERIC_MALLOC_INDEX)
	++info->bitmap_insert_count;
#endif
	/* Add it to the bitmap. */
	bitmap_set_l(bitmap, (allocptr - info->bitmap_base_addr) / MALLOC_ALIGN);
out:
	BIG_UNLOCK
}

static inline void __generic_malloc_index_delete(struct allocator *a,
	struct arena_bitmap_info *info,
	void *userptr/*, size_t freed_usable_size*/,
	sizefn_t *sizefn)
{
	/* The freed_usable_size is not strictly necessary. It was added
	 * for handling realloc after-the-fact. In this case, by the time we
	 * get called, the usable size has already changed. However, after-the-fact
	 * was a broken way to handle realloc() when we are using trailers, because in
	 * the case of a *smaller* realloc'd size, where the realloc happens in-place,
	 * realloc() would overwrite our insert with its own (regular heap metadata)
	 * trailer.
	 */
	assert(userptr != NULL);
#ifndef NO_ALLOC_CACHE
	void *allocptr = userptr;
	__liballocs_uncache_all(allocptr, sizefn(allocptr)); // FIXME: per-allocator call
#endif

#ifdef TRACE_GENERIC_MALLOC_INDEX
	/* Check the recently-freed list for this pointer. We will warn about
	 * a double-free if we hit it. */
	for (int i = 0; i < RECENTLY_FREED_SIZE; ++i)
	{
		if (recently_freed[i] == userptr)
		{
			fprintf(stderr, "*** Double free detected for alloc chunk %p\n",
				userptr);
			return;
		}
	}
#endif
#ifndef NO_BIGALLOCS
	/* Is this a chunk that got promoted into a bigalloc?
	 * FIXME: since we no longer have the 'arena' bigalloc,
	 * this search is slightly slower than before. We stopped receiving the
	 * arena so that these functions could be used in a pure bitmap context,
	 */
	struct big_allocation *b = __lookup_bigalloc_under(userptr, /*arena->suballocator*/ a,
		/*arena*/ NULL, NULL);
	/* If so, we promoted this chunk into the bigalloc index. We are still
	 * keeping its metadata locally, though. */
	if (__builtin_expect(b != NULL, 0))
	{
		void *allocptr = userptr;
		unsigned long size = sizefn(allocptr); // FIXME: use per-alloc call
#ifdef TRACE_GENERIC_MALLOC_INDEX
		fprintf(stderr, "*** Unindexing bigalloc entry for alloc chunk %p (size %lu)\n",
				allocptr, size);
#endif
		__liballocs_delete_bigalloc_at(userptr, b->allocated_by);
#ifdef TRACE_GENERIC_MALLOC_INDEX
		*info->next_recently_freed_to_replace = userptr;
		++info->next_recently_freed_to_replace;
		if (info->next_recently_freed_to_replace == &info->recently_freed[RECENTLY_FREED_SIZE])
		{
			info->next_recently_freed_to_replace = &info->recently_freed[0];
		}
#endif
		return;
	}
#endif
	int lock_ret;
	BIG_LOCK
	bitmap_word_t *bitmap = info->bitmap;
#ifndef NO_BIGALLOCS
	struct big_allocation *arena = __lookup_bigalloc_under_by_suballocator(userptr,
		a,
		/*arena*/ NULL, NULL);
	/* The address *must* be in our tracked range. Assert this. */
	assert(info->bitmap_base_addr == ROUND_DOWN_PTR(arena->begin, MALLOC_ALIGN*BITMAP_WORD_NBITS));
#endif
	assert((uintptr_t) userptr >= (uintptr_t) info->bitmap_base_addr);
	bitmap_clear_l(bitmap, ((uintptr_t) userptr - (uintptr_t) info->bitmap_base_addr)
			/ MALLOC_ALIGN);

#ifdef TRACE_GENERIC_MALLOC_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from bitmap at %p\n",
		userptr, bitmap);
#endif

	/* (old comment; still true?) FIXME: we need a big lock around realloc()
	 * to avoid concurrent in-place realloc()s messing with the other inserts we access. */

out:
#ifdef TRACE_GENERIC_MALLOC_INDEX
	*info->next_recently_freed_to_replace = userptr;
	++info->next_recently_freed_to_replace;
	if (info->next_recently_freed_to_replace == &info->recently_freed[RECENTLY_FREED_SIZE])
	{
		info->next_recently_freed_to_replace = &info->recently_freed[0];
	}
#endif
	BIG_UNLOCK
}

static inline
void __generic_malloc_index_reinsert_after_resize(
	struct allocator *a,
	struct arena_bitmap_info *oldinfo, /* new and old need not share a bitmap! */
	void *userptr,
	size_t modified_size,
	size_t old_usable_size,
	size_t requested_size,
	const void *caller, void *new_allocptr, sizefn_t *sizefn)
{
	if (new_allocptr && new_allocptr != userptr)
	{
		/* FIXME: check the new type metadata against the old! We can probably do this
		 * in a way that's uniform with memcpy... the new chunk will take its type
		 * from the realloc site, and we then check compatibility on the copy. */
		struct arena_bitmap_info *newinfo = ensure_arena_info_for_userptr(a, new_allocptr);
		__generic_malloc_index_insert(a, newinfo, new_allocptr,
			requested_size, __current_allocsite ?: caller, sizefn);
		/* HACK: this is a bit racy. Not sure what to do about it really. We can't
		 * pre-copy (we *could* speculatively pre-snapshot though, into a thread-local
		 * buffer, or a fresh buffer allocated on an "exactly one live per thread" basis). */
		/* FIXME: THIS IS BROKEN when using lifetime extension: userptr is not
		 * pointing to valid memory but is read through... */
#ifndef LIFETIME_POLICIES
		__notify_copy(new_allocptr, userptr,
			caller_usable_size_for_chunk_and_usable_size(userptr, old_usable_size));
#endif
	}
	else // !new_allocptr || new_allocptr == userptr
	{
		/* Re-index at the same start address. The old usable size
		 * is the *modified* size, i.e. we modified it before
		 * allocating it, so we pass it as the modified_size to
		 * __generic_malloc_index_insert. */
		// FIXME: is this right? what if new_allocptr is null?
		__generic_malloc_index_insert(a, oldinfo, userptr, requested_size,
			__current_allocsite ? __current_allocsite : caller, sizefn);
	}
#ifndef NO_BIGALLOCS
	/* Are we a bigalloc? */
	struct big_allocation *b = __lookup_bigalloc_from_root(userptr, a, NULL);
	if (new_allocptr == userptr && modified_size < old_usable_size && b)
	{
		__liballocs_truncate_bigalloc_at_end(b, (char*) userptr + modified_size);
	}
#endif
}

static inline
struct insert *lookup_object_info_via_bitmap(struct arena_bitmap_info *info,
	void *mem, void **out_object_start, size_t *out_object_size, void **ignored,
	sizefn_t *sizefn)
{
	struct insert *found_ins = NULL;  //lookup(arena, mem, &l01_object_start);
	unsigned long nbits_hidden = 0;
	void *object_start = NULL;
	unsigned start_idx;
	unsigned long found_bitidx;

	if (!info) goto out;
	start_idx = ((uintptr_t) mem - (uintptr_t) info->bitmap_base_addr) / MALLOC_ALIGN;
	/* OPTIMISATION: exploit the maximum object size,
	 * to set a "fake" bitmap base address that serves as the maximum
	 * extent of the search. In effect, the earlier part of the bitmap is "hidden"
	 * i.e. we will skip searching within it. This is achieved by by passing a
	 * higher base address to bitmap_rfind_first_set_leq_l. */
#ifdef NDEBUG
	{
		void *fake_bitmap_base_addr = ROUND_DOWN_PTR((uintptr_t) mem -
			(uintptr_t) info->biggest_unpromoted_object, MALLOC_ALIGN*BITMAP_WORD_NBITS);
		if ((uintptr_t) fake_bitmap_base_addr > (uintptr_t) info->bitmap_base_addr)
		{
			nbits_hidden = BITMAP_WORD_NBITS *
				(((uintptr_t) fake_bitmap_base_addr - (uintptr_t) info->bitmap_base_addr) /
				(MALLOC_ALIGN * BITMAP_WORD_NBITS));
		}
	}
#endif
	assert(nbits_hidden % BITMAP_WORD_NBITS == 0);
	found_bitidx = bitmap_rfind_first_set_leq_l(
		info->bitmap + (nbits_hidden / BITMAP_WORD_NBITS),
		info->bitmap + info->nwords,
		start_idx - nbits_hidden, NULL);
	if (found_bitidx != (unsigned long) -1)
	{
		found_bitidx += nbits_hidden;
		object_start = info->bitmap_base_addr + (MALLOC_ALIGN * found_bitidx);
		found_ins = insert_for_chunk(object_start, sizefn);
	}
	if (found_ins)
	{
		assert(object_start);
		if (out_object_start) *out_object_start = object_start;
		if (out_object_size) *out_object_size = usersize(object_start, sizefn);
	}
out:
	assert(!found_ins || INSERT_DESCRIBES_OBJECT(found_ins));
	return found_ins;
}

/* A client-friendly lookup function. */
static inline
struct insert *lookup_object_info(struct big_allocation *arena,
	void *mem, void **out_object_start, size_t *out_object_size, void **ignored,
	sizefn_t *sizefn)
{
	/* Unlike our malloc hooks, we might get called before initialization,
	   e.g. if someone tries to do a lookup before the first malloc of the
	   program's execution. Rather than putting an initialization check
	   in the fast-path functions, we bail here.  */
	if (!big_allocations[1].begin) return NULL;

	/* We no longer "ensure" the info on a query. Rather, the
	 * lookup_object_info_via_bitmap call will fail fast if the info is NULL. 
	 * If there's no bitmap, there's no object. FIXME: is this really always
	 * true? What about an interior pointer query? i.e. is it valid to issue
	 * a query starting "off the end" of the known heap, and expect it to
	 * correctly search backwards? That might depend how up-to-date our "known" is. */
#if 0
	struct arena_bitmap_info *info = ensure_arena_has_info(arena);
	ensure_has_bitmap_to(a, info, arena->end);
	assert(info->bitmap_base_addr == ROUND_DOWN_PTR(arena->begin, MALLOC_ALIGN*BITMAP_WORD_NBITS));
#endif
	return lookup_object_info_via_bitmap(arena_info_for_userptr(arena->suballocator, mem),
		mem, out_object_start, out_object_size, ignored, sizefn);
}

static inline
liballocs_err_t __generic_malloc_get_info(struct allocator *a, sizefn_t *sizefn,
	void *obj, struct big_allocation *maybe_the_allocation,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_heap_case;
	/* For heap allocations, we look up the allocation site.
	 * (This also yields an offset within a toplevel object.)
	 * Then we translate the allocation site to a uniqtypes rec location.
	 * (For direct calls in eagerly-loaded code, we can cache this information
	 * within uniqtypes itself. How? Make uniqtypes include a hash table with
	 * initial contents mapping allocsites to uniqtype recs. This hash table
	 * is initialized during load, but can be extended as new allocsites
	 * are discovered, e.g. indirect ones.)
	 */
	struct insert *heap_info = NULL;
	void *base;
	size_t caller_usable_size;
	/* NOTE: bigallocs already have the size adjusted to exclude the insert. */
	if (maybe_the_allocation && maybe_the_allocation->allocated_by == a)
	{
		/* Promoted allocation: we already have the metadata. */
		base = maybe_the_allocation->begin;
		caller_usable_size = (char*) maybe_the_allocation->end - (char*) maybe_the_allocation->begin;
		heap_info = insert_for_chunk_and_caller_usable_size(base, caller_usable_size
			+ sizeof (struct extended_insert));
	}
	else
	{
		size_t alloc_usable_chunksize = 0;
		heap_info = lookup_object_info_via_bitmap(arena_info_for_userptr(a, obj),
			obj, &base, &alloc_usable_chunksize, NULL, sizefn);
		if (!heap_info)
		{
			/* For an unindexed non-promoted chunk, we don't know the base, so
			 * we don't know the logical size. We don't know anything. Note that
			 * for promoted chunks, we might know the size and base because we
			 * can promote to bigalloc knowing just the original base pointer, from
			 * which malloc_usable_size() can do the rest. */
			++__liballocs_aborted_unindexed_heap;
			return &__liballocs_err_unindexed_heap_object;
		}
		assert(base);
		caller_usable_size = caller_usable_size_for_chunk_and_usable_size(base,
			alloc_usable_chunksize);
	}
	assert(heap_info);
	if (out_base) *out_base = base;
	if (out_size) *out_size = caller_usable_size;
	if (out_type || out_site) return __liballocs_extract_and_output_alloc_site_and_type(
		heap_info, out_type, (void**) out_site);
	// no error
	return NULL;
}

static inline
liballocs_err_t __generic_malloc_set_type(struct allocator *a,
	struct big_allocation *maybe_the_allocation, void *obj,
	struct uniqtype *new_type, sizefn_t *sizefn)
{
	struct insert *ins = lookup_object_info(arena_for_userptr(a, obj), obj,
		NULL, NULL, NULL, sizefn);
	if (!ins) return &__liballocs_err_unindexed_heap_object;
	ins->alloc_site = (uintptr_t) new_type;
	ins->alloc_site_flag = 1; // meaning it's a type, not a site
	return NULL;
}

#endif
