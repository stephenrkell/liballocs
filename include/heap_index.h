#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include <stdbool.h>
#include "liballocs_config.h"
#include "pageindex.h"
#include "malloc-meta.h"
#include "bitmap.h"

int safe_to_call_malloc __attribute__((weak));

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

/* Now the stuff to do with the metadata 'insert'.
 * This will stick around. */

// FIXME: this needs to be per-arena, probably
// in the bigalloc or a malloc'd bit of suballocator-private metadata
extern unsigned long biggest_unpromoted_object __attribute__((weak,visibility("protected")));

/* Inserts describing objects have user addresses. They may have the flag set or unset. */
#define INSERT_DESCRIBES_OBJECT(ins) \
	(!((ins)->alloc_site) || (char*)((uintptr_t)((unsigned long long)((ins)->alloc_site))) >= MINIMUM_USER_ADDRESS)
#define INSERT_IS_NULL(p_ins) (!(p_ins)->alloc_site && !(p_ins)->alloc_site_flag)

/* What's the most space that a malloc header will use? 
 * We use this figure to guess when an alloc has been satisfied with mmap().  
 * Making it too big hurts performance but not correctness. */
#define MAXIMUM_MALLOC_HEADER_OVERHEAD 16

struct allocator;
extern struct allocator __generic_malloc_allocator;

#include "pageindex.h"

struct insert *lookup_object_info(struct big_allocation *arena, void *mem,
		void **out_object_start, size_t *out_object_size, 
		void **ignored) __attribute__((weak));


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
 *   |<------------------------------------>|       caller-usable
 *   |<---------------------------->|       |       requested by caller
 *                                  |<--->| |       padding to _Alignof (struct insert)  (maybe empty)
 *                                        |<-->|    size of insert
 *   |<--------------------------------------->|    how much we actually request from malloc
 *                                          |  <>|  possible padding added by malloc     (maybe empty)
 *                                          |<-->|  **the actual insert** is always at base + malloc_usable - sizeof insert
 *
 *   FIXME: this means inserts may be misaligned.
 *   In practice this seems not to happen, because
 *   malloc pads to a #words and inserts at word-sized.
 *
 * - 'requested size' means the size requested by the caller
 * - 'malloc usable size' means the size returned by malloc_usable_size(),
 *      which includes our trailer space
 *      (just 'usable size' by default also means this)
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

size_t malloc_usable_size(void *ptr);
static size_t allocsize_to_usersize(size_t usersize) { return usersize; }
static size_t usersize_to_allocsize(size_t allocsize) { return allocsize; }
static size_t usersize(void *userptr) { return allocsize_to_usersize(malloc_usable_size(userptr)); }
static size_t allocsize(void *allocptr) { return malloc_usable_size(allocptr); }

struct arena_bitmap_info
{
	unsigned long nwords;
	bitmap_word_t *bitmap;
	void *bitmap_base_addr;
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
#ifdef LIFETIME_POLICIES
typedef LIFETIME_INSERT_TYPE lifetime_insert_t;
#define LIFETIME_POLICY_FLAG(id) (0x1 << (id))
// By convention lifetime policy 0 is the manual deallocation policy
#define MANUAL_DEALLOCATION_POLICY 0
#define MANUAL_DEALLOCATION_FLAG LIFETIME_POLICY_FLAG(MANUAL_DEALLOCATION_POLICY)
// Manual deallocation is not an "attached" policy
#define HAS_LIFETIME_POLICIES_ATTACHED(lti) ((lti) & ~(MANUAL_DEALLOCATION_FLAG))
#endif

#if 0
struct extended_insert
{
#ifdef LIFETIME_POLICIES
	lifetime_insert_t lifetime;
#endif
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
#endif
#define extended_insert insert

static inline size_t caller_usable_size_for_chunk_and_malloc_usable_size(void *userptr,
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
static inline size_t caller_usable_size_for_chunk(void *userptr)
{
	return caller_usable_size_for_chunk_and_malloc_usable_size(userptr,
			malloc_usable_size(userptr));
}
static inline struct insert *insert_for_chunk(void *userptr)
{
	return insert_for_chunk_and_caller_usable_size(userptr,
		caller_usable_size_for_chunk(userptr));
}

#if 0
#ifdef LIFETIME_POLICIES
static inline lifetime_insert_t *lifetime_insert_for_chunk(void *userptr)
{
	return &extended_insert_for_chunk(userptr)->lifetime;
}
#endif
#endif

#endif
