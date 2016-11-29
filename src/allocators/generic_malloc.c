/* 
 * TODO:
 * lock-free bin walking using Harris's algorithm
 * produce allocator-specific versions (dlmalloc, initially) that 
 * - don't need headers/trailers...
 * - ... by stealing bits from the host allocator's "size" field (64-bit only)
 * keep chunk lists sorted within each bin?
 */

/* This file uses GNU C extensions */
#define _GNU_SOURCE

#include <sys/types.h>
/* liballocs definitely defines these internally */
size_t malloc_usable_size(void *ptr) __attribute__((visibility("protected")));
size_t __real_malloc_usable_size(void *ptr) __attribute__((visibility("protected")));
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#ifdef MALLOC_USABLE_SIZE_HACK
#include <dlfcn.h>
extern "C" {
static inline size_t malloc_usable_size(void *ptr) __attribute__((visibility("protected")));
}
#else
size_t malloc_usable_size(void *ptr);
#endif
#include "liballocs_private.h"
#include "relf.h"

// HACK for libcrunch -- please remove (similar to malloc_usable_size -> __mallochooks_*)
void __libcrunch_uncache_all(const void *allocptr, size_t size) __attribute__((weak));

static void *allocptr_to_userptr(void *allocptr);
static void *userptr_to_allocptr(void *allocptr);

#define ALLOCPTR_TO_USERPTR(p) (allocptr_to_userptr(p))
#define USERPTR_TO_ALLOCPTR(p) (userptr_to_allocptr(p))

#ifndef EXTRA_INSERT_SPACE
#define EXTRA_INSERT_SPACE 0
#endif

#define ALLOC_EVENT_QUALIFIERS __attribute__((visibility("hidden")))

#include "alloc_events.h"
#include "heap_index.h"
#include "pageindex.h"

#ifndef NO_PTHREADS
#define BIG_LOCK \
	lock_ret = pthread_mutex_lock(&mutex); \
	assert(lock_ret == 0);
#define BIG_UNLOCK \
	lock_ret = pthread_mutex_unlock(&mutex); \
	assert(lock_ret == 0);
/* We're recursive only because assertion failures sometimes want to do 
 * asprintf, so try to re-acquire our mutex. */
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

#else
#define BIG_LOCK
#define BIG_UNLOCK
#endif

#ifndef NO_TLS
__thread void *__current_allocsite;
__thread void *__current_allocfn;
__thread size_t __current_allocsz;
__thread int __currently_freeing;
__thread int __currently_allocating;
#else
void *__current_allocsite;
void *__current_allocfn;
size_t __current_allocsz;
int __currently_freeing;
int __currently_allocating;
#endif

#ifdef MALLOC_USABLE_SIZE_HACK
#include "malloc_usable_size_hack.h"
#endif

#ifdef TRACE_HEAP_INDEX
/* Size the circular buffer of recently freed chunks */
#define RECENTLY_FREED_SIZE 100
#endif

#ifdef TRACE_HEAP_INDEX
/* Keep a circular buffer of recently freed chunks */
static void *recently_freed[RECENTLY_FREED_SIZE];
static void **next_recently_freed_to_replace = &recently_freed[0];
#endif

struct entry *index_region __attribute__((aligned(64))) /* HACK for cacheline-alignedness */;
unsigned long biggest_unpromoted_object __attribute__((visibility("protected")));
void *index_max_address;
int safe_to_call_malloc;

void *index_begin_addr;
void *index_end_addr;
#ifndef LOOKUP_CACHE_SIZE
#define LOOKUP_CACHE_SIZE 4
#endif

struct lookup_cache_entry;
static void install_cache_entry(void *object_start,
	size_t usable_size, unsigned short depth, _Bool is_deepest,
	struct insert *insert);
static void invalidate_cache_entries(void *object_start,
	unsigned short depths_mask,
	struct insert *ins, signed nentries);
static int cache_clear_deepest_flag_and_update_ins(void *object_start,
	unsigned short depths_mask,
	struct insert *ins, signed nentries,
	struct insert *new_ins);

/* The (unsigned) -1 conversion here provokes a compiler warning,
 * which we suppress. There are two ways of doing this.
 * One is to turn the warning off and back on again, clobbering the former setting.
 * Another is, if the GCC version we have allows it (must be > 4.6ish),
 * to use the push/pop mechanism. If we can't pop, we leave it "on" (conservative).
 * To handle the case where we don't have push/pop, 
 * we also suppress pragma warnings, then re-enable them. :-) */
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
static void check_impl_sanity(void)
{
	assert(PAGE_SIZE == sysconf(_SC_PAGE_SIZE));
	assert(LOG_PAGE_SIZE == integer_log2(PAGE_SIZE));

	assert(sizeof (struct entry) == 1);
	assert(
			entry_to_offset((struct entry){ .present = 1, .removed = 0, .distance = (unsigned) -1})
			+ entry_to_offset((struct entry){ .present = 1, .removed = 0, .distance = 1 }) 
		== entry_coverage_in_bytes);
}
/* First, re-enable the overflow pragma, to be conservative. */
#pragma GCC diagnostic warning "-Woverflow"
/* Now, if we have "pop", we will restore it to its actual former setting. */
#pragma GCC diagnostic pop
#pragma GCC diagnostic warning "-Wpragmas"

static _Bool tried_to_init;

static void
do_init(void)
{
	/* Optionally delay, for attaching a debugger. */
	if (getenv("HEAP_INDEX_DELAY_INIT")) sleep(8);

	/* Check we got the shift logic correct in entry_to_offset, and other compile-time logic. */
	check_impl_sanity();
	
	/* If we're already trying to initialize, or have already
	 * tried, don't try recursively/again. */
	if (tried_to_init) return;
	tried_to_init = 1;
	
	if (index_region) return; /* already done */

	/* Initialize what we depend on. */
	__mmap_allocator_init();
	
	index_begin_addr = (void*) 0U;
#if defined(__x86_64__) || defined(x86_64)
	index_end_addr = (void*)(1ULL<<47); /* it's effectively a 47-bit address space */
#else
	index_end_addr = (void*) 0U; /* both 0 => cover full address range */
#endif
	
	size_t mapping_size = MEMTABLE_MAPPING_SIZE_WITH_TYPE(struct entry,
		entry_coverage_in_bytes, 
		index_begin_addr,
		index_end_addr
	);

	if (mapping_size > BIGGEST_MMAP_ALLOWED)
	{
#ifndef NDEBUG
		fprintf(stderr, "%s: warning: mapping %lld bytes not %ld\n",
			__FILE__, BIGGEST_MMAP_ALLOWED, mapping_size);
		fprintf(stderr, "%s: warning: only bottom 1/%lld of address space is tracked.\n",
			__FILE__, mapping_size / BIGGEST_MMAP_ALLOWED);
#endif
		mapping_size = BIGGEST_MMAP_ALLOWED;
		/* Back-calculate what address range we can cover from this mapping size. */
		unsigned long long nentries = mapping_size / sizeof (entry_type);
		void *one_past_max_indexed_address = index_begin_addr +
			nentries * entry_coverage_in_bytes;
		index_end_addr = one_past_max_indexed_address;
	}
	
	/* HACK: always place at 0x400000000000, to avoid problems with shadow space. */
	index_region = MEMTABLE_NEW_WITH_TYPE_AT_ADDR(struct entry, 
		entry_coverage_in_bytes, index_begin_addr, index_end_addr, (const void*) 0x400000000000ul);
	debug_printf(3, "heap_index at %p\n", index_region);
	
	assert(index_region != MAP_FAILED);
}

void post_init(void) __attribute__((visibility("hidden")));
void post_init(void)
{
	do_init();
}

static inline struct insert *insert_for_chunk(void *userptr);
static void index_delete(void *userptr);

#ifndef NDEBUG
/* In this newer, more space-compact implementation, we can't do as much
 * sanity checking. Check that if our entry is not present, our distance
 * is 0. */
#define INSERT_SANITY_CHECK(p_t) assert( \
	!(!((p_t)->un.ptrs.next.present) && !((p_t)->un.ptrs.next.removed) && (p_t)->un.ptrs.next.distance != 0) \
	&& !(!((p_t)->un.ptrs.prev.present) && !((p_t)->un.ptrs.prev.removed) && (p_t)->un.ptrs.prev.distance != 0))

static void list_sanity_check(entry_type *head, const void *should_see_chunk)
{
	void *head_chunk = entry_ptr_to_addr(head);
	_Bool saw_should_see_chunk = 0;
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr,
		"Begin sanity check of list indexed at %p, head chunk %p\n",
		head, head_chunk);
#endif
	void *cur_userchunk = head_chunk;
	unsigned count = 0;
	while (cur_userchunk != NULL)
	{
		++count;
		if (should_see_chunk && cur_userchunk == should_see_chunk) saw_should_see_chunk = 1;
		INSERT_SANITY_CHECK(insert_for_chunk(cur_userchunk));
		/* If the next chunk link is null, entry_to_same_range_addr
		 * should detect this (.present == 0) and give us NULL. */
		void *next_userchunk
		 = entry_to_same_range_addr(
			insert_for_chunk(cur_userchunk)->un.ptrs.next, 
			cur_userchunk
		);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "List has a chunk beginning at userptr %p"
			" (usable_size %zu, insert {next: %p, prev %p})\n",
			cur_userchunk, 
			malloc_usable_size(userptr_to_allocptr(cur_userchunk)),
			next_userchunk,
			entry_to_same_range_addr(
				insert_for_chunk(cur_userchunk)->un.ptrs.prev, 
				cur_userchunk
			)
		);
#endif
		assert(next_userchunk != head_chunk);
		assert(next_userchunk != cur_userchunk);

		/* If we're not the first element, we should have a 
		 * prev chunk. */
		if (count > 1) assert(NULL != entry_to_same_range_addr(
				insert_for_chunk(cur_userchunk)->un.ptrs.prev, 
				cur_userchunk
			));


		cur_userchunk = next_userchunk;
	}
	if (should_see_chunk && !saw_should_see_chunk)
	{
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "Was expecting to find chunk at %p\n", should_see_chunk);
#endif

	}
	assert(!should_see_chunk || saw_should_see_chunk);
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr,
		"Passed sanity check of list indexed at %p, head chunk %p, "
		"length %d\n", head, head_chunk, count);
#endif
}
#else /* NDEBUG */
#define INSERT_SANITY_CHECK(p_t)
static void list_sanity_check(entry_type *head, const void *should_see_chunk) {}
#endif

// static void memset_index_big_chunk(void *userptr, struct entry value)
// {
// 	void *allocptr = userptr_to_allocptr(userptr);
// 	/* Allow allocs beginning a short distance into the entry to be 
// 	 * treated as beginning at the start of the entry.
// 	 * This is because the malloc header. should not prevent an initial
// 	 * entry from being marked as belonging to the bigalloc. */
// 	_Bool covers_whole_initial_entry = ((uintptr_t) allocptr) % PAGE_SIZE
// 		 <= MAXIMUM_MALLOC_HEADER_OVERHEAD;
// 	char *malloc_end_address = (char*) allocptr + malloc_usable_size(allocptr);
// 	_Bool covers_whole_final_entry = (0 == ((uintptr_t) malloc_end_address % 
// 		entry_coverage_in_bytes));
// 	struct entry *start_entry = covers_whole_initial_entry ? 
// 		INDEX_LOC_FOR_ADDR(userptr)
// 			: INDEX_LOC_FOR_ADDR(userptr) + 1;
// 	struct entry *end_entry = covers_whole_final_entry ? 
// 		INDEX_LOC_FOR_ADDR((char*) malloc_end_address)
// 			: INDEX_LOC_FOR_ADDR((char*) malloc_end_address) - 1;
// 	size_t n = (end_entry - start_entry) * sizeof (struct entry);
// #ifndef NDEBUG
// 	/* CHECK that we're really overwriting what we expect.*/
// 	struct entry bigalloc_value = { 0, 1, 63 };
// 	assert(IS_BIGALLOC_ENTRY(&bigalloc_value));
// 	char bigalloc_accept[] = { *(char*) &bigalloc_value, '\0' };
// 	struct entry empty_value = { 0, 0, 0 };
// 	assert(IS_EMPTY_ENTRY(&empty_value));
// 	if (*(char*) &bigalloc_value == *(char*) &value)
// 	{
// 		/* Check we see n empties */
// 		/* We can't use strspn to compare against zero bytes. Instead, use memcmp! */
// 		char zeroes[n];
// 		bzero(zeroes, n);
// 		_Bool ok = (0 == memcmp(zeroes, (char*) start_entry, n));
// 		assert(ok);
// 	} else if (*(char*) &empty_value == *(char*) &value)
// 	{
// 		size_t n_ok = strspn((char*) start_entry, bigalloc_accept);
// 		assert(n_ok >= n);
// 	}
// #endif
// 	if (end_entry > start_entry)
// 	{
// 		memset(start_entry, 
// 			*(char*) &value, 
// 			n
// 		);
// 	}
// }

static void 
index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller);

void 
__liballocs_index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller)
{
	index_insert(new_userchunkaddr, modified_size, caller);
}

static unsigned long index_insert_count;

#define PROMOTE_TO_BIGALLOC(userchunk) \
	(malloc_usable_size(userptr_to_allocptr((userchunk))) \
				 > /* HACK: default glibc lower mmap threshold: 128 kB */ 131072)
/* We also apply a hack which helps performance: if a malloc chunk begins
 * within a very short distance of a page boundary, pretend that it begins
 * on the page boundary, for the purposes of bigallocs. This is to ensure
 * that queries on the first page of a large object don't go down a slower
 * path. FIXME: I've a feeling it currently breaks some alloca cases.
 * ARGH. It actually breaks everything, because we need to undo the offset
 * when interpreting the block's uniqtype. Don't do it, for now. */
#define BIGALLOC_BEGIN(allocptr) (allocptr) /* \
	(((uintptr_t)(allocptr)) % PAGE_SIZE <= MAXIMUM_MALLOC_HEADER_OVERHEAD) \
	 ? (void*)(ROUND_DOWN_PTR((allocptr), PAGE_SIZE)) : (allocptr) \
	)*/
	
static struct big_allocation *fresh_big(void *allocptr, size_t bigalloc_size, 
	struct insert ins, struct big_allocation *containing_bigalloc)
{
	char *bigalloc_begin = BIGALLOC_BEGIN(allocptr);
	struct big_allocation *b = __liballocs_new_bigalloc(
		bigalloc_begin,
		bigalloc_size,
		(struct meta_info) {
			/* HMM: we could use an opaque pointer to the "real" insert, but 
			 * instead we make a copy of that insert. This is perhaps better for
			 * locality, since the big_allocation record is more likely
			 * to be in the cache. FIXME: measure this. Would be cleaner to use ptr. */
			.what = INS_AND_BITS,
			.un = {
				ins_and_bits: { 
					.ins = ins
				}
			}
		},
		containing_bigalloc,
		&__generic_malloc_allocator
	);
		
	if (!b) abort();
	return b;
}

static struct big_allocation *become_big(void *allocptr, size_t bigalloc_size, 
	struct insert ins, struct big_allocation *containing_bigalloc)
{
	/* It's only legal call this if allocptr is already an allocation. */
	index_delete(allocptr_to_userptr(allocptr));
	return fresh_big(allocptr, bigalloc_size, ins, containing_bigalloc);
}

static struct big_allocation *ensure_big(void *addr)
{
	void *start;
	struct big_allocation *maybe_already = __lookup_bigalloc(addr, 
		&__generic_malloc_allocator, &start);
	if (maybe_already) return maybe_already;
	
	size_t size;
	const void *site;
	struct uniqtype *t;
	liballocs_err_t err = __generic_heap_get_info(addr, NULL, &t, &start, &size, &site);
	if (err && err != &__liballocs_err_unrecognised_alloc_site) abort();
	
	return become_big(userptr_to_allocptr(start), size, t ? (struct insert) {
						.alloc_site_flag = 1,
						.alloc_site = (uintptr_t) t
					} : (struct insert) {
						.alloc_site_flag = 0,
						.alloc_site = (uintptr_t) site
					}, __lookup_deepest_bigalloc(start));
}
static void 
index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller)
{
	int lock_ret;
	BIG_LOCK
	
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) do_init();
	assert(index_region);
	
	/* The address *must* be in our tracked range. Assert this. */
	assert(new_userchunkaddr <= (index_end_addr ? index_end_addr : MAP_FAILED));
	
#ifdef TRACE_HEAP_INDEX
	/* Check the recently freed list for this pointer. Delete it if we find it. */
	for (int i = 0; i < RECENTLY_FREED_SIZE; ++i)
	{
		if (recently_freed[i] == new_userchunkaddr)
		{ 
			recently_freed[i] = NULL;
			next_recently_freed_to_replace = &recently_freed[i];
		}
	}
#endif
	
	/* Make sure the parent bigalloc knows we're suballocating it. */
	char *allocptr = userptr_to_allocptr(new_userchunkaddr);
	struct big_allocation *containing_bigalloc = __lookup_deepest_bigalloc(
		userptr_to_allocptr(new_userchunkaddr));
	if (!containing_bigalloc) abort();
	if (unlikely(!containing_bigalloc->suballocator))
	{
		containing_bigalloc->suballocator = &__generic_malloc_allocator;
	} else assert(containing_bigalloc->suballocator == &__generic_malloc_allocator
		|| containing_bigalloc->suballocator == &__alloca_allocator);
	// FIXME: split alloca off into a separate table?
	
	/* Populate our extra in-chunk fields */
	struct insert *p_insert = insert_for_chunk(new_userchunkaddr);
	p_insert->alloc_site_flag = 0U;
	p_insert->alloc_site = (uintptr_t) caller;
	
	struct big_allocation *this_chunk_bigalloc = NULL;
	/* If we're big enough, 
	 * push our metadata into the bigalloc map. 
	 * (Do we still index it at l1? NO, but this stores up complication when we need to promote it.  */
	if (__builtin_expect(
			PROMOTE_TO_BIGALLOC(new_userchunkaddr)
			/* NOTE: no longer do we have to be page-aligned to use the bigalloc map */
			, 
		0))
	{
		char *bigalloc_begin = BIGALLOC_BEGIN(allocptr);
		size_t extra_size = allocptr - bigalloc_begin;
		size_t bigalloc_size = modified_size - sizeof (struct insert) + extra_size;
		this_chunk_bigalloc = fresh_big(allocptr, bigalloc_size,
			(struct insert) {
						.alloc_site_flag = 0,
						.alloc_site = (uintptr_t) caller
					}, containing_bigalloc);
		if (!this_chunk_bigalloc) abort();
		BIG_UNLOCK
		return;
	}
	
	/* if we got here, it's going in l1 */
	if (modified_size > biggest_unpromoted_object) biggest_unpromoted_object = modified_size;

	struct entry *index_entry = INDEX_LOC_FOR_ADDR(new_userchunkaddr);

	/* DEBUGGING: sanity check entire bin */
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "***[%09ld] Inserting user chunk at %p into list indexed at %p\n", 
		index_insert_count, new_userchunkaddr, index_entry);
#endif
#if !defined(NDEBUG) || defined(TRACE_HEAP_INDEX)
	++index_insert_count;
#endif
	list_sanity_check(index_entry, NULL);

	void *head_chunkptr = entry_ptr_to_addr(index_entry);
	

	/* Add it to the index. We always add to the start of the list, for now. */
	/* 1. Initialize our insert. */
	p_insert->un.ptrs.next = addr_to_entry(head_chunkptr);
	p_insert->un.ptrs.prev = addr_to_entry(NULL);
	assert(!p_insert->un.ptrs.prev.present);
	
	/* 2. Fix up the next insert, if there is one */
	if (p_insert->un.ptrs.next.present)
	{
		insert_for_chunk(entry_to_same_range_addr(p_insert->un.ptrs.next, new_userchunkaddr))->un.ptrs.prev
		 = addr_to_entry(new_userchunkaddr);
	}
	/* 3. Fix up the index. */
	*index_entry = addr_to_entry(new_userchunkaddr); // FIXME: thread-safety

	/* sanity checks */
	struct entry *e = index_entry;
	assert(e->present); // it's there
	assert(insert_for_chunk(entry_ptr_to_addr(e)));
	assert(insert_for_chunk(entry_ptr_to_addr(e)) == p_insert);
	INSERT_SANITY_CHECK(p_insert);
	if (p_insert->un.ptrs.next.present) INSERT_SANITY_CHECK(
		insert_for_chunk(entry_to_same_range_addr(p_insert->un.ptrs.next, new_userchunkaddr)));
	if (p_insert->un.ptrs.prev.present) INSERT_SANITY_CHECK(
		insert_for_chunk(entry_to_same_range_addr(p_insert->un.ptrs.prev, new_userchunkaddr)));
	list_sanity_check(e, new_userchunkaddr);
	
	BIG_UNLOCK
}

void 
post_successful_alloc(void *allocptr, size_t modified_size, size_t modified_alignment, 
		size_t requested_size, size_t requested_alignment, const void *caller)
		__attribute__((visibility("hidden")));
void 
post_successful_alloc(void *allocptr, size_t modified_size, size_t modified_alignment, 
		size_t requested_size, size_t requested_alignment, const void *caller)
{
	index_insert(allocptr /* == userptr */, modified_size, __current_allocsite ? __current_allocsite : caller);
	safe_to_call_malloc = 1; // if somebody succeeded, anyone should succeed
}

void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller) __attribute__((visibility("hidden")));
void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller)
{
	/* We increase the size by the amount of extra data we store, 
	 * and possibly a bit more to allow for alignment.  */
	size_t orig_size = *p_size;
	/* Add the size of struct insert, and round this up to the align of struct insert. 
	 * This ensure we always have room for an *aligned* struct insert. */
	size_t size_with_insert = orig_size + sizeof (struct insert) + EXTRA_INSERT_SPACE;
	size_t size_to_allocate = PAD_TO_ALIGN(size_with_insert, sizeof (struct insert));
	assert(0 == size_to_allocate % ALIGNOF(struct insert));
	*p_size = size_to_allocate;
}

struct insert *__liballocs_insert_for_chunk_and_usable_size(void *userptr, size_t usable_size)
{
	return insert_for_chunk_and_usable_size(userptr, usable_size);
}

static void index_delete(void *userptr);

void 
__liballocs_index_delete(void *userptr)
{
	index_delete(userptr);
}

static void index_delete(void *userptr/*, size_t freed_usable_size*/)
{
	/* The freed_usable_size is not strictly necessary. It was added
	 * for handling realloc after-the-fact. In this case, by the time we
	 * get called, the usable size has already changed. However, after-the-fact
	 * was a broken way to handle realloc() when we were using trailers instead
	 * of inserts, because in the case of a *smaller*
	 * realloc'd size, where the realloc happens in-place, realloc() would overwrite
	 * our insert with its own (regular heap metadata) trailer, breaking the list.
	 */
	
	if (userptr == NULL) return; // HACK: shouldn't be necessary; a BUG somewhere
	
	/* HACK for libcrunch cache invalidation */
	if (__libcrunch_uncache_all)
	{
		void *allocptr = userptr_to_allocptr(userptr);
		__libcrunch_uncache_all(allocptr, malloc_usable_size(allocptr));
	}
	
	int lock_ret;
	BIG_LOCK
	
#ifdef TRACE_HEAP_INDEX
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
	
	/* We promoted this entry into the bigalloc index. We still
	 * kept its metadata locally, though. */
	struct entry *index_entry = INDEX_LOC_FOR_ADDR(userptr);
	/* Are we a bigalloc? */
	struct big_allocation *b = __lookup_bigalloc(userptr, 
			&__generic_malloc_allocator, NULL);
	if (b)
	{
		void *allocptr = userptr_to_allocptr(userptr);
		unsigned long size = malloc_usable_size(allocptr);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "*** Unindexing bigalloc entry for alloc chunk %p (size %lu)\n", 
				allocptr, size);
#endif
		//unsigned start_remainder = ((uintptr_t) allocptr) % PAGE_SIZE;
		//unsigned end_remainder = (((uintptr_t) allocptr) + size) % PAGE_SIZE;
		
		//unsigned expected_pagewise_size = size 
		//		+ start_remainder
		//		+ ((end_remainder == 0) ? 0 : PAGE_SIZE - end_remainder);
		__liballocs_delete_bigalloc_at(userptr_to_allocptr(userptr), 
			&__generic_malloc_allocator);
		// memset the covered entries with the empty value
		//struct entry empty_value = { 0, 0, 0 };
		//assert(IS_EMPTY_ENTRY(&empty_value));
		//memset_index_big_chunk(userptr, empty_value);
		
#ifdef TRACE_HEAP_INDEX
		*next_recently_freed_to_replace = userptr;
		++next_recently_freed_to_replace;
		if (next_recently_freed_to_replace == &recently_freed[RECENTLY_FREED_SIZE])
		{
			next_recently_freed_to_replace = &recently_freed[0];
		}
#endif
		
		BIG_UNLOCK
		return;
	}

#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from list indexed at %p\n", 
		userptr, index_entry);
#endif
	
	unsigned suballocated_region_number = 0;
	struct insert *ins = insert_for_chunk(userptr);
	//if (ALLOC_IS_SUBALLOCATED(userptr, ins)) 
	//{
	//	suballocated_region_number = (uintptr_t) ins->alloc_site;
	//}

	list_sanity_check(index_entry, userptr);
	INSERT_SANITY_CHECK(insert_for_chunk/*_with_usable_size*/(userptr/*, freed_usable_size*/));

	/* (old comment; still true?) FIXME: we need a big lock around realloc()
	 * to avoid concurrent in-place realloc()s messing with the other inserts we access. */

	/* remove it from the bins */
	void *our_next_chunk = entry_to_same_range_addr(insert_for_chunk(userptr)->un.ptrs.next, userptr);
	void *our_prev_chunk = entry_to_same_range_addr(insert_for_chunk(userptr)->un.ptrs.prev, userptr);
	
	/* FIXME: make these atomic */
	if (our_prev_chunk) 
	{
		INSERT_SANITY_CHECK(insert_for_chunk(our_prev_chunk));
		insert_for_chunk(our_prev_chunk)->un.ptrs.next = addr_to_entry(our_next_chunk);
	}
	else /* !our_prev_chunk */
	{
		/* removing head of the list */
		*index_entry = addr_to_entry(our_next_chunk);
		if (!our_next_chunk)
		{
			/* ... it's a singleton list, so 
			 * - no prev chunk to update
			 * - the index entry should be non-present
			 * - exit */
			assert(index_entry->present == 0);
			goto out;
		}
	}

	if (our_next_chunk) 
	{
		INSERT_SANITY_CHECK(insert_for_chunk(our_next_chunk));
		
		/* may assign NULL here, if we're removing the head of the list */
		insert_for_chunk(our_next_chunk)->un.ptrs.prev = addr_to_entry(our_prev_chunk);
	}
	else /* !our_next_chunk */
	{
		/* removing tail of the list... */
		/* ... and NOT a singleton -- we've handled that case already */
		assert(our_prev_chunk);
	
		/* update the previous chunk's insert */
		insert_for_chunk(our_prev_chunk)->un.ptrs.next = addr_to_entry(NULL);

		/* nothing else to do here, as we don't keep a tail pointer */
	}
	/* Now that we have deleted the record, our bin should be sane,
	 * modulo concurrent reallocs. */
out:
#ifdef TRACE_HEAP_INDEX
	*next_recently_freed_to_replace = userptr;
	++next_recently_freed_to_replace;
	if (next_recently_freed_to_replace == &recently_freed[RECENTLY_FREED_SIZE])
	{
		next_recently_freed_to_replace = &recently_freed[0];
	}
#endif
	invalidate_cache_entries(userptr, (unsigned short) -1, NULL, -1);
	list_sanity_check(index_entry, NULL);
	
	BIG_UNLOCK
}

void pre_nonnull_free(void *userptr, size_t freed_usable_size) __attribute__((visibility("hidden")));
void pre_nonnull_free(void *userptr, size_t freed_usable_size)
{
	index_delete(userptr/*, freed_usable_size*/);
}

void post_nonnull_free(void *userptr) __attribute__((visibility("hidden")));
void post_nonnull_free(void *userptr) 
{}

void pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller) __attribute__((visibility("hidden")));
void pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller)
{
	/* When this happens, we *may or may not be freeing an area*
	 * -- i.e. if the realloc fails, we will not actually free anything.
	 * However, whn we were using trailers, and 
	 * in the case of realloc()ing a *slightly smaller* region, 
	 * the allocator might trash our insert (by writing its own data over it). 
	 * So we *must* delete the entry first,
	 * then recreate it later, as it may not survive the realloc() uncorrupted. */
	
	/* Another complication: if we're realloc'ing a bigalloc, we might have to
	 * move its children. BUT should the user ever do this? It's only sensible
	 * to realloc a suballocated area if you know the realloc will happen in-place, 
	 * i.e. if you're making it smaller (only). 
	 * 
	 * BUT some bigallocs are just big; they needn't have children. 
	 * For those, does it matter if we delete and then re-create the bigalloc record?
	 * I don't see why it should.
	 */
	// struct entry *index_entry = INDEX_LOC_FOR_ADDR(userptr);

	index_delete(userptr/*, malloc_usable_size(ptr)*/);
}
void post_nonnull_nonzero_realloc(void *userptr, 
	size_t modified_size, 
	size_t old_usable_size,
	const void *caller, void *__new_allocptr)
{
	/* Are we a bigalloc? */
	struct big_allocation *b = __lookup_bigalloc(userptr, 
			&__generic_malloc_allocator, NULL);
	if (__new_allocptr && __new_allocptr != userptr)
	{
		/* Create a new bin entry. This will also take care of becoming a bigalloc, etc..
		 * FIXME: check the new type metadata against the old! We can probably do this
		 * in a way that's uniform with memcpy... the new chunk will take its type
		 * from the realloc site, and we then check compatibility on the copy. */
		index_insert(allocptr_to_userptr(__new_allocptr), 
				modified_size, __current_allocsite ? __current_allocsite : caller);
		/* HACK: this is a bit racy. Not sure what to do about it really. We can't
		 * pre-copy (we *could* speculatively pre-snapshot though, into a thread-local
		 * buffer, or a fresh buffer allocated on an "exactly one live per thread" basis). */
		__notify_copy(__new_allocptr, userptr, old_usable_size - sizeof (struct insert) - EXTRA_INSERT_SPACE);
	}
	else // !__new_allocptr || __new_allocptr == userptr
	{
		/* *recreate* the old bin entry! The old usable size
		 * is the *modified* size, i.e. we modified it before
		 * allocating it, so we pass it as the modified_size to
		 * index_insert. */
		// FIXME: is this right? what if __new_allocptr is null?
		index_insert(userptr, old_usable_size, __current_allocsite ? __current_allocsite : caller);
	}
	
	if (__new_allocptr == userptr && modified_size < old_usable_size)
	{
		if (b)
		{
			__liballocs_truncate_bigalloc_at_end(b, (char*) userptr + modified_size);
		}
	}
	
	/* If the old alloc has gone away, do the malloc_hooks call the free hook on it? 
	 * YES: it was done before the realloc, in the pre-hook. */
}

// same but zero bytes, not bits
static int nlzb1(unsigned long x) {
	int n;

	if (x == 0) return 8;
	n = 0;

	if (x <= 0x00000000FFFFFFFFL) { n += 4; x <<= 32; }
	if (x <= 0x0000FFFFFFFFFFFFL) { n += 2; x <<= 16; }
	if (x <= 0x00FFFFFFFFFFFFFFL) { n += 1;  x <<= 8; }
	
	return n;
}

static inline unsigned char *rfind_nonzero_byte(unsigned char *one_beyond_start, unsigned char *last_good_byte)
{
#define SIZE (sizeof (unsigned long))
#define IS_ALIGNED(p) (((uintptr_t)(p)) % (SIZE) == 0)

	unsigned char *p = one_beyond_start;
	/* Do the unaligned part */
	while (!IS_ALIGNED(p))
	{
		--p;
		if (p < last_good_byte) return NULL;
		if (*p != 0) return p;
	}
	// now p is aligned and any address >=p is not the one we want
	// (if we had an aligned pointer come in, we don't want it -- it's one_beyond_start)

	/* Do the aligned part. */
	while (p-SIZE >= last_good_byte)
	{
		p -= SIZE;
		unsigned long v = *((unsigned long *) p);
		if (v != 0ul)
		{
			// HIT -- but what is the highest nonzero byte?
			int nlzb = nlzb1(v); // in range 0..7
			return p + SIZE - 1 - nlzb;
		}
	}
	// now we have tested all bytes from p upwards
	// and p-SIZE < last_good_byte
	long nbytes_remaining = p - last_good_byte;
	assert(nbytes_remaining < SIZE);
	assert(nbytes_remaining >= 0);
	
	/* Do the unaligned part */
	while (p > last_good_byte)
	{
		--p;
		if (*p != 0) return p;
	}
	
	return NULL;
#undef IS_ALIGNED
#undef SIZE
}

static inline _Bool find_next_nonempty_bin(struct entry **p_cur, 
		struct entry *limit,
		size_t *p_object_minimum_size
		)
{
	size_t max_nbytes_coverage_to_scan = biggest_unpromoted_object - *p_object_minimum_size;
	size_t max_nbuckets_to_scan = 
			(max_nbytes_coverage_to_scan % entry_coverage_in_bytes) == 0 
		?    max_nbytes_coverage_to_scan / entry_coverage_in_bytes
		:    (max_nbytes_coverage_to_scan / entry_coverage_in_bytes) + 1;
	unsigned char *limit_by_size = (unsigned char *) *p_cur - max_nbuckets_to_scan;
	unsigned char *limit_to_pass = (limit_by_size > (unsigned char *) index_region)
			 ? limit_by_size : (unsigned char *) index_region;
	unsigned char *found = rfind_nonzero_byte((unsigned char *) *p_cur, limit_to_pass);
	if (!found) 
	{ 
		*p_object_minimum_size += (((unsigned char *) *p_cur) - limit_to_pass) * entry_coverage_in_bytes; 
		*p_cur = (struct entry *) limit_to_pass;
		return 0;
	}
	else
	{ 
		*p_object_minimum_size += (((unsigned char *) *p_cur) - found) * entry_coverage_in_bytes; 
		*p_cur = (struct entry *) found; 
		return 1;
	}

	// FIXME: adapt http://www.int80h.org/strlen/ 
	// or memrchr.S from eglibc
	// to do what we want.
}

#ifndef LOOKUP_CACHE_SIZE
#define LOOKUP_CACHE_SIZE 4
#endif
struct lookup_cache_entry
{
	void *object_start;
	size_t usable_size:60;
	unsigned short depth:3;
	unsigned short is_deepest:1;
	struct insert *insert;
} lookup_cache[LOOKUP_CACHE_SIZE];
static struct lookup_cache_entry *next_to_evict = &lookup_cache[0];

static void check_cache_sanity(void)
{
#ifndef NDEBUG
	for (int i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		assert(!lookup_cache[i].object_start 
				|| (INSERT_DESCRIBES_OBJECT(lookup_cache[i].insert)
					&& lookup_cache[i].depth <= 2));
	}
#endif
}

static void install_cache_entry(void *object_start,
	size_t object_size,
	unsigned short depth, 
	_Bool is_deepest,
	struct insert *insert)
{
	check_cache_sanity();
	/* our "insert" should always be the insert that describes the object,
	 * NOT one that chains into the suballocs table. */
	assert(INSERT_DESCRIBES_OBJECT(insert));
	assert(next_to_evict >= &lookup_cache[0] && next_to_evict < &lookup_cache[LOOKUP_CACHE_SIZE]);
	*next_to_evict = (struct lookup_cache_entry) {
		object_start, object_size, depth, is_deepest, insert
	}; // FIXME: thread safety
	// don't immediately evict the entry we just created
	next_to_evict = &lookup_cache[(next_to_evict + 1 - &lookup_cache[0]) % LOOKUP_CACHE_SIZE];
	assert(next_to_evict >= &lookup_cache[0] && next_to_evict < &lookup_cache[LOOKUP_CACHE_SIZE]);
	check_cache_sanity();
}

static void invalidate_cache_entries(void *object_start,
	unsigned short depths_mask,
	struct insert *ins,
	signed nentries)
{
	unsigned ninvalidated = 0;
	check_cache_sanity();
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if ((!object_start || object_start == lookup_cache[i].object_start)
				&& (!ins || ins == lookup_cache[i].insert)
				&& (0 != (1<<lookup_cache[i].depth & depths_mask))) 
		{
			lookup_cache[i] = (struct lookup_cache_entry) {
				NULL, 0, 0, 0, NULL
			};
			next_to_evict = &lookup_cache[i];
			check_cache_sanity();
			++ninvalidated;
			if (nentries > 0 && ninvalidated >= nentries) return;
		}
	}
	check_cache_sanity();
}

static int cache_clear_deepest_flag_and_update_ins(void *object_start,
	unsigned short depths_mask,
	struct insert *ins,
	signed nentries,
	struct insert *new_ins)
{
	unsigned ncleared = 0;
	// we might be used to restore the cache invariant, so don't check
	// check_cache_sanity();
	assert(ins);
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if ((!object_start || object_start == lookup_cache[i].object_start)
				&& (ins == lookup_cache[i].insert)
				&& (0 != (1<<lookup_cache[i].depth & depths_mask))) 
		{
			lookup_cache[i].is_deepest = 0;
			lookup_cache[i].insert = new_ins;
			check_cache_sanity();
			++ncleared;
			if (nentries > 0 && ncleared >= nentries) return ncleared;
		}
	}
	check_cache_sanity();
	return ncleared;
}

static
struct insert *lookup_l01_object_info(const void *mem, void **out_object_start);
static
struct insert *lookup_l01_object_info_nocache(const void *mem, void **out_object_start);

static 
struct insert *object_insert(const void *obj, struct insert *ins)
{
	return ins;
}
/* A client-friendly lookup function that knows about bigallocs.
 * FIXME: this needs to go away! Clients shouldn't have to know about inserts,
 * and not all allocators maintain them. */
struct insert *__liballocs_get_insert(const void *mem)
{
	struct big_allocation *b = __lookup_bigalloc(mem,
		&__generic_malloc_allocator, NULL);
	if (b)
	{
		assert(b->meta.what == INS_AND_BITS);
		return &b->meta.un.ins_and_bits.ins;
	}
	else return lookup_object_info(mem, NULL, NULL, NULL);
}

/* A client-friendly lookup function with cache. */
struct insert *lookup_object_info(const void *mem, void **out_object_start, size_t *out_object_size,
		void **ignored)
{
	/* Unlike our malloc hooks, we might get called before initialization,
	   e.g. if someone tries to do a lookup before the first malloc of the
	   program's execution. Rather than putting an initialization check
	   in the fast-path functions, we bail here.  */
	if (!index_region) return NULL;
	
	/* Try matching in the cache. NOTE: how does this impact bigalloc and deep-indexed 
	 * entries? In all cases, we cache them here. We also keep a "is_deepest" flag
	 * which tells us (conservatively) whether it's known to be the deepest entry
	 * indexing that storage. In this function, we *only* return a cache hit if the 
	 * flag is set. (In lookup_l01_object_info, this logic is different.) */
	check_cache_sanity();
	void *l01_object_start = NULL;
	struct insert *found_l01 = NULL;
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if (lookup_cache[i].object_start && 
				(char*) mem >= (char*) lookup_cache[i].object_start && 
				(char*) mem < (char*) lookup_cache[i].object_start + lookup_cache[i].usable_size)
		{
			// possible hit
			if (lookup_cache[i].depth == 1 || lookup_cache[i].depth == 0)
			{
				l01_object_start = lookup_cache[i].object_start;
				found_l01 = lookup_cache[i].insert;
			}
			
			if (lookup_cache[i].is_deepest)
			{
				// HIT!
				assert(lookup_cache[i].object_start);
	#if defined(TRACE_DEEP_HEAP_INDEX) || defined(TRACE_HEAP_INDEX)
				fprintf(stderr, "Cache hit at pos %d (%p) with alloc site %p\n", i, 
						lookup_cache[i].object_start, (void*) (uintptr_t) lookup_cache[i].insert->alloc_site);
				fflush(stderr);
	#endif
				assert(INSERT_DESCRIBES_OBJECT(lookup_cache[i].insert));

				if (out_object_start) *out_object_start = lookup_cache[i].object_start;
				if (out_object_size) *out_object_size = lookup_cache[i].usable_size;
				// ... so ensure we're not about to evict this guy
				if (next_to_evict - &lookup_cache[0] == i)
				{
					next_to_evict = &lookup_cache[(i + 1) % LOOKUP_CACHE_SIZE];
					assert(next_to_evict - &lookup_cache[0] < LOOKUP_CACHE_SIZE);
				}
				assert(INSERT_DESCRIBES_OBJECT(lookup_cache[i].insert));
				return lookup_cache[i].insert;
			}
		}
	}
	
	// didn't hit cache, but we may have seen the l01 entry
	struct insert *found;
	void *object_start;
	unsigned short depth = 1;
	if (found_l01)
	{
		/* CARE: the cache's p_ins points to the alloc's insert, even if it's been
		 * moved (in the suballocated case). So we re-lookup the physical insert here. */
		found = insert_for_chunk(l01_object_start);
	}
	else
	{
		found = lookup_l01_object_info_nocache(mem, &l01_object_start);
	}
	size_t size;

	if (found)
	{
		size = usersize(l01_object_start);
		object_start = l01_object_start;
		_Bool is_deepest = INSERT_DESCRIBES_OBJECT(found);
		
		// cache the l01 entry
		install_cache_entry(object_start, size, 1, is_deepest, object_insert(object_start, found));
		
		if (!is_deepest)
		{
			assert(l01_object_start);
			/* deep case */
			void *deep_object_start;
			size_t deep_object_size;
			struct insert *found_deeper = NULL; /*lookup_deep_alloc(mem, 1, found, &deep_object_start, 
					&deep_object_size, &containing_chunk_rec);*/
			if (found_deeper)
			{
				assert(0);
				// override the values we assigned just now
				object_start = deep_object_start;
				found = found_deeper;
				size = deep_object_size;
				// cache this too
				//g_entry(object_start, size, 2 /* FIXME */, 1 /* FIXME */, 
				//	found);
			}
			else
			{
				// we still have to point the metadata at the *sub*indexed copy
				assert(!INSERT_DESCRIBES_OBJECT(found));
				found = object_insert(mem, found);
			}
		}


		if (out_object_start) *out_object_start = object_start;
		if (out_object_size) *out_object_size = size;
	}
	
	assert(!found || INSERT_DESCRIBES_OBJECT(found));
	return found;
}

static
struct insert *lookup_l01_object_info(const void *mem, void **out_object_start) 
{
	// first, try the cache
	check_cache_sanity();
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if (lookup_cache[i].object_start && 
				lookup_cache[i].depth <= 1 && 
				(char*) mem >= (char*) lookup_cache[i].object_start && 
				(char*) mem < (char*) lookup_cache[i].object_start + lookup_cache[i].usable_size)
		{
			// HIT!
			struct insert *real_ins = object_insert(lookup_cache[i].object_start, lookup_cache[i].insert);
#if defined(TRACE_DEEP_HEAP_INDEX) || defined(TRACE_HEAP_INDEX)
			fprintf(stderr, "Cache[l01] hit at pos %d (%p) with alloc site %p\n", i, 
					lookup_cache[i].object_start, (void*) (uintptr_t) real_ins->alloc_site);
			fflush(stderr);
#endif
			assert(INSERT_DESCRIBES_OBJECT(real_ins));
			
			if (out_object_start) *out_object_start = lookup_cache[i].object_start;

			// ... so ensure we're not about to evict this guy
			if (next_to_evict - &lookup_cache[0] == i)
			{
				next_to_evict = &lookup_cache[(i + 1) % LOOKUP_CACHE_SIZE];
				assert(next_to_evict - &lookup_cache[0] < LOOKUP_CACHE_SIZE);
			}
			// return the possibly-SUBALLOC insert -- not the one from the cache
			return insert_for_chunk(lookup_cache[i].object_start);
		}
	}
	
	return lookup_l01_object_info_nocache(mem, out_object_start);
}

static
struct insert *lookup_l01_object_info_nocache(const void *mem, void **out_object_start) 
{
	struct entry *first_head = INDEX_LOC_FOR_ADDR(mem);
	struct entry *cur_head = first_head;
	size_t object_minimum_size = 0;

	// Optimisation: if we see an object
	// in the current bucket that starts before our object, 
	// but doesn't span the address we're searching for,
	// we don't need to look at previous buckets, 
	// because we know that our pointer can't be an interior
	// pointer into some object starting in a earlier bucket's region.
	_Bool seen_object_starting_earlier = 0;
	do
	{
		seen_object_starting_earlier = 0;
		
		if (__builtin_expect(IS_BIGALLOC_ENTRY(cur_head), 0))
		{
			// we shouldn't need this any more
			abort();
			// return __lookup_bigalloc_with_insert(mem, &__generic_malloc_allocator, out_object_start);
		}
	
// 		if (__builtin_expect(IS_DEEP_ENTRY(cur_head), 0))
// 		{
// 			if (cur_head != first_head)
// 			{
// 				/* If we didn't point into non-deep-indexed memory at ptr,
// 				 * we're not going to find our allocation in a deep-indexed
// 				 * region, since we always upgrade units of at least a whole
// 				 * chunk. So we can abort now. 
// 				 */
// #ifdef TRACE_DEEP_HEAP_INDEX
// 				fprintf(stderr, "Strayed into deep-indexed region (bucket base %p) "
// 						"searching for chunk overlapping %p, so aborting\n", 
// 					ADDR_FOR_INDEX_LOC(cur_head), mem);
// #endif
// 				goto fail;
// 			}
// 			struct deep_entry_region *region;
// 			struct deep_entry *found = lookup_deep_alloc((void*) mem, /*cur_head,*/ -1, -1, &region, &seen_object_starting_earlier);
// 			// did we find an overlapping object?
// 			if (found)
// 			{
// 				if (out_deep) *out_deep = found;
// 				void *object_start = (char*) region->base_addr + (found->distance_4bytes << 2);
// 				if (out_object_start) *out_object_start = object_start;
// 				install_cache_entry(object_start, (found->size_4bytes << 2), &found->u_tail.ins);
// 				return &found->u_tail.ins;
// 			}
// 			else
// 			{
// 				// we should at least have a region
// 				assert(region);
// 				// resume the search from the next-lower index
// 				cur_head = INDEX_LOC_FOR_ADDR((char*) region->base_addr - 1);
// 				continue;
// 			}
// 		}
		
		void *cur_userchunk = entry_ptr_to_addr(cur_head);

		while (cur_userchunk)
		{
			struct insert *cur_insert = insert_for_chunk(cur_userchunk);
#ifndef NDEBUG
			/* Sanity check on the insert. */
			if ((char*) cur_insert < (char*) cur_userchunk
				|| (char*) cur_insert - (char*) cur_userchunk > biggest_unpromoted_object)
			{
				fprintf(stderr, "Saw insane insert address %p for chunk beginning %p "
					"(usable size %zu, allocptr %p); memory corruption?\n", 
					cur_insert, cur_userchunk, 
					malloc_usable_size(userptr_to_allocptr(cur_userchunk)), 
					userptr_to_allocptr(cur_userchunk));
			}	
#endif
			if (mem >= cur_userchunk
				&& mem < cur_userchunk + malloc_usable_size(userptr_to_allocptr(cur_userchunk))) 
			{
				// match!
				if (out_object_start) *out_object_start = cur_userchunk;
				return cur_insert;
			}
			
			// do that optimisation
			if (cur_userchunk < mem) seen_object_starting_earlier = 1;
			
			cur_userchunk = entry_to_same_range_addr(cur_insert->un.ptrs.next, cur_userchunk);
		}
		
		/* we reached the end of the list */ // FIXME: use assembly-language replacement for cur_head--
	} while (!seen_object_starting_earlier
		&& find_next_nonempty_bin(&cur_head, &index_region[0], &object_minimum_size)); 
fail:
	//fprintf(stderr, "Heap index lookup failed for %p with "
	//	"cur_head %p, object_minimum_size %zu, seen_object_starting_earlier %d\n",
	//	mem, cur_head, object_minimum_size, (int) seen_object_starting_earlier);
	return NULL;
	/* FIXME: use the actual biggest allocated object, not a guess. */
}

liballocs_err_t __generic_heap_get_info(void * obj, struct big_allocation *maybe_bigalloc, 
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_heap_case; // FIXME: needn't be heap -- could be alloca
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
	
	/* NOTE: bigallocs already have the size adjusted by the insert. */
	if (maybe_bigalloc)
	{
		/* We already have the metadata. */
		heap_info = &maybe_bigalloc->meta.un.ins_and_bits.ins;
		if (out_base) *out_base = maybe_bigalloc->begin;
		if (out_size) *out_size = (char*) maybe_bigalloc->end - (char*) maybe_bigalloc->begin;
	} 
	else
	{
		size_t alloc_chunksize;
		heap_info = lookup_object_info(obj, out_base, &alloc_chunksize, NULL);
		if (heap_info)
		{
			if (out_size) *out_size = alloc_chunksize - sizeof (struct insert) - EXTRA_INSERT_SPACE;
		}
	}
	
	if (!heap_info)
	{
		++__liballocs_aborted_unindexed_heap;
		return &__liballocs_err_unindexed_heap_object;
	}
	
	return extract_and_output_alloc_site_and_type(heap_info, out_type, (void**) out_site);
}

struct allocator __generic_malloc_allocator = {
	.name = "generic malloc",
	.get_info = __generic_heap_get_info,
	.is_cacheable = 1,
	.ensure_big = ensure_big
};
