/* This set of hook definitions will maintain a memtable of all
 * allocated heap chunks, and will store an "insert" in each chunk
 * tracking its allocation site. 
 *
 * Compile in C99 mode! We use raw "inline" and possibly other C99 things.
 *
 * For the fastest code, compile -O3 and -DNDEBUG. */

/* 
 * TODO:
 * some sort of thread safety
 * produce allocator-specific versions (dlmalloc, initially) that 
 * - don't need headers/trailers...
 * - ... by stealing bits from the host allocator's "size" field (64-bit only)
 * keep chunk lists sorted within each bin?
 */

/* This file uses GNU C extensions */
#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#ifdef MALLOC_USABLE_SIZE_HACK
#include <dlfcn.h>
extern "C" {
static inline size_t malloc_usable_size(void *ptr);
}
#else
size_t malloc_usable_size(void *ptr);
#endif

/* This defines core hooks, and static prototypes for our hooks. */
#ifndef MALLOC_HOOKS_INCLUDE
#define MALLOC_HOOKS_INCLUDE "malloc_hooks.c" 
#endif
/* This defines core hooks, and static prototypes for our hooks. */
#include MALLOC_HOOKS_INCLUDE

#include "heap_index.h"
#define BIGGEST_SENSIBLE_OBJECT (256*1024*1024)

/* For now, inserts increase memory usage.  
 * Ideally, we want to make headers/trailers which fit in reclaimed space. 
 * Specifically, we can steal bits from a "chunk size" field.
 * On 64-bit machines this is fairly easy. On 32-bit it's harder
 * because the size field is smaller! But it can be done.
 * I'll produce a hacked version of dlmalloc which does this,
 * at some point.... */ 

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

struct entry *index_region;
int safe_to_call_malloc;
void *index_max_address;

#define entry_coverage_in_bytes 512
typedef struct entry entry_type;
void *index_begin_addr;
void *index_end_addr;
#ifndef LOOKUP_CACHE_SIZE
#define LOOKUP_CACHE_SIZE 4
#endif

struct lookup_cache_entry;
static void install_cache_entry(void *object_start,
	size_t usable_size,
	struct deep_entry *deep,
	struct insert *insert);
static void invalidate_cache_entry(void *object_start,
	size_t usable_size);

/* "Distance" is a right-shifted offset within a memory region. */
static inline ptrdiff_t entry_to_offset(struct entry e) 
{ 
	assert(e.present); 
	return e.distance << DISTANCE_UNIT_SHIFT; 
}
static inline struct entry offset_to_entry(ptrdiff_t o) 
{ 
	return (struct entry) { .present = 1, .removed = 0, .distance = o >> DISTANCE_UNIT_SHIFT }; 
}
static inline void *entry_ptr_to_addr(struct entry *p_e)
{
	if (!p_e->present) return NULL;
	return MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(
		index_region,
		entry_type,
		entry_coverage_in_bytes,
		index_begin_addr,
		index_end_addr,
		p_e)
	+ entry_to_offset(*p_e);
}
static inline void *entry_to_same_range_addr(struct entry e, void *same_range_ptr)
{
	if (!e.present) return NULL;
	return MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(
		index_region,
		entry_type,
		entry_coverage_in_bytes,
		index_begin_addr,
		index_end_addr,
		same_range_ptr) + entry_to_offset(e);
}
static inline struct entry addr_to_entry(void *a)
{
	if (a == NULL) return (struct entry) { .present = 0, .removed = 0, .distance = 0 };
	else return offset_to_entry(
		MEMTABLE_ADDR_RANGE_OFFSET_WITH_TYPE(
			index_region, entry_type, entry_coverage_in_bytes, 
			index_begin_addr, index_end_addr,
			a
		)
	);
}

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

static unsigned page_size;
static unsigned log_page_size;

static void
init_hook(void)
{
	/* Optionally delay, for attaching a debugger. */
	if (getenv("HEAP_INDEX_DELAY_INIT")) sleep(8);

	/* Check we got the shift logic correct in entry_to_offset, and other compile-time logic. */
	check_impl_sanity();

	if (index_region) return; /* already done */
	
	index_begin_addr = (void*) 0U;
#if defined(__x86_64__) || defined(x86_64)
	index_end_addr = (void*)(1ULL<<48); /* it's effectively a 48-bit address space */
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
	
	index_region = MEMTABLE_NEW_WITH_TYPE(struct entry, 
		entry_coverage_in_bytes, index_begin_addr, index_end_addr);
	
	page_size = sysconf(_SC_PAGE_SIZE);
	log_page_size = integer_log2(page_size);
	
	assert(index_region != MAP_FAILED);
}

static inline struct insert *insert_for_chunk(void *userptr);

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

#define INDEX_LOC_FOR_ADDR(a) MEMTABLE_ADDR_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))
#define INDEX_BIN_START_ADDRESS_FOR_ADDR(a) MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))
#define INDEX_BIN_END_ADDRESS_FOR_ADDR(a) ((char*)(MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, ((char*)(a)))) + entry_coverage_in_bytes)
#define ADDR_FOR_INDEX_LOC(e) MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, index_begin_addr, index_end_addr, (e))

static uintptr_t nbytes_in_index_for_l0_entry(void *userchunk_base)
{
	assert(sysconf(_SC_PAGE_SIZE) == 4096);
	void *allocptr = userptr_to_allocptr(userchunk_base);
	void *end_addr = (char*) allocptr + malloc_usable_size(allocptr);
	uintptr_t begin_pagenum = ((uintptr_t) userchunk_base >> 12);
	uintptr_t end_pagenum = ((uintptr_t) end_addr >> 12)
			 + (((((uintptr_t) end_addr) % 4096) == 0) ? 0 : 1);
	unsigned long nbytes_in_index = ((end_pagenum - begin_pagenum) << 12)
			/ entry_coverage_in_bytes;
	return nbytes_in_index;
}

static void 
index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	assert(index_region);
	
	/* The address *must* be in our tracked range. Assert this. */
	assert(new_userchunkaddr <= (index_end_addr ? index_end_addr : MAP_FAILED));
	
	/* If we're entirely within a mmap()'d region, 
	 * and if we cover all of it, 
	 * push our metadata into the l0 map. 
	 * (Do we still index it at l1? NO, but this stores up complication when we need to promote it.  */
	if (__builtin_expect(
			modified_size > /* HACK: default glibc lower mmap threshold: 128 kB */ 131072
			&& (uintptr_t) userptr_to_allocptr(new_userchunkaddr) % page_size <= MAXIMUM_MALLOC_HEADER_OVERHEAD
				&& &__try_index_l0, 
		0))
	{
		const struct insert *ins = __try_index_l0(userptr_to_allocptr(new_userchunkaddr), modified_size, caller);
		if (ins)
		{
			// memset the covered entries with the l0 value
			struct entry l0_value = { 0, 1, 63 };
			assert(IS_L0_ENTRY(&l0_value));
			memset(INDEX_LOC_FOR_ADDR(new_userchunkaddr), *(char*) &l0_value, 
				nbytes_in_index_for_l0_entry(new_userchunkaddr));
			assert(IS_L0_ENTRY(INDEX_LOC_FOR_ADDR(new_userchunkaddr)));
			assert(IS_L0_ENTRY(INDEX_LOC_FOR_ADDR((char*) new_userchunkaddr + modified_size - 1)));
			return;
		}
	}

	struct entry *index_entry = INDEX_LOC_FOR_ADDR(new_userchunkaddr);
	
	/* If we got a deep alloc entry, do the deep thing. */
	if (__builtin_expect(IS_DEEP_ENTRY(index_entry), 0))
	{
		_Bool unset_allocsite = 0;
		if (!__current_allocsite) { __current_allocsite = (void *) caller; unset_allocsite = 1; }
		assert(__current_allocsite == caller);
		__index_deep_alloc(new_userchunkaddr, 1, malloc_usable_size(userptr_to_allocptr(new_userchunkaddr)));
		if (unset_allocsite) __current_allocsite = NULL;
		return;
	}

	/* DEBUGGING: sanity check entire bin */
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Inserting user chunk at %p into list indexed at %p\n", 
		new_userchunkaddr, index_entry);
#endif
	list_sanity_check(index_entry, NULL);

	void *head_chunkptr = entry_ptr_to_addr(index_entry);
	
	/* Populate our extra fields */
	struct insert *p_insert = insert_for_chunk(new_userchunkaddr);
	p_insert->alloc_site_flag = 0U;
	p_insert->alloc_site = (unsigned long) caller;

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
}

/* "headers" versions */
// static void *allocptr_to_userptr(void *allocptr)
// {
// 	/* The no-breadcrumb case is the common case. */
// 	if (!allocptr) return NULL;
// 	if (__builtin_expect(
// 			(uintptr_t) ((struct insert *) allocptr)->alloc_site >= 0x1000,
// 			1)
// 		)
// 	{
// 		return (char *)allocptr + sizeof (struct insert);
// 	}
// 	else
// 	{
// 		/* The alloc-to-user breadcrumb case: the allocsite field low-order bits hold 
// 		 * the alignment as a power of two, from which we can compute the user ptr. */
// 		size_t requested_alignment
// 		 = 1ul << (((uintptr_t) (((struct insert *) allocptr)->alloc_site)) & 0xfff);
// 		uintptr_t userptr
// 		 = requested_alignment * (
// 				((uintptr_t) ((char *)allocptr + sizeof (struct insert)) / requested_alignment) + 1);
// 		return (void*) userptr;
// 	}
// }
// 
// static void *userptr_to_allocptr(void *userptr)
// {
// 	/* The no-breadcrumb case is the common case. */
// 	if (!userptr) return NULL;
// 	if (__builtin_expect(
// 			(uintptr_t) ((struct insert *) ((char *) userptr - sizeof (struct insert)))
// 				->alloc_site >= 0x1000,
// 			1)
// 		)
// 	{
// 		return (char *)userptr - sizeof (struct insert);
// 	}
// 	else
// 	{
// 		/* The user-to-alloc breadcrumb case: the allocsite field low-order bits hold
// 		 * the alignment. */
// 		size_t log_requested_alignment = ((uintptr_t) ((((struct insert *) userptr)-1)->alloc_site)) & 0xfff;
// 		size_t requested_alignment = 1ul << log_requested_alignment;
// 		
// 		// 
// 		// 	userptr = requested_alignment * (((uintptr_t) (allocptr + sizeof(struct insert)) / requested_alignment) + 1);
// 		// 
// 		// => userptr / requested_alignment == (((uintptr_t) (allocptr + sizeof(struct insert)) / requested_alignment) + 1);
// 		// 
// 		// => (u / r_a) - 1 == (((uintptr_t) (allocptr + sizeof(struct insert)) / requested_alignment)
// 		//
// 		// => r_a * ((u / r_a) - 1) + remainder == allocptr + sizeof(struct insert)
// 		// 
// 		// and we have asserted that the remainder == sizeof (struct insert), so 
// 		// 
// 		// => allocptr == r_a * ((u / r_a) - 1) - sizeof (struct insert) + remainder
// 		// 
// 		// => allocptr == r_a * ((u / r_a) - 1)
// 
// 		uintptr_t allocptr
// 		 = requested_alignment * (((uintptr_t) userptr >> log_requested_alignment) - 1);
// 		assert(allocptr_to_userptr((void*) allocptr) == userptr);
// 		return (void*) allocptr;
// 	}
// }
// 
// // "headers" version
// static inline struct insert *insert_for_chunk(void *userptr)
// {
// 	/* The no-breadcrumb case is the common case */
// 	struct insert *possible = (struct insert*) ((char*) userptr - sizeof (struct insert));
// 	if (__builtin_expect(
// 			(uintptr_t) possible->alloc_site >= 0x1000, 
// 			1)
// 		)
// 	{
// 		return possible;
// 	}
// 	else
// 	{
// 		/* The real insert is *two* insert-sizes back. */
// 		return (struct insert*) ((char*) userptr - 2 * sizeof (struct insert));
// 	}
// }

static void *userptr_to_allocptr(void *userptr) { return userptr; }
static void *allocptr_to_userptr(void *allocptr) { return allocptr; }
static size_t allocsize_to_usersize(size_t usersize) { return usersize; }
static size_t usersize_to_allocsize(size_t allocsize) { return allocsize; }
static size_t usersize(void *userptr) { return allocsize_to_usersize(malloc_usable_size(userptr_to_allocptr(userptr))); }
static size_t allocsize(void *allocptr) { return malloc_usable_size(allocptr); }
static inline struct insert *insert_for_chunk_and_usable_size(void *userptr, size_t usable_size);
static inline struct insert *insert_for_chunk(void *userptr)
{
	return insert_for_chunk_and_usable_size(userptr, malloc_usable_size(userptr)); 
}
static inline struct insert *insert_for_chunk_and_usable_size(void *userptr, size_t usable_size)
{
	return (struct insert*) ((char*) userptr + usable_size) - 1;
}
static void 
post_successful_alloc(void *allocptr, size_t modified_size, size_t modified_alignment, 
		size_t requested_size, size_t requested_alignment, const void *caller)
{
/* "headers" version */
// 	/* We always index just the userptr! index_insert will use 
// 	 * insert_for_chunk to find its insert, even if it uses breadcrumbs. */
// 	void *candidate_userptr = (char*) allocptr + sizeof (struct insert); // HACK: shouldn't know this here
// 	void *userptr;
// 	
// 	/* We need to set up breadcrumbs *right now*, because index_insert will want them. */
// 	/* Since we have the pointer we were actually allocated, 
// 	 * we can be conservative about whether to use breadcrumbs.  */
// 	if (__builtin_expect((uintptr_t) candidate_userptr % requested_alignment != 0, 0))
// 	{
// 		/* We need breadcrumbs case: set up breadcrumbs so that our userptr 
// 		 * and allocptr can be found from one another. We must have
// 		 * at least three inserts' worth of space in the chunk -- which 
// 		 * we ensured in pre_alloc. */
// 		
// 		userptr = (void*)(requested_alignment * (((uintptr_t) candidate_userptr / requested_alignment) + 1));
// 		// i.e.
// 		// userptr = requested_alignment * (((uintptr_t) ((char*) allocptr + sizeof (struct insert)) / requested_alignment) + 1);
// 		assert((char *) userptr >= (char*) allocptr + 3 * sizeof (struct insert));
// 		assert(userptr < allocptr + modified_size);
// #ifdef TRACE_HEAP_INDEX
// 		fprintf(stderr, "Alignment/breadcrumb logic issued user ptr %p for alloc ptr %p " 
// 					"(user requested align %d, hook requested align %d, user requested size %d, hook requested size %d)\n", 
// 					userptr, allocptr, requested_alignment, modified_alignment,
// 					requested_size, modified_size);
// #endif
// 		/* We need to be able to reproduce the above userptr calculation 
// 		 * in the alloc-to-user case, and *invert* it in the user-to-alloc case. 
// 		 *
// 		 * Reproducing it: store the requested alignment, as a power of two.
// 		 
// 		 * Inverting it: this means storing the *remainder* of the division. 
// 		 * How large can the remainder get? Clearly it's in the range 
// 		 * 0..(requested_alignment - 1).
// 		 * And since we got it from allocptr + sizeof (struct insert), 
// 		 * and allocptr is modified_alignment-aligned, 
// 		 * it's very likely to be one word, or else one word plus some power of two
// 		 * less than the modified alignment but greater than or equal to the 
// 		 * requested alignment. That's only one possible power of two! 
// 		 * I'm going to assert that it's one word, and figure out what's happening
// 		 * in other cases via debugging. */
// 		uintptr_t remainder = ((uintptr_t) candidate_userptr % requested_alignment);
// 		assert(remainder == sizeof (struct insert));
// 		
// 		// user-to-alloc breadcrumb
// 		struct insert bu = { 0, integer_log2(requested_alignment), 0, 0 };
// 		// alloc_to_user breadcrumb
// 		struct insert ba = { 0, integer_log2(requested_alignment), 0, 0 };
// 		// actual insert: initialized by index_insert
// 		
// 		// write the breadcrumbs into the chunk
// 		*(struct insert *)allocptr = ba;
// 		*(((struct insert *)userptr) - 1) = bu;
// 	} 
// 	else
// 	{
// 		userptr = candidate_userptr;
// 		/* HACK: 
// 		 * we need to pre-initialize the insert because until we have a valid 
// 		 * alloc_site, insert_to_chunk can't tell where to find the real insert
// 		 * versus where the breadcrumbs are.
// 		 */ 
// 		*(((struct insert *)userptr) - 1) = (struct insert) { 0, (uintptr_t) caller, 0, 0};
// 	}
// 	
// 	index_insert(userptr, modified_size, __current_allocsite ? __current_allocsite : caller);
	
	/* Detect the case where malloc is using mmap(). We can optimise this 
	 * as follows.
	 * 
	 * - In our interval tree, record the area as being homogeneously of the same type.
	 * 
	 * - If we convert any of the region to a deep alloc region, we won't need to seek
	 *   backwards a long way in the memtable to discover this (cf. finding a trailer)
	 *   because all the memtable entries will be set to point to the deep region. 
	 * 
	 * - Note that large sub-allocated regions are still not handled very well. 
	 *   We can argue that that's a less common case. If you want large objects,
	 *   you're better off calling to a l0 or l1-level allocator; in practice 
	 *   malloc, at l1, degenerates itself to the l0 mmap() case for precisely
	 *   this reason. */
	 
	safe_to_call_malloc = 1; // if somebody succeeded, anyone should succeed
	
	index_insert(allocptr /* == userptr */, modified_size, __current_allocsite ? __current_allocsite : caller);
}

static void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller)
{
	/* We increase the size by the amount of extra data we store, 
	 * and possibly a bit more to allow for alignment.  */
	size_t orig_size = *p_size;
	size_t size_to_allocate = orig_size + sizeof (struct insert);
/* "headers" version */
// 	if (*p_alignment > sizeof (void*))
// 	{
// 		// bump up size by alignment or two inserts (for breadcrumbs), whichever is more
// 		size_t two_inserts = 2 * sizeof (struct insert);
// 		size_to_allocate += (two_inserts > *p_alignment) ? two_inserts : *p_alignment;
// 		*p_alignment *= 2;
// 		
// 		/* Why is this sufficient? Recall that if we have a nontrivial alignment, 
// 		 * it's because we're calling memalign. Memalign *will* return a pointer with
// 		 * the requested alignment; it's just that our alloc-to-user is going
// 		 * to destroy that alignment. 
// 		 * 
// 		 * One approach would be to ask for *twice* the alignment and *twice* the size. 
// 		 * Then we're guaranteed an address in the *middle* of the chunk with adequate 
// 		 * space and adequate alignment. But this seems unnecessarily wasteful. 
// 		 * 
// 		 * It is sufficient instead to bump up the size by alignment?  
// 		 * Suppose we're asking for m bytes aligned to k bytes.
// 		 * Does m + k aligned to k + 1 always contain an appropriate address?
// 		 * We are issued a pointer p, 
// 		 * the first possible userptr with appropriate alignment is p + k, 
// 		 * which need only have (m + k) - k bytes remaining. This is clearly okay. */
// 		
// 	}
	*p_size = size_to_allocate;
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
	
	struct entry *index_entry = INDEX_LOC_FOR_ADDR(userptr);
	/* unindex the l0 maps */
	if (__builtin_expect(IS_L0_ENTRY(index_entry), 0))
	{
		void *allocptr = userptr_to_allocptr(userptr);
		unsigned long size = malloc_usable_size(allocptr);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "*** Unindexing l0 entry for alloc chunk %p (size %lu)\n", 
				allocptr, size);
#endif
		unsigned page_size = sysconf(_SC_PAGE_SIZE);
		unsigned start_remainder = ((uintptr_t) allocptr) % page_size;
		unsigned end_remainder = (((uintptr_t) allocptr) + size) % page_size;
		
		unsigned expected_pagewise_size = size 
				+ start_remainder
				+ ((end_remainder == 0) ? 0 : page_size - end_remainder);
		unsigned size_unindexed = __unindex_l0(userptr_to_allocptr(userptr));
#ifdef TRACE_HEAP_INDEX
		if (size_unindexed > expected_pagewise_size)
		{
			fprintf(stderr, "*** ERROR: unindexed too much unindexing %p: %ld not %ld\n", 
				allocptr, size_unindexed, expected_pagewise_size);
		}
		if (size_unindexed < expected_pagewise_size)
		{
			fprintf(stderr, "*** ERROR: unindexed too little unindexing %p: %ld not %ld\n", 
				allocptr, size_unindexed, expected_pagewise_size);
		}
#endif
		// memset the covered entries with the empty value
		struct entry empty_value = { 0, 0, 0 };
		assert(IS_EMPTY_ENTRY(&empty_value));
		memset(index_entry, *(char*) &empty_value, nbytes_in_index_for_l0_entry(userptr));
		return;
	}

	if (__builtin_expect(IS_DEEP_ENTRY(index_entry), 0))
	{
#ifdef TRACE_DEEP_HEAP_INDEX
	fprintf(stderr, "*** Unindexing deep entry for chunk %p\n", userptr);
#endif
		__unindex_deep_alloc(userptr, 1); // invalidates cache
		return;
	}
	
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from list indexed at %p\n", 
		userptr, index_entry);
#endif

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
	invalidate_cache_entry(userptr, usersize(userptr));
	list_sanity_check(index_entry, NULL);
}

static void pre_nonnull_free(void *userptr, size_t freed_usable_size)
{
	index_delete(userptr/*, freed_usable_size*/);
}

static void post_nonnull_free(void *userptr) {}

static void pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller)
{
	/* When this happens, we *may or may not be freeing an area*
	 * -- i.e. if the realloc fails, we will not actually free anything.
	 * However, whn we were using trailers, and 
	 * in the case of realloc()ing a *slightly smaller* region, 
	 * the allocator might trash our insert (by writing its own data over it). 
	 * So we *must* delete the entry first,
	 * then recreate it later, as it may not survive the realloc() uncorrupted. */
	index_delete(userptr/*, malloc_usable_size(ptr)*/);
}
static void post_nonnull_nonzero_realloc(void *userptr, 
	size_t modified_size, 
	size_t old_usable_size,
	const void *caller, void *__new_allocptr)
{
	if (__new_allocptr != NULL)
	{
		/* create a new bin entry */
		index_insert(allocptr_to_userptr(__new_allocptr), 
				modified_size, __current_allocsite ? __current_allocsite : caller);
	}
	else 
	{
		/* *recreate* the old bin entry! The old usable size
		 * is the *modified* size, i.e. we modified it before
		 * allocating it, so we pass it as the modified_size to
		 * index_insert. */
		index_insert(userptr, old_usable_size, __current_allocsite ? __current_allocsite : caller);
	} 
}

struct deep_entry_region deep_entry_regions[1u<<6]; // must match the bit size of "distance"!

static struct deep_entry *lookup_deep_alloc(void *ptr,/* struct entry *bucket,*/ int level_upper_bound, int level_lower_bound,
		struct deep_entry_region **out_region, 
		_Bool *out_seen_object_starting_earlier);

static inline _Bool find_next_nonempty_bin(struct entry **p_cur, 
		struct entry *limit,
		size_t *p_object_minimum_size
		)
{
	// first version: just what the old loop did
	--(*p_cur);
	*p_object_minimum_size += entry_coverage_in_bytes;
	
	return *p_object_minimum_size <= BIGGEST_SENSIBLE_OBJECT && *p_cur > limit;

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
	size_t usable_size;
	struct deep_entry *deep;
	struct insert *insert;
} lookup_cache[LOOKUP_CACHE_SIZE];
static struct lookup_cache_entry *next_to_evict = &lookup_cache[0];

static void install_cache_entry(void *object_start,
	size_t object_size,
	struct deep_entry *deep,
	struct insert *insert)
{
	assert(next_to_evict >= &lookup_cache[0] && next_to_evict < &lookup_cache[LOOKUP_CACHE_SIZE]);
	*next_to_evict = (struct lookup_cache_entry) {
		object_start, object_size, deep, insert
	}; // FIXME: thread safety
}

static void invalidate_cache_entry(void *object_start,
	size_t object_size)
{
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if (object_start == lookup_cache[i].object_start 
				&& object_size == lookup_cache[i].usable_size) 
		{
			lookup_cache[i] = (struct lookup_cache_entry) {
				NULL, 0, NULL, NULL
			};
			next_to_evict = &lookup_cache[i];
			return;
		}
	}
}

/* A more client-friendly lookup function. */
struct insert *lookup_object_info(const void *mem, void **out_object_start, struct deep_entry **out_deep)
{
	/* Unlike our malloc hooks, we might get called before initialization,
	   e.g. if someone tries to do a lookup before the first malloc of the
	   program's execution. Rather than putting an initialization check
	   in the fast-path functions, we bail here.  */
	if (!index_region) return NULL;
	
	/* Try matching in the cache. NOTE: how does this impact l0 and deep-indexed 
	 * entries? In all cases, we cache them here. Invalidate if we deep-index
	 * an existing allocation. */
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if ((char*) mem >= (char*) lookup_cache[i].object_start 
				&& (char*) mem < (char*) lookup_cache[i].object_start + lookup_cache[i].usable_size)
		{
			if (out_object_start) *out_object_start = lookup_cache[i].object_start;
			if (out_deep) *out_deep = lookup_cache[i].deep;
			// ensure we're not about to evict this guy
			if (next_to_evict - &lookup_cache[0] == i)
			{
				next_to_evict = &lookup_cache[(i + 1) % LOOKUP_CACHE_SIZE];
				assert(next_to_evict - &lookup_cache[0] < LOOKUP_CACHE_SIZE);
			}
			return lookup_cache[i].insert;
			// case of deep inserts means we need to store the insert ptr specially
				//insert_for_chunk_and_usable_size(lookup_cache[i].object_start, lookup_cache[i].usable_size);
		}
	}
	
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
		/* Is the current head a deep-indexed chunk? If so, 
		 * search that whole deep index region.
		 * 
		 * NOTE: this search goes backwards, and for this reason,
		 * so does the open allocation of deep entry slots: for objects
		 * starting at or before address p, its deep entry slot must be
		 * at or before some address q.
		 */
		seen_object_starting_earlier = 0;
		
		if (__builtin_expect(IS_L0_ENTRY(cur_head), 0))
		{
			return __lookup_l0(mem, out_object_start);
		}
	
		if (__builtin_expect(IS_DEEP_ENTRY(cur_head), 0))
		{
			if (cur_head != first_head)
			{
				/* If we didn't point into non-deep-indexed memory at ptr,
				 * we're not going to find our allocation in a deep-indexed
				 * region, since we always upgrade units of at least a whole
				 * chunk. So we can abort now. 
				 */
#ifdef TRACE_DEEP_HEAP_INDEX
				fprintf(stderr, "Strayed into deep-indexed region (bucket base %p) "
						"searching for chunk overlapping %p, so aborting\n", 
					ADDR_FOR_INDEX_LOC(cur_head), mem);
#endif
				goto fail;
			}
			struct deep_entry_region *region;
			struct deep_entry *found = lookup_deep_alloc((void*) mem, /*cur_head,*/ -1, -1, &region, &seen_object_starting_earlier);
			// did we find an overlapping object?
			if (found)
			{
				if (out_deep) *out_deep = found;
				void *object_start = (char*) region->base_addr + (found->distance_4bytes << 2);
				if (out_object_start) *out_object_start = object_start;
				install_cache_entry(object_start, (found->size_4bytes << 2), found, &found->u_tail.ins);
				return &found->u_tail.ins;
			}
			else
			{
				// we should at least have a region
				assert(region);
				// resume the search from the next-lower index
				cur_head = INDEX_LOC_FOR_ADDR((char*) region->base_addr - 1);
				continue;
			}
		}
		
		void *cur_userchunk = entry_ptr_to_addr(cur_head);

		while (cur_userchunk)
		{
			struct insert *cur_insert = insert_for_chunk(cur_userchunk);
#ifndef NDEBUG
			/* Sanity check on the insert. */
			if ((char*) cur_insert < (char*) cur_userchunk
				|| (char*) cur_insert - (char*) cur_userchunk > BIGGEST_SENSIBLE_OBJECT)
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
				if (out_deep) *out_deep = NULL;
				if (out_object_start) *out_object_start = cur_userchunk;
				install_cache_entry(cur_userchunk, usersize(cur_userchunk), NULL, cur_insert);
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
	fprintf(stderr, "Heap index lookup failed with "
		"cur_head %p, object_minimum_size %zu, seen_object_starting_earlier %d",
		cur_head, object_minimum_size, (int) seen_object_starting_earlier);
	return NULL;
	/* FIXME: use the actual biggest allocated object, not a guess. */
}

static int new_deep_alloc_index(void *start_addr, void *end_addr, int undersize_factor_as_right_shift)
{
	// 0. mmap-allocate a region
	assert(undersize_factor_as_right_shift >= 0);
	ptrdiff_t range_size = (char*) end_addr - (char*) start_addr;
	size_t mapping_size = (sizeof (struct deep_entry) * (range_size / 4)) >> undersize_factor_as_right_shift;
	void *region = mmap(NULL, 2 * mapping_size, PROT_READ|PROT_WRITE, // 2*mapping_size is for *head*-padding
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	assert(region != MAP_FAILED);
	
	// find an unused slot in the deep entry regions table
	struct deep_entry_region *p_slot = &deep_entry_regions[0];
	for (; p_slot < &deep_entry_regions[sizeof deep_entry_regions / sizeof deep_entry_regions[0]]; ++p_slot)
	{
		if (!p_slot->region) // FIXME: use CAS
		{
			// initialize it and return
			p_slot->region = region + mapping_size; // i.e. *half_way* through the region!
			p_slot->base_addr = start_addr;
			p_slot->end_addr = end_addr;
			p_slot->undersize_right_shift = undersize_factor_as_right_shift;
			p_slot->half_size = mapping_size;
			return p_slot - &deep_entry_regions[0];
		}
	}

	return -1;
}

static struct deep_entry *grab_first_free_deep_entry(int index, void *addr, unsigned size_4bytes, char level_minus_one)
{
	// find the first possible slot
	struct deep_entry_region *r = &deep_entry_regions[index];
	int highest_index = ((char*) addr - (char*)r->base_addr)
		 >> (2 + r->undersize_right_shift);
	struct deep_entry *first_attempt = &r->region[highest_index];
	struct deep_entry *attempt = first_attempt;
	while (attempt->valid) { --attempt; }// FIXME: use CAS to grab
	
	unsigned displacement_from_natural = first_attempt - attempt;
	if (displacement_from_natural > r->biggest_index_displacement_from_natural)
	{
		r->biggest_index_displacement_from_natural = displacement_from_natural;
	}
	if (size_4bytes > r->biggest_object_in_4bytes_total)
	{
		r->biggest_object_in_4bytes_total = size_4bytes;
	}
	if (size_4bytes > r->biggest_object_in_4bytes_by_level_minus_one[level_minus_one])
	{
		r->biggest_object_in_4bytes_by_level_minus_one[level_minus_one] = size_4bytes;
	}
#ifdef TRACE_DEEP_HEAP_INDEX
	fprintf(stderr, 
		"Had to walk back %d places from %p to find free deep entry for %p (level %d)\n", displacement_from_natural, first_attempt, addr, (int) level_minus_one + 1);
#endif
	return attempt;
}

// more-public version (still only really for testing)
struct deep_entry *__lookup_deep_alloc(void *ptr, int level_upper_bound, int level_lower_bound, 
		struct deep_entry_region **out_region);

// file-internal version
static struct deep_entry *lookup_deep_alloc(void *ptr, int level_upper_bound, int level_lower_bound, 
		struct deep_entry_region **out_region, 
		_Bool *out_seen_object_starting_earlier)
{
	//assert(INDEX_LOC_FOR_ADDR(ptr) >= bucket);
	// find the relevant region 
	struct entry *e = INDEX_LOC_FOR_ADDR(ptr);
	assert(IS_DEEP_ENTRY(e));
	int index = e->distance;
	assert(deep_entry_regions[index].region);
	struct deep_entry_region *r = &deep_entry_regions[index];
	if (out_region) *out_region = r;
	
	// reject queries for below this region's deepest level
	if (level_lower_bound > r->deepest_level_minus_one + 1)
	{
		return NULL;
	}
	
	// find the first possible slot
	int highest_index = ((char*) ptr - (char*) deep_entry_regions[index].base_addr)
		 >> (2 + deep_entry_regions[index].undersize_right_shift);
	struct deep_entry *first_poss = &deep_entry_regions[index].region[highest_index];
	struct deep_entry *poss = first_poss;

	#define DEEP_ENTRY_START(r, e) ((char*)((r)->base_addr) + (((e)->distance_4bytes)<<2))
	#define DEEP_ENTRY_END(r, e) ((char*)((r)->base_addr) + (((e)->distance_4bytes)<<2) + ((e)->size_4bytes<<2))
	
	#define DEEP_ENTRY_OVERLAPS(r, e, ptr) (DEEP_ENTRY_START((r), (e)) <= (char*)(ptr) && DEEP_ENTRY_END((r), (e)) > (char*) (ptr))
	
	#define MATCH_LEVEL(e, lub, llb) (((lub) == -1 || (e)->level_minus_one + 1 <= (lub)) && \
		((llb) == -1 || (e)->level_minus_one + 1 >= (llb)))

	/* NOTE: how can we bound the search? 
	 * The biggest_index_displacement_from_natural is not the whole story, because 
	 * it's computed from the object's start address. When we're searching, we might
	 * not be starting from there. We need biggest_object_by_level too. */
	unsigned biggest_search_distance
	 = r->biggest_index_displacement_from_natural
	  + ((level_upper_bound == -1 || level_lower_bound == -1 || level_lower_bound != level_upper_bound)
	  	 ? (r->biggest_object_in_4bytes_total >> r->undersize_right_shift)
		 : (r->biggest_object_in_4bytes_by_level_minus_one[level_lower_bound - 1] >> r->undersize_right_shift));
		 
	struct deep_entry *candidate = NULL;
	do
	{
		while (first_poss - poss <= biggest_search_distance
			&& (!poss->valid 
				|| !DEEP_ENTRY_OVERLAPS(r, poss, ptr) 
				|| !MATCH_LEVEL(poss, level_upper_bound, level_lower_bound)))
		{
			/* If we saw any object starting before ptr, tell the enclosing loop in lookup_object_info
			 * that it can give up if we fail. */
			if (poss->valid && DEEP_ENTRY_START(r, poss) < (char*) ptr
				&& MATCH_LEVEL(poss, level_upper_bound, level_lower_bound))
			{
				*out_seen_object_starting_earlier = 1;
			}

			--poss;
			assert((char*) poss >= (char*) deep_entry_regions[index].region - deep_entry_regions[index].half_size);
		}

		if (first_poss - poss > biggest_search_distance)
		{
			// we've failed
		#ifdef TRACE_DEEP_HEAP_INDEX
			fprintf(stderr, 
				"Failed lookup of deep entry for %p at level >= %d after seeking back %ld places from %p\n", 
					ptr, level_upper_bound, first_poss - poss, first_poss);
		#endif

			return NULL;
		}
		
		/* Okay, we've found a candidate; might there be a better candidate? */
		candidate = poss;
	} while (candidate->level_minus_one + 1 < level_upper_bound 
			&& candidate->level_minus_one < r->deepest_level_minus_one);
	
	unsigned nbytes_back = (first_poss - candidate) * sizeof (struct deep_entry);
	unsigned nbytes_back_max = r->half_size + (highest_index * sizeof (struct deep_entry));
	assert(nbytes_back <= nbytes_back_max);
	
#ifdef TRACE_DEEP_HEAP_INDEX
	fprintf(stderr, 
		"Had to search back %ld places (%ld bytes; max %ld) from %p to find deep entry for %p (level %d)\n", 
			first_poss - candidate, 
			(long) nbytes_back, (long) nbytes_back_max, first_poss, ptr,
			candidate->level_minus_one + 1);
#endif
	assert(level_lower_bound == -1 || candidate->level_minus_one + 1 >= level_lower_bound);
	assert(level_upper_bound == -1 || candidate->level_minus_one + 1 <= level_upper_bound);
	return poss;
	
}

struct deep_entry *__lookup_deep_alloc(void *ptr, int level_upper_bound, int level_lower_bound, 
		struct deep_entry_region **out_region)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	
	_Bool ignored;
	//struct entry *e = INDEX_LOC_FOR_ADDR(ptr);
	//do 
	//{
	//	if (IS_DEEP_ENTRY(e))
	//	{
			struct deep_entry *found = lookup_deep_alloc(ptr,/* e,*/ level_upper_bound, level_lower_bound, out_region, &ignored);
			if (found) return found;
	//	}
	//	--e;
	//} while ((INDEX_LOC_FOR_ADDR(ptr) - e) * entry_coverage_in_bytes < BIGGEST_SENSIBLE_OBJECT);
	return NULL;
}


static void convert_index_range_to_deep_alloc(void *start_addr, void *end_addr)
{
	/* Walk the bins covering these ranges, and make deep alloc structures
	 * out of them, to replace the existing memtable structures. */
	struct entry *begin_head = INDEX_LOC_FOR_ADDR(start_addr);

	/* If end_addr is exactly at the start of a bin range, we don't walk that bin, 
	 * but otherwise we do. */
	void *real_end_addr = INDEX_BIN_END_ADDRESS_FOR_ADDR((char*)end_addr - 1);
	struct entry *end_head = INDEX_LOC_FOR_ADDR(real_end_addr);
	
	/* Can we extend an existing deep alloc range?
	 * Short answer: no! Not without resizing the virtual memory region. 
	 * We could do this, but in-place mremap might fail. HMM. a mremap that
	 * moved us somewhere else in the VAS would be okay. But we shouldn't
	 * need to merge/resize regions; we should know how big they are. 
	 *
	 * AH, but Perl doesn't work this way: it allocates a ton of page-sized
	 * regions and links them together. BAH. So not only do we need mremap(), 
	 * but there's no guarantee Perl will get contiguous pages, so we might
	 * just run out of deep regions. */
// 	struct deep_entry_region *abuts_our_start = NULL;
// 	struct deep_entry_region *abuts_our_end = NULL;
// 	for (auto p_might_extend = &deep_entry_regions[0]; 
// 			p_might_extend < &deep_entry_regions[MAX_DEEP_ENTRY_REGIONS]; 
// 			++p_might_extend)
// 	{
// 		if (p_might_extend->base_addr == real_end_addr) 
// 		{ assert(!abuts_our_end); abuts_our_end = p_might_extend; }
// 		if (p_might_extend->end_addr == start_addr)
// 		{ assert(!abuts_our_start); abuts_our_start = p_might_extend; }
// 		
// 		if (abuts_our_end && abuts_our_start) break; // short-circuit
// 	}
// 	
// 	assert(!(abuts_our_end && abuts_our_start)); // merge case -- handle this later
// 	
// 	if (abuts_our_end)
// 	{
// 		// extend this one to cover our 
// 	}
// 	else if (abuts_our_start)
// 	{
// 		
// 	}
	
	/* Allocate a deep index. */
	int ind = new_deep_alloc_index(start_addr, real_end_addr, /* HACK / GUESS */ 3);
	// i.e. one deep entry (16 bytes) for every 4 bytes / 0.125 i.e. every 32 bytes, so 50% space overhead
	
	for (struct entry *cur_entry = begin_head; cur_entry < end_head; ++cur_entry)
	{
		assert(!IS_L0_ENTRY(cur_entry)); // FIXME: promote l0 entries too
		
		void *cur_userchunk = entry_ptr_to_addr(cur_entry); // might be null
		while (cur_userchunk)
		{
			struct insert *cur_insert = insert_for_chunk(cur_userchunk);
			
			char *allocptr = userptr_to_allocptr(cur_userchunk);
			size_t alloc_chunk_size = malloc_usable_size(allocptr);
			size_t chunk_size_from_userptr = alloc_chunk_size - ((char*) cur_userchunk - allocptr);
			
			// cache-invalidate this entry
			invalidate_cache_entry(cur_userchunk, alloc_chunk_size);

			// build an equivalent entry in the deep space -- FIXME: thread-safety, but to be handled in grab_, not here
			*grab_first_free_deep_entry(ind, cur_userchunk, chunk_size_from_userptr >> 2, 0) = (struct deep_entry) {
				.valid = 1,
				.distance_4bytes = ((char*) cur_userchunk - (char*) start_addr) >> 2,
				.level_minus_one = 0,   // allocation level of this object *minus one*, i.e. 1..4
				.size_4bytes = chunk_size_from_userptr >> 2, // byte size in multiples of four bytes -- v. large is very unlikely for nested allocations
				.u_tail = { ins: (struct insert) {
					.alloc_site_flag = cur_insert->alloc_site_flag,
					.alloc_site = cur_insert->alloc_site
				} }
			};
#ifdef TRACE_DEEP_HEAP_INDEX
			fprintf(stderr, 
				"Upgraded l1 chunk at %p to deep alloc representation\n", cur_userchunk);
#endif

			// move to the next chunk
			cur_userchunk = entry_to_same_range_addr(cur_insert->un.ptrs.next, cur_userchunk);
		} // end while chunk
		
		// now unlink the whole lot
		// FIXME: thread-safety: unlink as we go
		*cur_entry = (struct entry) { .present = 0, .removed = 1, .distance = ind }; 
		assert(IS_DEEP_ENTRY(cur_entry));
#ifdef TRACE_DEEP_HEAP_INDEX
			fprintf(stderr, 
				"Upgraded l1 bucket, entry addr %p, range %p-%p, to deep alloc region, index %d\n", 
					cur_entry, ADDR_FOR_INDEX_LOC(cur_entry), ADDR_FOR_INDEX_LOC(cur_entry+1), ind);
#endif
	} // end for head
#ifdef TRACE_DEEP_HEAP_INDEX
			fprintf(stderr, 
				"Established deep alloc index between %p and %p\n", start_addr, real_end_addr);
#endif
}

int __index_deep_alloc(void *ptr, int level, unsigned size_bytes) 
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	
	/* Note that once a bucket becomes "deep", we get called for malloc() allocations
	 * too. If this happens, ptr is our malloc chunk ptr. We can identify this because
	 * level == 1. */
	
	/* Get the malloc chunk that contains this ptr. It may or may not 
	 * already be deep-indexed. */
	void *malloc_userchunk_start;
	struct deep_entry *existing_deep;
	struct insert *p_ins = NULL;
	if (level != 1)
	{
		p_ins = lookup_object_info(ptr, &malloc_userchunk_start, &existing_deep);
	}
	else
	{
		malloc_userchunk_start = ptr;
		p_ins = insert_for_chunk(ptr);
	}
	assert(p_ins);
	assert(malloc_userchunk_start);
	size_t malloc_chunk_size = malloc_usable_size(userptr_to_allocptr(malloc_userchunk_start));
	void *chunk_end_address = (char*) malloc_userchunk_start
			 + malloc_chunk_size;
	_Bool malloc_chunk_completely_fills_last_bucket
			 = (chunk_end_address == ADDR_FOR_INDEX_LOC(INDEX_BIN_END_ADDRESS_FOR_ADDR((char*) chunk_end_address - 1)));
	_Bool malloc_chunk_is_only_one_bucket
			= (INDEX_LOC_FOR_ADDR(malloc_userchunk_start)
			 == INDEX_LOC_FOR_ADDR((char*) chunk_end_address - 1));
	_Bool ptr_starts_in_last_bucket = !malloc_chunk_is_only_one_bucket && 
			(INDEX_LOC_FOR_ADDR(malloc_userchunk_start) == INDEX_LOC_FOR_ADDR((char*) chunk_end_address - 1));
	
	struct entry *first_malloc_chunk_entry = INDEX_LOC_FOR_ADDR(malloc_userchunk_start);
	struct entry *ptr_entry = INDEX_LOC_FOR_ADDR(ptr);
	/* If there's any deep, it should all be deep. */
	if (!existing_deep)
	{
		assert(!IS_DEEP_ENTRY(first_malloc_chunk_entry));

		/* It's an empty or non-deep entry; convert it for the whole malloc-span of our current object
		 * EXCEPT for the last bucket, assuming we don't completely fill it *AND* if we don't begin
		 * in it. 
		 * In that cases it's allowed to stay normal-l1-indexed
		 * since later chunks which don't want to be deep-indexed can still begin in it
		 * i.e. preventing endless extension creep of our deep region.
		 * (we will seek backwards into the deep bit if we start at the end of our object, so we can still find deep objects). */
		_Bool deep_alloc_begins_in_last_bucket 
				= (INDEX_LOC_FOR_ADDR(ptr) == INDEX_LOC_FOR_ADDR((char*) chunk_end_address - 1));
		convert_index_range_to_deep_alloc(
			INDEX_BIN_START_ADDRESS_FOR_ADDR(malloc_userchunk_start), 
					(malloc_chunk_completely_fills_last_bucket || malloc_chunk_is_only_one_bucket)
					? INDEX_BIN_END_ADDRESS_FOR_ADDR(chunk_end_address)
					: ADDR_FOR_INDEX_LOC(INDEX_LOC_FOR_ADDR(chunk_end_address) - 1));
	}
	assert(IS_DEEP_ENTRY(first_malloc_chunk_entry));
	// the last entry is not normally a deep one, 
	// ... FIXME: unless it already was one?
	assert(!IS_DEEP_ENTRY(INDEX_LOC_FOR_ADDR((char*) malloc_userchunk_start + malloc_chunk_size - 1))
		|| malloc_chunk_completely_fills_last_bucket || malloc_chunk_is_only_one_bucket);
	
	/* What about ptr_entry? By definition, it's in the span of the malloc 
	 * chunk, so it should normally be a deep entry too. */
	assert(ptr_starts_in_last_bucket || IS_DEEP_ENTRY(ptr_entry));
	
	/* Disgusting HACK: if our indexed object's start address is in the last bucket, 
	 * pretend it was indexed in the previous bucket. Lookups should still work, because
	 * we keep searching backwards, and once we're searching the deep index 
	 * we don't care that we got there from the wrong memtable bucket -- we can still
	 * represent the allocation's address. */
	if (ptr_starts_in_last_bucket)
	{
		--ptr_entry;
		assert(IS_DEEP_ENTRY(ptr_entry)); // HMM -- how do we know this?
	}
	
	/* Now find the deepest entry spanning this address already. */
	struct deep_entry_region *region = NULL;
	struct deep_entry *found_parent = __lookup_deep_alloc(ptr, -1, -1, &region);
	/* If we're a bona fide deep alloc, we should have at least a malloc above us. 
	 * AND if that malloc hadn't been made into a deep alloc yet, we just did that.
	 * So we'd better be a level-1 alloc or have found a parent. */
	assert(level == 1 || found_parent);
	assert(!found_parent || region == &deep_entry_regions[ptr_entry->distance]);
	
	unsigned distance_4bytes = ((char*) ptr - (char*) region->base_addr) >> 2;
	if (level == -1) level = found_parent->level_minus_one + 1 + 1;
	unsigned level_minus_one = level - 1;

	unsigned parent_distance = distance_4bytes - ((level == 1) ? 0 : found_parent->distance_4bytes);
	// add to the existing index
	*grab_first_free_deep_entry(ptr_entry->distance, ptr, size_bytes >> 2, level_minus_one) = (struct deep_entry) {
		.valid = 1,
		.distance_4bytes = distance_4bytes,
		.level_minus_one = level_minus_one,   // allocation level of this object *minus one*, i.e. 1..4
		.size_4bytes = size_bytes >> 2, // byte size in multiples of four bytes -- v. large is very unlikely for nested allocations
		.u_tail = { ins_full: {
			.alloc_site_flag = 0,
			.alloc_site = (uintptr_t) __current_allocsite,
			/* Also store the distance from our parent allocation 
			 * -- in units of 4bytes for now, but ideally in units of 
			      the highest common factor of distance_4bytes and size_4bytes? 
			      Typically this factor will be higher than one, allowing us to pack 
			      this field into 16 bytes even in the case of large subheaps. BUT we
			      might find some awkward cases. */
			.bits = parent_distance <= 65535 ? parent_distance
						: (fprintf(stderr, "Warning: couldn't represent parent-alloc distance %ld\n", parent_distance), 65535)
		} }
	};
	
	// update this region's deepest level
	if (level_minus_one > region->deepest_level_minus_one)
	{
		region->deepest_level_minus_one = level_minus_one;
	}
	
	return level_minus_one + 1;
}

void __unindex_deep_alloc(void *ptr, int level) 
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();

	/* Find the deep alloc entry and free it. */
	struct deep_entry_region *region;
	_Bool ignored;
	struct deep_entry *found = lookup_deep_alloc(ptr, /*INDEX_LOC_FOR_ADDR(ptr),*/ level, level, &region, &ignored);
	assert(found);
	invalidate_cache_entry((char*) region->base_addr + (found->distance_4bytes << 2),
			found->size_4bytes << 2);
	*found = (struct deep_entry) {
		.valid = 0
	};
}
