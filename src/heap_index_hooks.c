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
#include <strings.h>
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

#define PAGE_SIZE 4096 /* checked later */
#define LOG_PAGE_SIZE 12

struct lookup_cache_entry;
static void install_cache_entry(void *object_start,
	size_t usable_size, unsigned short depth, _Bool is_deepest,
	struct suballocated_chunk_rec *containing_chunk,
	struct insert *insert);
static void invalidate_cache_entries(void *object_start,
	unsigned short depths_mask,
	struct suballocated_chunk_rec *sub, struct insert *ins, signed nentries);
static int cache_clear_deepest_flag_and_update_ins(void *object_start,
	unsigned short depths_mask,
	struct suballocated_chunk_rec *sub, struct insert *ins, signed nentries,
	struct insert *new_ins);

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

static void delete_suballocated_chunk(struct suballocated_chunk_rec *p_rec);
static void unindex_deep_alloc_internal(void *ptr, struct insert *existing_ins, 
		struct suballocated_chunk_rec *p_rec);
static struct suballocated_chunk_rec *suballocated_chunks;

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
			&& (uintptr_t) userptr_to_allocptr(new_userchunkaddr) % PAGE_SIZE <= MAXIMUM_MALLOC_HEADER_OVERHEAD
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
	
// 	/* If we got a deep alloc entry, do the deep thing. */
// 	if (__builtin_expect(IS_DEEP_ENTRY(index_entry), 0))
// 	{
// 		_Bool unset_allocsite = 0;
// 		if (!__current_allocsite) { __current_allocsite = (void *) caller; unset_allocsite = 1; }
// 		assert(__current_allocsite == caller);
// 		__index_deep_alloc(new_userchunkaddr, 1, malloc_usable_size(userptr_to_allocptr(new_userchunkaddr)));
// 		if (unset_allocsite) __current_allocsite = NULL;
// 		return;
// 	}

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
		unsigned start_remainder = ((uintptr_t) allocptr) % PAGE_SIZE;
		unsigned end_remainder = (((uintptr_t) allocptr) + size) % PAGE_SIZE;
		
		unsigned expected_pagewise_size = size 
				+ start_remainder
				+ ((end_remainder == 0) ? 0 : PAGE_SIZE - end_remainder);
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

// 	if (__builtin_expect(IS_DEEP_ENTRY(index_entry), 0))
// 	{
// #ifdef TRACE_DEEP_HEAP_INDEX
// 	fprintf(stderr, "*** Unindexing deep entry for chunk %p\n", userptr);
// #endif
// 		__unindex_deep_alloc(userptr, 1); // invalidates cache
// 		return;
// 	}
	
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from list indexed at %p\n", 
		userptr, index_entry);
#endif
	
	unsigned suballocated_region_number = 0;
	struct insert *ins = insert_for_chunk(userptr);
	if (ALLOC_IS_SUBALLOCATED(userptr, ins)) 
	{
		suballocated_region_number = (uintptr_t) ins->alloc_site;
	}

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
	/* If there were suballocated chunks under here, delete the whole lot. */
	if (suballocated_region_number != 0)
	{
		delete_suballocated_chunk(&suballocated_chunks[suballocated_region_number]);
	}
	invalidate_cache_entries(userptr, (unsigned short) -1, NULL, NULL, -1);
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
	while (!IS_ALIGNED(p-SIZE))
	{
		if (p-1 < last_good_byte) return NULL;
		
		if (*--p != 0) return p;
	}
	
	/* Do the aligned part */
	while (p-SIZE >= last_good_byte)
	{
		unsigned long v = *((unsigned long *)(p-SIZE));
		if (v != 0ul)
		{
			// HIT -- but what is the highest nonzero byte?
			int nlzb = nlzb1(v); // in range 0..7
			return p - 1 - nlzb;
		}
		p -= SIZE;
	}
	
	assert((p-SIZE) - last_good_byte < SIZE);
	assert((p-SIZE) - last_good_byte >= 0);
	
	/* Do the unaligned part */
	while ((p-SIZE) - last_good_byte > 0)
	{
		if (p-1 < last_good_byte) return NULL;
		
		if (*--p != 0) return p;
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
	size_t max_nbytes_coverage_to_scan = BIGGEST_SENSIBLE_OBJECT - *p_object_minimum_size;
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
	
//	// first version: just what the old loop did
//	do
//	{
//		--(*p_cur);
//		*p_object_minimum_size += entry_coverage_in_bytes;
//		
//		// if we've gone too far, give up
//		if (*p_object_minimum_size > BIGGEST_SENSIBLE_OBJECT || *p_cur <= limit) return 0;
//		
//		// if we've hit a nonempty, stop
//		if (!IS_EMPTY_ENTRY(*p_cur)) return 1;
//		
//	} while (1);

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
	struct suballocated_chunk_rec *containing_chunk;
	struct insert *insert;
} lookup_cache[LOOKUP_CACHE_SIZE];
static struct lookup_cache_entry *next_to_evict = &lookup_cache[0];

static void check_cache_sanity(void)
{
	// the cache alrways 
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
	struct suballocated_chunk_rec *containing_chunk,
	struct insert *insert)
{
	check_cache_sanity();
	/* our "insert" should always be the insert that describes the object,
	 * NOT one that chains into the suballocs table. */
	assert(INSERT_DESCRIBES_OBJECT(insert));
	assert(next_to_evict >= &lookup_cache[0] && next_to_evict < &lookup_cache[LOOKUP_CACHE_SIZE]);
	assert((char*)(uintptr_t) insert->alloc_site >= MINIMUM_USER_ADDRESS);
	*next_to_evict = (struct lookup_cache_entry) {
		object_start, object_size, depth, is_deepest, containing_chunk, insert
	}; // FIXME: thread safety
	// don't immediately evict the entry we just created
	next_to_evict = &lookup_cache[(next_to_evict + 1 - &lookup_cache[0]) % LOOKUP_CACHE_SIZE];
	assert(next_to_evict >= &lookup_cache[0] && next_to_evict < &lookup_cache[LOOKUP_CACHE_SIZE]);
	check_cache_sanity();
}

static void invalidate_cache_entries(void *object_start,
	unsigned short depths_mask,
	struct suballocated_chunk_rec *containing,
	struct insert *ins,
	signed nentries)
{
	unsigned ninvalidated = 0;
	check_cache_sanity();
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if ((!object_start || object_start == lookup_cache[i].object_start)
				&& (!containing || containing == lookup_cache[i].containing_chunk)
				&& (!ins || ins == lookup_cache[i].insert)
				&& (0 != (1<<lookup_cache[i].depth & depths_mask))) 
		{
			lookup_cache[i] = (struct lookup_cache_entry) {
				NULL, 0, 0, 0, NULL, NULL
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
	struct suballocated_chunk_rec *containing,
	struct insert *ins,
	signed nentries,
	struct insert *new_ins)
{
	unsigned ncleared = 0;
	check_cache_sanity();
	assert(ins);
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if ((!object_start || object_start == lookup_cache[i].object_start)
				&& (!containing || containing == lookup_cache[i].containing_chunk)
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
struct insert *object_insert(const void *obj, struct insert *ins)
{
	if (__builtin_expect(!INSERT_DESCRIBES_OBJECT(ins), 0))
	{
		struct suballocated_chunk_rec *p_rec = &suballocated_chunks[(unsigned) ins->alloc_site];
		assert(p_rec);
		return &p_rec->higherlevel_ins; // FIXME: generalise to depth > 2
	}
	return ins;
}

static
struct insert *lookup_deep_alloc(const void *ptr, int max_levels, 
		struct insert *start,
		void **out_object_start,
		size_t *out_object_size,
		struct suballocated_chunk_rec **out_containing_chunk);

/* A client-friendly lookup function with cache. */
struct insert *lookup_object_info(const void *mem, void **out_object_start, size_t *out_object_size,
		struct suballocated_chunk_rec **out_containing_chunk)
{
	/* Unlike our malloc hooks, we might get called before initialization,
	   e.g. if someone tries to do a lookup before the first malloc of the
	   program's execution. Rather than putting an initialization check
	   in the fast-path functions, we bail here.  */
	if (!index_region) return NULL;
	
	/* Try matching in the cache. NOTE: how does this impact l0 and deep-indexed 
	 * entries? In all cases, we cache them here. We also keep a "is_deepest" flag
	 * which tells us (conservatively) whether it's known to be the deepest entry
	 * indexing that storage. We *only* return a cache hit if the flag is set. */
	check_cache_sanity();
	for (unsigned i = 0; i < LOOKUP_CACHE_SIZE; ++i)
	{
		if (lookup_cache[i].object_start && 
				lookup_cache[i].is_deepest && 
				(char*) mem >= (char*) lookup_cache[i].object_start && 
				(char*) mem < (char*) lookup_cache[i].object_start + lookup_cache[i].usable_size)
		{
			// HIT!
			assert(lookup_cache[i].object_start);
#if defined(TRACE_DEEP_HEAP_INDEX) || defined(TRACE_HEAP_INDEX)
			fprintf(stderr, "Cache hit at pos %d (%p) with alloc site %p\n", i, 
					lookup_cache[i].object_start, (void*) (uintptr_t) lookup_cache[i].insert->alloc_site);
			fflush(stderr);
#endif
			assert((char*)(uintptr_t)(lookup_cache[i].insert->alloc_site) >= MINIMUM_USER_ADDRESS);
			
			if (out_object_start) *out_object_start = lookup_cache[i].object_start;
			if (out_containing_chunk) *out_containing_chunk = lookup_cache[i].containing_chunk;
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
	void *l01_object_start;
	struct insert *found = lookup_l01_object_info(mem, &l01_object_start);
	unsigned short depth = 1;
	size_t size;
	struct suballocated_chunk_rec *containing_chunk_rec = NULL; // initialized shortly...
	void *object_start;

	if (found)
	{
		size = usersize(l01_object_start);
		object_start = l01_object_start;
		containing_chunk_rec = NULL;
		_Bool is_deepest = INSERT_DESCRIBES_OBJECT(found);
		
		// cache the l01 entry
		install_cache_entry(object_start, size, 1, is_deepest, NULL, object_insert(l01_object_start, found));
		
		if (!is_deepest)
		{
			assert(l01_object_start);
			/* deep case */
			void *deep_object_start;
			size_t deep_object_size;
			struct insert *found_deeper = lookup_deep_alloc(mem, 1, found, &deep_object_start, 
					&deep_object_size, &containing_chunk_rec);
			if (found_deeper)
			{
				// override the values we assigned just now
				object_start = deep_object_start;
				found = found_deeper;
				size = deep_object_size;
				// cache this too
				install_cache_entry(object_start, size, 2 /* FIXME */, 1 /* FIXME */, 
					containing_chunk_rec, found);
			}
			else
			{
				// we still have to point the metadata at the *sub*indexed copy
				assert((char*)(uintptr_t) found->alloc_site < MINIMUM_USER_ADDRESS);
				found = object_insert(mem, found);
			}
		}


		if (out_object_start) *out_object_start = object_start;
		if (out_object_size) *out_object_size = size;
		if (out_containing_chunk) *out_containing_chunk = containing_chunk_rec;
	}
	
	assert(!found || (char*)(uintptr_t) found->alloc_site >= MINIMUM_USER_ADDRESS);
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
			assert((char*)(uintptr_t)(real_ins->alloc_site) >= MINIMUM_USER_ADDRESS);
			
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
		
		if (__builtin_expect(IS_L0_ENTRY(cur_head), 0))
		{
			return __lookup_l0(mem, out_object_start);
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
// 				install_cache_entry(object_start, (found->size_4bytes << 2), found, &found->u_tail.ins);
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
	fprintf(stderr, "Heap index lookup failed with "
		"cur_head %p, object_minimum_size %zu, seen_object_starting_earlier %d\n",
		cur_head, object_minimum_size, (int) seen_object_starting_earlier);
	return NULL;
	/* FIXME: use the actual biggest allocated object, not a guess. */
}

/* How the deep index works (take 2). 
 * 
 * Every allocation is indexed by a 'struct insert'. This holds at any level
 * (l0, l1, deep). 
 * 
 * We encode "suballocatedness" by using a special addr in the insert. 
 * 
 * This addr is also an index into the "suballocated chunks" table. 
 * Currently this table supports 16M entries (less the first one, which is unused). 
 * We mmap() this and keep a bitmap of which entries are unused. The bitmap
 * is 16Mbits or 2MB, so worth nocommit-allocating. */

static unsigned long *suballocated_chunks_bitmap;
static unsigned long bitmap_nwords;
#define UNSIGNED_LONG_NBITS (NBITS(unsigned long))
static 
void 
check_bucket_sanity(struct insert *p_bucket, struct suballocated_chunk_rec *p_rec);

#define MAX_PITCH 256 /* Don't support larger than 256-byte pitches, s.t. remainder fits in one byte */

static void init_suballocs(void)
{
	if (!suballocated_chunks)
	{
		
		suballocated_chunks = mmap(NULL, 
			MAX_SUBALLOCATED_CHUNKS * sizeof (struct suballocated_chunk_rec), 
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
		assert(suballocated_chunks != MAP_FAILED);
		size_t bitmap_nbytes = MAX_SUBALLOCATED_CHUNKS >> 3;
		suballocated_chunks_bitmap = mmap(NULL, 
			bitmap_nbytes,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
		assert(suballocated_chunks_bitmap != MAP_FAILED);
		bitmap_nwords = bitmap_nbytes / sizeof (unsigned long);
	}
}

static struct suballocated_chunk_rec *make_suballocated_chunk(void *chunk_base, size_t chunk_size, 
		struct insert *chunk_existing_ins, size_t guessed_average_size)
{
	if (!suballocated_chunks) init_suballocs();
	assert(chunk_size != 0);
	check_cache_sanity();
	
	/* Use the bitmap to find the first unused bit EXCEPT THE FIRST one.
	 * This is because we don't want the case of a NULL alloc_site field
	 * to mean anything sane.
	 * Actually we leave blank the first 64 because it's easier. */
	unsigned long *p_bitmap_word = &suballocated_chunks_bitmap[1];
	while (*p_bitmap_word == (unsigned long) -1) ++p_bitmap_word;
	assert(p_bitmap_word - &suballocated_chunks_bitmap[0] < bitmap_nwords);
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	while (*p_bitmap_word & test_bit)
	{
		if (__builtin_expect(test_bit != 1ul<<(UNSIGNED_LONG_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap_word - &suballocated_chunks_bitmap[0]) * UNSIGNED_LONG_NBITS
			+ test_bit_index;
	// set the bit in the bitmap
	*p_bitmap_word |= test_bit;
	// write the corresponding structure
	struct suballocated_chunk_rec *p_rec = &suballocated_chunks[free_index];
	assert(!ALLOC_IS_SUBALLOCATED(chunk_base, chunk_existing_ins));
	*p_rec = (struct suballocated_chunk_rec) {
		.higherlevel_ins = *chunk_existing_ins,
		.parent = NULL, // FIXME: level > 2 cases
		.begin = chunk_base,
		.real_size = chunk_size,
		.size = next_power_of_two_ge(chunk_size)
	}; // others 0 for now
	
	if (guessed_average_size > MAX_PITCH) guessed_average_size = MAX_PITCH;
	p_rec->log_pitch = integer_log2(next_power_of_two_ge(guessed_average_size));
	
	/* The size of a layer is (normally) 
	 * the number of bytes required to store one metadata record per average-size unit. */
	p_rec->one_layer_nbytes = (sizeof (struct insert)) * (p_rec->size >> p_rec->log_pitch);
	assert(is_power_of_two(p_rec->one_layer_nbytes));
	
	/* For small chunks, we might not fill a page, so resize the pitch so that we do. */
	if (__builtin_expect( p_rec->one_layer_nbytes < PAGE_SIZE, 0))
	{
		// force a one-page layer size, and recalculate the pitch
		p_rec->one_layer_nbytes = PAGE_SIZE;
		/* 
		      one_layer_nbytes == sizeof insert * chunk_size / pitch
		
		  =>  pitch            == sizeof insert * chunk_size / one_layer_nbytes
		  
		*/
		unsigned pitch = ((sizeof (struct insert)) * p_rec->size) >> LOG_PAGE_SIZE;
		assert(is_power_of_two(pitch));
		p_rec->log_pitch = integer_log2(pitch);
		/* Note also that 
		
		      one_layer_nrecs  == chunk_size / pitch
		*/
	}
	unsigned nbuckets = p_rec->one_layer_nbytes / sizeof (struct insert);
	assert(nbuckets < (uintptr_t) MINIMUM_USER_ADDRESS); // see note about size in index logic, below
	// FIXME: if this fails, increase the pitch until it's true
	
	/* The pitch equals the number of layers, because we allocate enough layers
	 * to go right down to byte-sized allocations.
	 * 
	 * It follows that we allocate enough virtual memory for one record per byte. */
	unsigned long nbytes = (sizeof (struct insert)) * p_rec->size;

	p_rec->metadata_recs = mmap(NULL, nbytes,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	assert(p_rec->metadata_recs != MAP_FAILED);
	
	/* Update the old insert with our info. */
	check_cache_sanity();
	chunk_existing_ins->alloc_site = free_index;
	chunk_existing_ins->alloc_site_flag = 0;
	// NO! WE DON'T do this because we need to leave the l1 linked list intact! 
	// chunk_existing_ins->un.bits = 0;
	check_cache_sanity();
	
	return p_rec;
}

static void delete_suballocated_chunk(struct suballocated_chunk_rec *p_rec)
{
	/* Remove it from the bitmap. */
	unsigned long *p_bitmap_word = suballocated_chunks_bitmap
			 + (p_rec - &suballocated_chunks[0]) / UNSIGNED_LONG_NBITS;
	int bit_index = (p_rec - &suballocated_chunks[0]) % UNSIGNED_LONG_NBITS;
	*p_bitmap_word &= ~(1ul<<bit_index);

	/* munmap it. */
	int ret = munmap(p_rec->metadata_recs, (sizeof (struct insert)) * p_rec->size);
	assert(ret == 0);
	
	// bzero the chunk rec
	bzero(p_rec, sizeof (struct suballocated_chunk_rec));
			
	/* We might want to restore the previous alloc_site bits in the higher-level 
	 * chunk. But we assume that's been/being deleted, so we don't bother. */
}

#define NBUCKET_OF(addr, p_rec)  ((uintptr_t) (addr) - (uintptr_t) (p_rec)->begin) >> (p_rec)->log_pitch
#define MODULUS_OF_ADDR(addr, p_rec)  ((uintptr_t) (addr) - (uintptr_t) (p_rec)->begin) % (1ul<<(p_rec)->log_pitch)
#define BUCKET_PITCH(p_rec) (1ul<<((p_rec)->log_pitch))
#define INSERTS_PER_LAYER(p_rec) ((p_rec)->size >> (p_rec)->log_pitch)
#define NLAYERS(p_rec) (1ul<<(p_rec)->log_pitch)
#define BUCKET_RANGE_BASE(p_bucket, p_rec) \
    (((char*)((p_rec)->begin)) + (((p_bucket) - (p_rec)->metadata_recs)<<((p_rec)->log_pitch)))
#define BUCKET_RANGE_END(p_bucket, p_rec) \
    (((char*)BUCKET_RANGE_BASE((p_bucket), (p_rec))) + BUCKET_PITCH((p_rec)))
#define BUCKET_PTR_FROM_INSERT_PTR(p_ins, p_rec) \
	((p_rec)->metadata_recs + (((p_ins) - (p_rec)->metadata_recs) % INSERTS_PER_LAYER(p_rec)))

int __index_deep_alloc(void *ptr, int level, unsigned size_bytes) 
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	if (!suballocated_chunks) init_suballocs();
	
	/* The caller will not know (currently) what level the suballoc is going in at. 
	 * FIXME: support cases where the caller can give us a lower bound. */
	assert(level == -1);
	
	/* Find the deepest existing chunk (>= l1) and its level. 
	 * Assert that the same such chunk is covering both the beginning and end 
	 * of this alloc. */
	assert(size_bytes >= 1);
	void *existing_object_start;
	struct suballocated_chunk_rec *containing_deep_chunk = NULL;
	char *end_addr = (char*) ptr + size_bytes;
	
	// HACK: just l01 for now; 
	// WHY? 1. we *want* the containing chunk; 
	//      2. we might point at an already suballoc'd region; don't want this chunk!
	//      3. "never cache non-leaf allocations" simplifies cache lookup
	struct insert *found_ins = lookup_l01_object_info(ptr, &existing_object_start
			/*, NULL, &containing_deep_chunk*/);
	assert(found_ins);
	
	// assert that we find the same chunk if we look up the *end* of the region
	assert(found_ins == lookup_l01_object_info((char*) ptr + size_bytes - 1, NULL));
	// FIXME: we don't support level>2 for now
	assert(!containing_deep_chunk);

	/* Do we already have a deep region covering this? Put differently, is the containing
	 * chunk already suballocated-*from*? If not, we have to make a new deep record for it
	 * AND update the cache. */
	struct suballocated_chunk_rec *p_rec;
	if (__builtin_expect(!ALLOC_IS_SUBALLOCATED(ptr, found_ins), 0))
	{
		p_rec = make_suballocated_chunk(existing_object_start, 
				// FIXME: here we assume we're contained in an l1 chunk
				usersize(existing_object_start) - sizeof (struct insert), 
				found_ins, /* guessed_average_size */ size_bytes);
		// invalidate any cache entry for the l01 entry. NO. just mark it as "not the deepest"
		// invalidate_cache_entry(existing_object_start, (1u<<0)|(1u<<1), NULL, NULL);
		cache_clear_deepest_flag_and_update_ins(existing_object_start, (1u<<0)|(1u<<1), NULL, found_ins, 1,
			&p_rec->higherlevel_ins);
	} else p_rec = &suballocated_chunks[(uintptr_t) found_ins->alloc_site];


	/* Get the relevant bucket. */
	unsigned long bucket_num = NBUCKET_OF(ptr, p_rec);
	struct insert *p_bucket = p_rec->metadata_recs + bucket_num;
	check_bucket_sanity(p_bucket, p_rec);

	/* Assert we don't already have metadata for this object.
	 * But actually, for GC'd heaps, shouldn't we just overwrite it?
	 * Then we don't need to interpose on the free operation, which
	 * might not be procedurally abstracted. */
	// struct insert *p_found_ins0 = lookup_deep_alloc(ptr, 1, 
	//	found_ins, NULL, NULL, NULL);
	// assert(!p_found_ins0);
	char *unindexed_up_to = ptr;
	char *unindex_end = (char*) ptr + size_bytes;
	// instead of walking bytewise, we should just walk up the allocs
	// 0. handle the case of an object starting [maybe much] earlier
	// creeping over into this bucket.
	void *earlier_object_start;
	size_t earlier_object_size;
	struct insert *p_old_ins = lookup_deep_alloc(ptr, 1, found_ins, &earlier_object_start,
			&earlier_object_size, NULL);
	if (p_old_ins) 
	{
		unindex_deep_alloc_internal(earlier_object_start, p_old_ins, p_rec); // FIXME: support deeper
	}
	unsigned short modulus = MODULUS_OF_ADDR(ptr, p_rec);
	// 1. now any object that overlaps us must start later than us, walk up the buckets
	for (struct insert *p_search_bucket = p_bucket;
			// we might find an object overlapping that starts in this bucket if 
			// -- our bucket range base is not later than the end of our object, and
			// -- our bucket range end is not earlier than the 
			(char*) BUCKET_RANGE_BASE(p_search_bucket, p_rec) < (char*) unindex_end; 
					//|| (char*) ptr >= BUCKET_RANGE_BASE(p_search_bucket, p_rec);
			
			++p_search_bucket)
	{
		for (struct insert *i_layer = p_search_bucket; 
				i_layer->alloc_site; 
				i_layer += INSERTS_PER_LAYER(p_rec))
		{
			/* Does this object overlap our allocation? */
			char *this_object_start;
			char *this_object_end_thisbucket;
			struct insert *this_object_ins;
			
			/* We don't care about continuation records; we'll find the 
			 * start record before any relevant continuation record. */
			if (IS_CONTINUATION_REC(i_layer))
			{
				// FIXME: assert that it doesn't overlap
				continue;
			}
			
			/* We have a start record. Check for overlap. */
			this_object_start = (char*) BUCKET_RANGE_BASE(p_search_bucket, p_rec) + MODULUS_OF_INSERT(i_layer);
			this_object_end_thisbucket = this_object_start + THISBUCKET_SIZE_OF_INSERT(i_layer);
			// if it overlaps us at all, it must overlap us in this bucket
			if (this_object_start < unindex_end 
					&& this_object_end_thisbucket > (char*) ptr)
			{
				unindex_deep_alloc_internal(this_object_start, i_layer, p_rec);
				/* HACK: this deletes i_layer, so move it back one. */
				i_layer -= INSERTS_PER_LAYER(p_rec);
			}
		}
	}

	/* Now we need to find a free metadata record to index this allocation at. */
	/* What's the first layer that's free? */
	struct insert *p_ins = p_bucket;
	unsigned layer_num = 0;
	while (p_ins->alloc_site)
	{
		p_ins += INSERTS_PER_LAYER(p_rec);
		++layer_num;
	}
	// we should never need to go beyond the last layer
	assert(layer_num < NLAYERS(p_rec));
	
	/* Store the insert. The object start modulus goes in `bits'. */
	p_ins->alloc_site = (uintptr_t) __current_allocsite;
	p_ins->alloc_site_flag = 0;
	
	/* We also need to represent the object's size somehow. We choose to use 
	 * continuation records since the insert doesn't have enough bits. Continuation records
	 * have alloc_site_flag == 1 and alloc_site < MINIMUM_USER_ADDRESS, and the "overhang"
	 * in bits (0 means "full bucket"). 
	 * The alloc site records the bucket number in which the object starts. This limits us to
	 * 4M buckets, so a 32MByte chunk for 8-byte-pitch, etc., which seems
	 * bearable for the moment. 
	 */
	unsigned short thisbucket_size = (NBUCKET_OF(end_addr, p_rec) == bucket_num) 
			? size_bytes
			: (BUCKET_PITCH(p_rec) - modulus);
	assert(thisbucket_size != 0);
	assert(thisbucket_size <= BUCKET_PITCH(p_rec));
	
	p_ins->un.bits = (thisbucket_size << 8) | modulus;
	
	/* We should be sane already, even though our continuation is not recorded. */
	check_bucket_sanity(p_bucket, p_rec);
	
	/* If we spill into the next bucket, set the continuation record */
	if ((char*)(BUCKET_RANGE_END(p_bucket, p_rec)) < end_addr)
	{
		struct insert *p_continuation_bucket = p_bucket + 1;
		assert(p_continuation_bucket - &p_rec->metadata_recs[0] < (uintptr_t) MINIMUM_USER_ADDRESS);
		struct insert *p_continuation_ins = p_continuation_bucket;
		/* Find a free slot */
		unsigned layer_num = 0;
		while (p_continuation_ins->alloc_site) 
		{ p_continuation_ins += INSERTS_PER_LAYER(p_rec); ++layer_num; }
		assert(layer_num < NLAYERS(p_rec));
		
		//unsigned short thisbucket_size = (end_addr >= BUCKET_RANGE_BASE(p_bucket + 1, p_rec))
		//		? 0
		//		: (char*) end_addr - (char*) BUCKET_RANGE_BASE(p_bucket, p_rec);
		//assert(thisbucket_size < 256);
		
		unsigned long size_after_first_bucket = size_bytes - thisbucket_size;
		assert(size_after_first_bucket != 0);
		unsigned long size_in_continuation_bucket 
		 = (size_after_first_bucket > BUCKET_PITCH(p_rec)) ? 0 : size_after_first_bucket;
		
		*p_continuation_ins = (struct insert) {
			.alloc_site = size_bytes, // NOTE what we're doing here!
			.alloc_site_flag = 1,     // ditto
			.un = { bits: (unsigned short) (size_in_continuation_bucket << 8) }  // ditto: modulus is zero, BUT size is included
		};
		assert(IS_CONTINUATION_REC(p_continuation_ins));
		check_bucket_sanity(p_continuation_bucket, p_rec);
	}
	
	check_bucket_sanity(p_bucket, p_rec);
	if (p_rec->biggest_object < size_bytes) p_rec->biggest_object = size_bytes;
	
#ifndef NDEBUG
	struct insert *p_found_ins1 = lookup_deep_alloc(ptr, 1, 
		found_ins, NULL, NULL, NULL);
	assert(p_found_ins1 == p_ins);
	struct insert *p_found_ins2 = lookup_deep_alloc((char*) ptr + size_bytes - 1, 1, 
		found_ins, NULL, NULL, NULL);
	assert(p_found_ins2 == p_ins);
#endif
	check_cache_sanity();
	return 2; // FIXME
}

static _Bool
get_start_from_continuation(struct insert *p_ins, struct insert *p_bucket, struct suballocated_chunk_rec *p_rec,
		void **out_object_start, size_t *out_object_size, struct insert **out_object_ins)
{
	/* NOTE: don't sanity check buckets in this function, because we might be 
	 * called from inside check_bucket_sanity(). */
	
	// the object starts somewhere in the previous bucket
	// okay: hop back to the object start
	struct insert *p_object_start_bucket = p_bucket - 1;

	// walk the object start bucket looking for the *last* object i.e. biggest modulus
	struct insert *object_ins;
	struct insert *biggest_modulus_pos = NULL;
	for (struct insert *i_layer = p_object_start_bucket;
			i_layer->alloc_site;
			i_layer += INSERTS_PER_LAYER(p_rec))
	{
		if (IS_CONTINUATION_REC(i_layer)) continue;
		// the modulus tells us where this object starts in the bucket range
		unsigned short modulus = p_object_start_bucket->un.bits & 0xff;
		if (!biggest_modulus_pos || 
				MODULUS_OF_INSERT(i_layer) > MODULUS_OF_INSERT(biggest_modulus_pos))
		{
			biggest_modulus_pos = i_layer;
		}
	}
	// we must have seen the last object
	assert(biggest_modulus_pos);
	object_ins = biggest_modulus_pos;
	char *object_start = (char*)(BUCKET_RANGE_BASE(p_object_start_bucket, p_rec)) 
			+ MODULUS_OF_INSERT(biggest_modulus_pos);
	uintptr_t object_size = p_ins->alloc_site;
	
	if (out_object_start) *out_object_start = object_start;
	if (out_object_size) *out_object_size = object_size;
	if (out_object_ins) *out_object_ins = object_ins;
	
	return 1;
}

static 
void 
check_bucket_sanity(struct insert *p_bucket, struct suballocated_chunk_rec *p_rec)
{
#ifndef NDEBUG
	/* Walk the bucket */
	unsigned layer_num = 0;
	for (struct insert *i_layer = p_bucket;
			i_layer->alloc_site;
			i_layer += INSERTS_PER_LAYER(p_rec), ++layer_num)
	{
		// we should never need to go beyond the last layer
		assert(layer_num < NLAYERS(p_rec));
		
		unsigned short thisbucket_size = i_layer->un.bits >> 8;
		unsigned short modulus = i_layer->un.bits & 0xff;
		
		assert(modulus < BUCKET_PITCH(p_rec));
		
		if (IS_CONTINUATION_REC(i_layer))
		{
			/* Check that the *previous* bucket contains the object start */
			assert(get_start_from_continuation(i_layer, p_bucket, p_rec, 
					NULL, NULL, NULL));
		}
		
		/* Check we don't overlap with anything else in this bucket. */
		for (struct insert *i_earlier_layer = p_bucket;
			i_earlier_layer != i_layer;
			i_earlier_layer += INSERTS_PER_LAYER(p_rec))
		{
			unsigned short thisbucket_earlier_size = i_earlier_layer->un.bits >> 8;
			unsigned short earlier_modulus = i_earlier_layer->un.bits & 0xff;
			
			// note that either record might be a continuation record
			// ... in which case zero-size means "the whole bucket"
			assert(!(IS_CONTINUATION_REC(i_earlier_layer) && thisbucket_earlier_size == 0));
			assert(!(IS_CONTINUATION_REC(i_layer) && thisbucket_size == 0));

			unsigned earlier_end = earlier_modulus + thisbucket_earlier_size;
			unsigned our_end = modulus + thisbucket_size;
			
			// conventional overlap
			assert(!(earlier_end > modulus && earlier_modulus < our_end));
			assert(!(our_end > earlier_modulus && modulus < earlier_end));
		}
	}

#endif
}

static
struct insert *lookup_deep_alloc(const void *ptr, int max_levels, 
		struct insert *start,
		void **out_object_start,
		size_t *out_object_size,
		struct suballocated_chunk_rec **out_containing_chunk)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	if (!suballocated_chunks) init_suballocs();
	
	assert(max_levels == 1);// i.e. we go down to l2 only
	assert(start);
	assert((char*)(uintptr_t) start->alloc_site < MINIMUM_USER_ADDRESS);
	
	assert(ALLOC_IS_SUBALLOCATED(ptr, start));
	struct suballocated_chunk_rec *p_rec = &suballocated_chunks[(unsigned) start->alloc_site];
	
	/* We've been given the containing (l1) chunk info. */

	/* How to do look-up? We walk the buckets, starting from the one that
	 * would index* an object starting at ptr. 
	 * If it has itself been sub-allocated, we recurse (FIXME), 
	 * and if that fails, stick with the result we have. */
	unsigned start_bucket_num = NBUCKET_OF(ptr, p_rec);
	struct insert *p_start_bucket = &p_rec->metadata_recs[start_bucket_num];
	struct insert *p_bucket = p_start_bucket;
	_Bool must_see_continuation = 0; // a bit like seen_object_starting_earlier
	char *earliest_possible_start = (char*) ptr - p_rec->biggest_object;
	do 
	{
		/* walk this bucket looking for an object overlapping us */
		char *thisbucket_base_addr = BUCKET_RANGE_BASE(p_bucket, p_rec);

		check_bucket_sanity(p_bucket, p_rec);
		
		unsigned layer_num = 0;
		for (struct insert *p_ins = p_bucket;
			p_ins->alloc_site;
			p_ins += INSERTS_PER_LAYER(p_rec), ++layer_num)
		{
			// we should never need to go beyond the last layer
			assert(layer_num < NLAYERS(p_rec));
			/* We are walking the bucket. Possibilities: 
			 * 
			 * it's a continuation record (may or may not overlap our ptr);
			 *
			 * it's an object start record (ditto).
			 */
			unsigned short object_size_in_this_bucket = p_ins->un.bits >> 8;
			unsigned short modulus = p_ins->un.bits & 0xff;

			if (IS_CONTINUATION_REC(p_ins))
			{
				/* Does this continuation overlap our search address? */
				assert(modulus == 0); // continuation recs have modulus zero
				
				void *object_start;
				size_t object_size;
				struct insert *object_ins;
				_Bool success = get_start_from_continuation(p_ins, p_bucket, p_rec,
						&object_start, &object_size, &object_ins);
				
				if ((char*) object_start + object_size > (char*) ptr)
				{
					// hit! 
					if (out_object_start) *out_object_start = object_start;
					if (out_containing_chunk) *out_containing_chunk = p_rec;
					return object_ins;
				}
				// else it's a continuation that we don't overlap
				// -- we can give up 
				if (must_see_continuation) goto fail;
			}
			else 
			{
				/* It's an object start record. Does it overlap? */
				char modulus = p_ins->un.bits & 0xff;
				char *object_start_addr = thisbucket_base_addr + modulus;
				void *object_end_addr = object_start_addr + object_size_in_this_bucket;

				if ((char*) object_start_addr <= (char*) ptr && (char*) object_end_addr > (char*) ptr)
				{
					// hit!
					if (out_object_start) *out_object_start = object_start_addr;
					if (out_containing_chunk) *out_containing_chunk = p_rec;
					return p_ins;
				}
			}
		} // end for each layer
		
		must_see_continuation = 1;
		
	} while (p_bucket-- >= &p_rec->metadata_recs[0]
			&& (char*) BUCKET_RANGE_END(p_bucket, p_rec) > earliest_possible_start);
fail:
	// failed!
	return NULL;
}

static void remove_one_insert(struct insert *p_ins, struct insert *p_bucket, struct suballocated_chunk_rec *p_rec)
{
	struct insert *replaced_ins = p_ins;
	do
	{
		struct insert *p_next_layer = replaced_ins + INSERTS_PER_LAYER(p_rec);
		/* Invalidate it from the cache. */
		invalidate_cache_entries(NULL, (unsigned short) -1, NULL, replaced_ins, 1);
		/* Copy the next layer's insert over ours. */
		*replaced_ins = *p_next_layer;
		/* Point us at the next layer to replace (i.e. if it's not null). */
		replaced_ins = p_next_layer;
	} while (replaced_ins->alloc_site);
}

static void unindex_deep_alloc_internal(void *ptr, struct insert *existing_ins, 
		struct suballocated_chunk_rec *p_rec)
{
	assert(existing_ins);
	assert(p_rec);
	
	struct insert *p_bucket = BUCKET_PTR_FROM_INSERT_PTR(existing_ins, p_rec);
	check_bucket_sanity(p_bucket, p_rec);
	
	unsigned short our_modulus = MODULUS_OF_INSERT(existing_ins);
	_Bool we_are_biggest_modulus = 1;
	for (struct insert *i_layer = p_bucket;
			we_are_biggest_modulus && i_layer->alloc_site;
			i_layer += INSERTS_PER_LAYER(p_rec))
	{
		we_are_biggest_modulus &= (our_modulus >= MODULUS_OF_INSERT(i_layer));
	}
	
	/* Delete this insert and "shift left" any later in the bucket, also
	 * invalidating them. */
	remove_one_insert(existing_ins, p_bucket, p_rec);
	check_bucket_sanity(p_bucket, p_rec);
	
	/* If we were the biggest modulus, delete any continuation record in the next bucket. */
	if (we_are_biggest_modulus)
	{
		for (struct insert *i_layer = p_bucket + 1;
				i_layer->alloc_site;
				i_layer += INSERTS_PER_LAYER(p_rec))
		{
			if (IS_CONTINUATION_REC(i_layer))
			{
				remove_one_insert(i_layer, p_bucket + 1, p_rec);
				check_bucket_sanity(p_bucket + 1, p_rec);
				break;
			}
		}
	}
	
	check_bucket_sanity(p_bucket, p_rec);
}

void __unindex_deep_alloc(void *ptr, int level) 
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	if (!suballocated_chunks) init_suballocs();
	
	/* Support cases where level>2. */
	assert(level == 2);
	
	void *existing_object_start;
	struct suballocated_chunk_rec *p_rec = NULL;
	struct insert *found_ins = lookup_object_info(ptr, &existing_object_start, NULL, &p_rec);
	assert(found_ins);
	assert(p_rec); 
	
	unindex_deep_alloc_internal(ptr, found_ins, p_rec);
}

