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
__thread int __current_alloclevel;
#else
void *__current_allocsite;
void *__current_allocfn;
size_t __current_allocsz;
int __current_alloclevel;
#endif

#ifdef MALLOC_USABLE_SIZE_HACK
#include "malloc_usable_size_hack.h"
#endif 

struct entry *index_region;
void *index_max_address;

#define entry_coverage_in_bytes 512
typedef struct entry entry_type;
void *index_begin_addr;
void *index_end_addr;

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
	!(!((p_t)->next.present) && (p_t)->next.distance != 0) \
	&& !(!((p_t)->prev.present) && (p_t)->prev.distance != 0))

static void list_sanity_check(entry_type *head)
{
	void *head_chunk = entry_ptr_to_addr(head);
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
		INSERT_SANITY_CHECK(insert_for_chunk(cur_userchunk));
		/* If the next chunk link is null, entry_to_same_range_addr
		 * should detect this (.present == 0) and give us NULL. */
		void *next_userchunk
		 = entry_to_same_range_addr(
			insert_for_chunk(cur_userchunk)->next, 
			cur_userchunk
		);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "List has a chunk beginning at userptr %p"
			" (usable_size %zu, insert {next: %p, prev %p})\n",
			cur_userchunk, 
			malloc_usable_size(userptr_to_allocptr(cur_userchunk)),
			next_userchunk,
			entry_to_same_range_addr(
				insert_for_chunk(cur_userchunk)->prev, 
				cur_userchunk
			)
		);
#endif
		assert(next_userchunk != head_chunk);
		assert(next_userchunk != cur_userchunk);

		/* If we're not the first element, we should have a 
		 * prev chunk. */
		if (count > 1) assert(NULL != entry_to_same_range_addr(
				insert_for_chunk(cur_userchunk)->prev, 
				cur_userchunk
			));


		cur_userchunk = next_userchunk;
	}
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr,
		"Passed sanity check of list indexed at %p, head chunk %p, "
		"length %d\n", head, head_chunk, count);
#endif
}
#else /* NDEBUG */
#define INSERT_SANITY_CHECK(p_t)
static void list_sanity_check(entry_type *head) {}
#endif

#define INDEX_LOC_FOR_ADDR(a) MEMTABLE_ADDR_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))
#define INDEX_BIN_START_ADDRESS_FOR_ADDR(a) MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))
#define INDEX_BIN_END_ADDRESS_FOR_ADDR(a) MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, ((char*)(a)) + entry_coverage_in_bytes)

#define IS_DEEP_ENTRY(e) (!(e)->present && (e)->removed)
#define IS_EMPTY_ENTRY(e) (!(e)->present && !(e)->removed)

static void 
index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	assert(index_region);
	
	/* The address *must* be in our tracked range. Assert this. */
	assert(new_userchunkaddr <= (index_end_addr ? index_end_addr : MAP_FAILED));
	
	struct entry *index_entry = INDEX_LOC_FOR_ADDR(new_userchunkaddr);
	
	/* If we got a deep alloc entry, do the deep thing. */
	if (__builtin_expect(IS_DEEP_ENTRY(index_entry), 0))
	{
		_Bool unset_allocsite = NULL;
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
	list_sanity_check(index_entry);

	void *head_chunkptr = entry_ptr_to_addr(index_entry);
	
	/* Populate our extra fields */
	struct insert *p_insert = insert_for_chunk(new_userchunkaddr);
	p_insert->alloc_site_flag = 0U;
	p_insert->alloc_site = (unsigned long) caller;

	/* Add it to the index. We always add to the start of the list, for now. */
	/* 1. Initialize our insert. */
	p_insert->next = addr_to_entry(head_chunkptr);
	p_insert->prev = addr_to_entry(NULL);
	assert(!p_insert->prev.present);
	
	/* 2. Fix up the next insert, if there is one */
	if (p_insert->next.present)
	{
		insert_for_chunk(entry_to_same_range_addr(p_insert->next, new_userchunkaddr))->prev
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
	if (p_insert->next.present) INSERT_SANITY_CHECK(
		insert_for_chunk(entry_to_same_range_addr(p_insert->next, new_userchunkaddr)));
	if (p_insert->prev.present) INSERT_SANITY_CHECK(
		insert_for_chunk(entry_to_same_range_addr(p_insert->prev, new_userchunkaddr)));
	list_sanity_check(e);
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
static inline struct insert *insert_for_chunk(void *userptr)
{
	return (struct trailer*) ((char*) userptr + malloc_usable_size(userptr)) - 1;
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
	struct entry *index_entry = INDEX_LOC_FOR_ADDR(userptr);
	if (__builtin_expect(IS_DEEP_ENTRY(index_entry), 0))
	{
		__unindex_deep_alloc(userptr, 1);
		return;
	}
	
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from list indexed at %p\n", 
		userptr, index_entry);
#endif

	list_sanity_check(index_entry);
	INSERT_SANITY_CHECK(insert_for_chunk/*_with_usable_size*/(userptr/*, freed_usable_size*/));

	/* (old comment; still true?) FIXME: we need a big lock around realloc()
	 * to avoid concurrent in-place realloc()s messing with the other inserts we access. */

	/* remove it from the bins */
	void *our_next_chunk = entry_to_same_range_addr(insert_for_chunk(userptr)->next, userptr);
	void *our_prev_chunk = entry_to_same_range_addr(insert_for_chunk(userptr)->prev, userptr);
	
	/* FIXME: make these atomic */
	if (our_prev_chunk) 
	{
		INSERT_SANITY_CHECK(insert_for_chunk(our_prev_chunk));
		insert_for_chunk(our_prev_chunk)->next = addr_to_entry(our_next_chunk);
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
		insert_for_chunk(our_next_chunk)->prev = addr_to_entry(our_prev_chunk);
	}
	else /* !our_next_chunk */
	{
		/* removing tail of the list... */
		/* ... and NOT a singleton -- we've handled that case already */
		assert(our_prev_chunk);
	
		/* update the previous chunk's insert */
		insert_for_chunk(our_prev_chunk)->next = addr_to_entry(NULL);

		/* nothing else to do here, as we don't keep a tail pointer */
	}
	/* Now that we have deleted the record, our bin should be sane,
	 * modulo concurrent reallocs. */
out:
	list_sanity_check(index_entry);
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

static struct deep_entry *lookup_deep_alloc(void *ptr, int level_upper_bound, int level_lower_bound,
		struct deep_entry_region **out_region, 
		_Bool *out_seen_object_starting_earlier);

/* A more client-friendly lookup function. */
struct insert *lookup_object_info(const void *mem, void **out_object_start)
{
	/* Unlike our malloc hooks, we might get called before initialization,
	   e.g. if someone tries to do a lookup before the first malloc of the
	   program's execution. Rather than putting an initialization check
	   in the fast-path functions, we bail here.  */
	if (!index_region) return NULL;
	
	struct entry *cur_head = INDEX_LOC_FOR_ADDR(mem);
	size_t object_minimum_size = 0;

#define BIGGEST_SENSIBLE_OBJECT (256*1024*1024)
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
		if (__builtin_expect(IS_DEEP_ENTRY(cur_head), 0))
		{
			struct deep_entry_region *region;
			struct deep_entry *found = lookup_deep_alloc((void*) mem, -1, -1, &region, &seen_object_starting_earlier);
			// did we find an overlapping object?
			if (found)
			{
				return &found->ins;
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
			if ((char*) cur_userchunk - (char*) cur_insert != sizeof(struct insert))
			{
				fprintf(stderr, "Saw insane insert address %p for chunk beginning %p "
					"(usable size %zu, allocptr %p); memory corruption?\n", 
					cur_insert, cur_userchunk, malloc_usable_size(userptr_to_allocptr(cur_userchunk)), userptr_to_allocptr(cur_userchunk));
			}	
#endif
			if (mem >= cur_userchunk
				&& mem < cur_userchunk + malloc_usable_size(userptr_to_allocptr(cur_userchunk))) 
			{
				if (out_object_start) *out_object_start = cur_userchunk;
				return cur_insert;
			}
			
			// do that optimisation
			if (cur_userchunk < mem) seen_object_starting_earlier = 1;
			
			cur_userchunk = entry_to_same_range_addr(cur_insert->next, cur_userchunk);
		}
		
		/* we reached the end of the list */
	} while (!seen_object_starting_earlier
		&& (object_minimum_size += entry_coverage_in_bytes,
		cur_head-- > &index_region[0] && object_minimum_size <= BIGGEST_SENSIBLE_OBJECT));
	fprintf(stderr, "Heap index lookup failed with "
		"cur_head %p, object_minimum_size %zu, seen_object_starting_earlier %d",
		cur_head, object_minimum_size, (int) seen_object_starting_earlier);
	return NULL;
	/* FIXME: use the actual biggest allocated object, not a guess. */

#undef BIGGEST_SENSIBLE_OBJECT
}

static unsigned biggest_index_displacement_from_natural;
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

static struct deep_entry *grab_first_free_deep_entry(int index, void *addr)
{
	// find the first possible slot
	int highest_index = ((char*) addr - (char*) deep_entry_regions[index].base_addr)
		 >> (2 + deep_entry_regions[index].undersize_right_shift);
	struct deep_entry *first_attempt = &deep_entry_regions[index].region[highest_index];
	struct deep_entry *attempt = first_attempt;
	while (attempt->valid) { --attempt; }// FIXME: use CAS to grab
	
	unsigned displacement_from_natural = first_attempt - attempt;
	if (displacement_from_natural > biggest_index_displacement_from_natural)
	{
		biggest_index_displacement_from_natural = displacement_from_natural;
	}
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, 
		"Had to seek back %d places from %p to find free deep entry for %p\n", displacement_from_natural, first_attempt, addr);
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
	// find the relevant region 
	int index = INDEX_LOC_FOR_ADDR(ptr)->distance;
	assert(IS_DEEP_ENTRY(INDEX_LOC_FOR_ADDR(ptr)));
	*out_region = &deep_entry_regions[index];
	
	// find the first possible slot
	int highest_index = ((char*) ptr - (char*) deep_entry_regions[index].base_addr)
		 >> (2 + deep_entry_regions[index].undersize_right_shift);
	struct deep_entry *first_attempt = &deep_entry_regions[index].region[highest_index];
	struct deep_entry *attempt = first_attempt;

	#define DEEP_ENTRY_START(r, e) ((char*)((r)->base_addr) + (((e)->distance_4bytes)<<2))
	#define DEEP_ENTRY_END(r, e) ((char*)((r)->base_addr) + (((e)->distance_4bytes)<<2) + ((e)->size_4bytes<<2))
	
	#define DEEP_ENTRY_OVERLAPS(r, e, ptr) (DEEP_ENTRY_START((r), (e)) <= (char*)(ptr) && DEEP_ENTRY_END((r), (e)) > (char*) (ptr))
	
	#define MATCH_LEVEL(e, lub, llb) (((lub) == -1 || (e)->level_minus_one + 1 <= (lub)) && \
		((llb) == -1 || (e)->level_minus_one + 1 >= (llb)))
	
	/* FIXME: we need to match levels more cleverly. In particular, 
	 * - we should return the deepest matching object;
	 * - just because find an object at level n, doesn't mean there isn't one at level n+1; 
	 * - but if there isn't, we will search all the way to failure, which is slow.
	 * - how can we avoid this? 
	 * 
	 *     1. by maintaining a flag is_deepest in each entry?
	 *         - This is still slow in the case where we have a deeper object but not overlapping our ptr.
	 *     2. by recursion, somehow? 
	 *         - We can't recurse over contained objects without explicitly storing them
	 */
	
	while (first_attempt - attempt <= biggest_index_displacement_from_natural 
		&& (!attempt->valid 
			|| !DEEP_ENTRY_OVERLAPS(*out_region, attempt, ptr) 
			|| !MATCH_LEVEL(attempt, level_upper_bound, level_lower_bound)))
	{
		/* If we saw any object starting before ptr, tell the enclosing loop in lookup_object_info
		 * that it can give up if we fail. */
		if (attempt->valid && DEEP_ENTRY_START(*out_region, attempt) < (char*) ptr
			&& MATCH_LEVEL(attempt, level_upper_bound, level_lower_bound))
		{
			*out_seen_object_starting_earlier = 1;
		}

		--attempt;
		assert((char*) attempt >= (char*) deep_entry_regions[index].region - deep_entry_regions[index].half_size);
	}
	
	if (first_attempt - attempt > biggest_index_displacement_from_natural)
	{
		// we've failed
	#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, 
			"Failed lookup of deep entry for %p at level >= %d after seeking back %ld places from %p\n", 
				ptr, level_upper_bound, first_attempt - attempt, first_attempt);
	#endif
		
		return NULL;
	}
	
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, 
		"Had to seek back %ld places from %p to look up deep entry for %p\n", first_attempt - attempt, first_attempt, ptr);
#endif
	assert(attempt->level_minus_one + 1 >= level_lower_bound);
	assert(attempt->level_minus_one + 1 <= level_upper_bound);
	return attempt;
	
}

struct deep_entry *__lookup_deep_alloc(void *ptr, int level_upper_bound, int level_lower_bound, 
		struct deep_entry_region **out_region)
{
	_Bool ignored;
	return lookup_deep_alloc(ptr, level_upper_bound, level_lower_bound, out_region, &ignored);
}


static void convert_index_range_to_deep_alloc(void *start_addr, void *end_addr)
{
	/* Walk the bins covering these ranges, and make deep alloc structures
	 * out of them, to replace the existing memtable structures. */
	struct entry *begin_head = INDEX_LOC_FOR_ADDR(start_addr);
	struct entry *end_head = INDEX_LOC_FOR_ADDR(end_addr);

	/* If end_addr is exactly at the start of a bin range, we don't walk that bin, 
	 * but otherwise we do. */
	void *real_end_addr = INDEX_BIN_END_ADDRESS_FOR_ADDR((char*)end_addr - 1);
	
	/* Allocate a deep index. */
	int ind = new_deep_alloc_index(start_addr, real_end_addr, /* HACK / GUESS */ 4);
	// i.e. one deep entry (16 bytes) for every 4 bytes / 0.0625 i.e. every 64 bytes, so 25% space overhead
	
	for (struct entry *cur_entry = begin_head; cur_entry != end_head; ++cur_entry)
	{
		void *cur_userchunk = entry_ptr_to_addr(cur_entry); // might be null
		while (cur_userchunk)
		{
			struct insert *cur_insert = insert_for_chunk(cur_userchunk);

			// build an equivalent entry in the deep space -- FIXME: thread-safety, but to be handled in grab_, not here
			*grab_first_free_deep_entry(ind, cur_userchunk) = (struct deep_entry) {
				.valid = 1,
				.distance_4bytes = ((char*) cur_userchunk - (char*) start_addr) >> 2,
				.level_minus_one = 0,   // allocation level of this object *minus one*, i.e. 1..4
				.size_4bytes = malloc_usable_size(cur_userchunk) >> 2, // byte size in multiples of four bytes -- v. large is very unlikely for nested allocations
				.ins = (struct insert) {
					.alloc_site_flag = cur_insert->alloc_site_flag,
					.alloc_site = cur_insert->alloc_site
				}
			};
#ifdef TRACE_HEAP_INDEX
			fprintf(stderr, 
				"Upgraded l1 chunk at %p to deep alloc representation\n", cur_userchunk);
#endif

			// move to the next chunk
			cur_userchunk = entry_to_same_range_addr(cur_insert->next, cur_userchunk);
		}
		
		// now unlink the whole lot
		// FIXME: thread-safety: unlink as we go
		*cur_entry = (struct entry) { .present = 0, .removed = 1, .distance = ind }; 
#ifdef TRACE_HEAP_INDEX
			fprintf(stderr, 
				"Established deep alloc index between %p and %p\n", start_addr, real_end_addr);
#endif
	}
}

void __index_deep_alloc(void *ptr, int level, unsigned size_bytes) 
{
	// case-split on the ptr
	struct entry *e = INDEX_LOC_FOR_ADDR(ptr);
	
	if (!IS_DEEP_ENTRY(e))
	{
		// it's an empty or non-deep entry; convert it for the whole malloc-span of our current object
		convert_index_range_to_deep_alloc(INDEX_BIN_START_ADDRESS_FOR_ADDR(ptr), 
			INDEX_BIN_END_ADDRESS_FOR_ADDR((char*) ptr + malloc_usable_size(userptr_to_allocptr(ptr))));
	}
	
	assert(IS_DEEP_ENTRY(e));
	struct deep_entry_region *region = &deep_entry_regions[e->distance];
	// add to the existing index
	*grab_first_free_deep_entry(e->distance, ptr) = (struct deep_entry) {
		.valid = 1,
		.distance_4bytes = ((char*) ptr - (char*) region->base_addr) >> 2,
		.level_minus_one = level - 1,   // allocation level of this object *minus one*, i.e. 1..4
		.size_4bytes = size_bytes >> 2, // byte size in multiples of four bytes -- v. large is very unlikely for nested allocations
		.ins = (struct insert) {
			.alloc_site_flag = 0,
			.alloc_site = (uintptr_t) __current_allocsite
		}
	};
}

void __unindex_deep_alloc(void *ptr, int level) 
{
	/* Find the deep alloc entry and free it. */
	struct deep_entry_region *region;
	_Bool ignored;
	struct deep_entry *found = lookup_deep_alloc(ptr, level, level, &region, &ignored);
	assert(found);
	*found = (struct deep_entry) {
		.valid = 0
	};
}
