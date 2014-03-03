/* This set of hook definitions will maintain a memtable of all
 * allocated heap chunks, and will store a "header" in each chunk
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

// always use the header for now, while we're changing stuff...
//#ifndef NO_HEADER
#include "heap_index.h"

/* For now, headers increase memory usage.  
 * Ideally, we want to make headers/trailers fit in reclaimed space. 
 * Specifically, we can steal bits from a "chunk size" field.
 * On 64-bit machines this is fairly easy. On 32-bit it's harder
 * because the size field is smaller! But it can be done.
 * I'll produce a hacked version of dlmalloc which does this,
 * at some point.... */ 

#ifndef NO_TLS
__thread void *__current_allocsite;
__thread void *__current_allocfn;
__thread size_t __current_allocsz;
#else
void *__current_allocsite;
void *__current_allocfn;
size_t __current_allocsz;
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

static inline struct header *header_for_chunk(void *userptr);

#ifndef NDEBUG
/* In this newer, more space-compact implementation, we can't do as much
 * sanity checking. Check that if our entry is not present, our distance
 * is 0. */
#define HEADER_SANITY_CHECK(p_t) assert( \
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
		HEADER_SANITY_CHECK(header_for_chunk(cur_userchunk));
		/* If the next chunk link is null, entry_to_same_range_addr
		 * should detect this (.present == 0) and give us NULL. */
		void *next_userchunk
		 = entry_to_same_range_addr(
			header_for_chunk(cur_userchunk)->next, 
			cur_userchunk
		);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "List has a chunk beginning at userptr %p"
			" (usable_size %zu, header {next: %p, prev %p})\n",
			cur_userchunk, 
			malloc_usable_size(userptr_to_allocptr(cur_userchunk)),
			next_userchunk,
			entry_to_same_range_addr(
				header_for_chunk(cur_userchunk)->prev, 
				cur_userchunk
			)
		);
#endif
		assert(next_userchunk != head_chunk);
		assert(next_userchunk != cur_userchunk);

		/* If we're not the first element, we should have a 
		 * prev chunk. */
		if (count > 1) assert(NULL != entry_to_same_range_addr(
				header_for_chunk(cur_userchunk)->prev, 
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
#define HEADER_SANITY_CHECK(p_t)
static void list_sanity_check(entry_type *head) {}
#endif

#define INDEX_LOC_FOR_ADDR(a) MEMTABLE_ADDR_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))

static void 
index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	assert(index_region);
	
	/* The address *must* be in our tracked range. Assert this. */
	assert(new_userchunkaddr <= (index_end_addr ? index_end_addr : MAP_FAILED));

	/* DEBUGGING: sanity check entire bin */
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Inserting user chunk at %p into list indexed at %p\n", 
		new_userchunkaddr, INDEX_LOC_FOR_ADDR(new_userchunkaddr));
#endif
	list_sanity_check(INDEX_LOC_FOR_ADDR(new_userchunkaddr));

	void *head_chunkptr = entry_ptr_to_addr(INDEX_LOC_FOR_ADDR(new_userchunkaddr));
	
	/* Populate our extra fields */
	struct header *p_header = header_for_chunk(new_userchunkaddr);
	p_header->alloc_site_flag = 0U;
	p_header->alloc_site = (unsigned long) caller;

	/* Add it to the index. We always add to the start of the list, for now. */
	/* 1. Initialize our header. */
	p_header->next = addr_to_entry(head_chunkptr);
	p_header->prev = addr_to_entry(NULL);
	assert(!p_header->prev.present);
	
	/* 2. Fix up the next header, if there is one */
	if (p_header->next.present)
	{
		header_for_chunk(entry_to_same_range_addr(p_header->next, new_userchunkaddr))->prev
		 = addr_to_entry(new_userchunkaddr);
	}
	/* 3. Fix up the index. */
	*INDEX_LOC_FOR_ADDR(new_userchunkaddr) = addr_to_entry(new_userchunkaddr); // FIXME: thread-safety

	/* sanity checks */
	struct entry *e = INDEX_LOC_FOR_ADDR(new_userchunkaddr);
	assert(e->present); // it's there
	assert(header_for_chunk(entry_ptr_to_addr(e)));
	assert(header_for_chunk(entry_ptr_to_addr(e)) == p_header);
	HEADER_SANITY_CHECK(p_header);
	if (p_header->next.present) HEADER_SANITY_CHECK(
		header_for_chunk(entry_to_same_range_addr(p_header->next, new_userchunkaddr)));
	if (p_header->prev.present) HEADER_SANITY_CHECK(
		header_for_chunk(entry_to_same_range_addr(p_header->prev, new_userchunkaddr)));
	list_sanity_check(INDEX_LOC_FOR_ADDR(new_userchunkaddr));
}

static void *allocptr_to_userptr(void *allocptr)
{
	/* The no-breadcrumb case is the common case. */
	if (!allocptr) return NULL;
	if (__builtin_expect(
			(uintptr_t) ((struct header *) allocptr)->alloc_site >= 0x1000,
			1)
		)
	{
		return (char *)allocptr + sizeof (struct header);
	}
	else
	{
		/* The alloc-to-user breadcrumb case: the allocsite field low-order bits hold 
		 * the alignment as a power of two, from which we can compute the user ptr. */
		size_t requested_alignment
		 = 1ul << (((uintptr_t) (((struct header *) allocptr)->alloc_site)) & 0xfff);
		uintptr_t userptr
		 = requested_alignment * (
				((uintptr_t) ((char *)allocptr + sizeof (struct header)) / requested_alignment) + 1);
		return (void*) userptr;
	}
}

static void *userptr_to_allocptr(void *userptr)
{
	/* The no-breadcrumb case is the common case. */
	if (!userptr) return NULL;
	if (__builtin_expect(
			(uintptr_t) ((struct header *) ((char *) userptr - sizeof (struct header)))
				->alloc_site >= 0x1000,
			1)
		)
	{
		return (char *)userptr - sizeof (struct header);
	}
	else
	{
		/* The user-to-alloc breadcrumb case: the allocsite field low-order bits hold
		 * the alignment. */
		size_t log_requested_alignment = ((uintptr_t) ((((struct header *) userptr)-1)->alloc_site)) & 0xfff;
		size_t requested_alignment = 1ul << log_requested_alignment;
		
		// 
		// 	userptr = requested_alignment * (((uintptr_t) (allocptr + sizeof(struct header)) / requested_alignment) + 1);
		// 
		// => userptr / requested_alignment == (((uintptr_t) (allocptr + sizeof(struct header)) / requested_alignment) + 1);
		// 
		// => (u / r_a) - 1 == (((uintptr_t) (allocptr + sizeof(struct header)) / requested_alignment)
		//
		// => r_a * ((u / r_a) - 1) + remainder == allocptr + sizeof(struct header)
		// 
		// and we have asserted that the remainder == sizeof (struct header), so 
		// 
		// => allocptr == r_a * ((u / r_a) - 1) - sizeof (struct header) + remainder
		// 
		// => allocptr == r_a * ((u / r_a) - 1)

		uintptr_t allocptr
		 = requested_alignment * (((uintptr_t) userptr >> log_requested_alignment) - 1);
		assert(allocptr_to_userptr((void*) allocptr) == userptr);
		return (void*) allocptr;
	}
}

static inline struct header *header_for_chunk(void *userptr)
{
	/* The no-breadcrumb case is the common case */
	struct header *possible = (struct header*) ((char*) userptr - sizeof (struct header));
	if (__builtin_expect(
			(uintptr_t) possible->alloc_site >= 0x1000, 
			1)
		)
	{
		return possible;
	}
	else
	{
		/* The real header is *two* headers back. */
		return (struct header*) ((char*) userptr - 2 * sizeof (struct header));
	}
}

static void 
post_successful_alloc(void *allocptr, size_t modified_size, size_t modified_alignment, 
		size_t requested_size, size_t requested_alignment, const void *caller)
{
	/* We always index just the userptr! index_insert will use 
	 * header_for_chunk to find its insert, even if it uses breadcrumbs. */
	void *candidate_userptr = (char*) allocptr + sizeof (struct header); // HACK: shouldn't know this here
	void *userptr;
	
	/* We need to set up breadcrumbs *right now*, because index_insert will want them. */
	/* Since we have the pointer we were actually allocated, 
	 * we can be conservative about whether to use breadcrumbs.  */
	if (__builtin_expect((uintptr_t) candidate_userptr % requested_alignment != 0, 0))
	{
		/* We need breadcrumbs case: set up breadcrumbs so that our userptr 
		 * and allocptr can be found from one another. We must have
		 * at least three inserts' worth of space in the chunk -- which 
		 * we ensured in pre_alloc. */
		
		userptr = (void*)(requested_alignment * (((uintptr_t) candidate_userptr / requested_alignment) + 1));
		// i.e.
		// userptr = requested_alignment * (((uintptr_t) ((char*) allocptr + sizeof (struct header)) / requested_alignment) + 1);
		assert((char *) userptr >= (char*) allocptr + 3 * sizeof (struct header));
		assert(userptr < allocptr + modified_size);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "Alignment/breadcrumb logic issued user ptr %p for alloc ptr %p " 
					"(user requested align %d, hook requested align %d, user requested size %d, hook requested size %d)\n", 
					userptr, allocptr, requested_alignment, modified_alignment,
					requested_size, modified_size);
#endif
		/* We need to be able to reproduce the above userptr calculation 
		 * in the alloc-to-user case, and *invert* it in the user-to-alloc case. 
		 *
		 * Reproducing it: store the requested alignment, as a power of two.
		 
		 * Inverting it: this means storing the *remainder* of the division. 
		 * How large can the remainder get? Clearly it's in the range 
		 * 0..(requested_alignment - 1).
		 * And since we got it from allocptr + sizeof (struct header), 
		 * and allocptr is modified_alignment-aligned, 
		 * it's very likely to be one word, or else one word plus some power of two
		 * less than the modified alignment but greater than or equal to the 
		 * requested alignment. That's only one possible power of two! 
		 * I'm going to assert that it's one word, and figure out what's happening
		 * in other cases via debugging. */
		uintptr_t remainder = ((uintptr_t) candidate_userptr % requested_alignment);
		assert(remainder == sizeof (struct header));
		
		// user-to-alloc breadcrumb
		struct header bu = { 0, integer_log2(requested_alignment), 0, 0 };
		// alloc_to_user breadcrumb
		struct header ba = { 0, integer_log2(requested_alignment), 0, 0 };
		// actual insert: initialized by index_insert
		
		// write the breadcrumbs into the chunk
		*(struct header *)allocptr = ba;
		*(((struct header *)userptr) - 1) = bu;
	} 
	else
	{
		userptr = candidate_userptr;
		/* HACK: 
		 * we need to pre-initialize the header because until we have a valid 
		 * alloc_site, header_to_chunk can't tell where to find the real header
		 * versus where the breadcrumbs are.
		 */ 
		*(((struct header *)userptr) - 1) = (struct header) { 0, (uintptr_t) caller, 0, 0};
	}
	
	index_insert(userptr, modified_size, __current_allocsite ? __current_allocsite : caller);
}

static void pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller)
{
	/* We increase the size by the amount of extra data we store, 
	 * and possibly a bit more to allow for alignment.  */
	size_t orig_size = *p_size;
	size_t size_to_allocate = orig_size + sizeof (struct header);
	if (*p_alignment > sizeof (void*))
	{
		// bump up size by alignment or two inserts (for breadcrumbs), whichever is more
		size_t two_inserts = 2 * sizeof (struct header);
		size_to_allocate += (two_inserts > *p_alignment) ? two_inserts : *p_alignment;
		*p_alignment *= 2;
		
		/* Why is this sufficient? Recall that if we have a nontrivial alignment, 
		 * it's because we're calling memalign. Memalign *will* return a pointer with
		 * the requested alignment; it's just that our alloc-to-user is going
		 * to destroy that alignment. 
		 * 
		 * One approach would be to ask for *twice* the alignment and *twice* the size. 
		 * Then we're guaranteed an address in the *middle* of the chunk with adequate 
		 * space and adequate alignment. But this seems unnecessarily wasteful. 
		 * 
		 * It is sufficient instead to bump up the size by alignment?  
		 * Suppose we're asking for m bytes aligned to k bytes.
		 * Does m + k aligned to k + 1 always contain an appropriate address?
		 * We are issued a pointer p, 
		 * the first possible userptr with appropriate alignment is p + k, 
		 * which need only have (m + k) - k bytes remaining. This is clearly okay. */
		
	}
	*p_size = size_to_allocate;
}
static void index_delete(void *userptr/*, size_t freed_usable_size*/)
{
	/* The freed_usable_size is not strictly necessary. It was added
	 * for handling realloc after-the-fact. In this case, by the time we
	 * get called, the usable size has already changed. However, after-the-fact
	 * was a broken way to handle realloc() when we were using trailers instead
	 * of headers, because in the case of a *smaller*
	 * realloc'd size, where the realloc happens in-place, realloc() would overwrite
	 * our header with its own (regular heap metadata) trailer, breaking the list.
	 */
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from list indexed at %p\n", 
		userptr, INDEX_LOC_FOR_ADDR(userptr));
#endif

	list_sanity_check(INDEX_LOC_FOR_ADDR(userptr));
	HEADER_SANITY_CHECK(header_for_chunk/*_with_usable_size*/(userptr/*, freed_usable_size*/));

	/* (old comment; still true?) FIXME: we need a big lock around realloc()
	 * to avoid concurrent in-place realloc()s messing with the other headers we access. */

	/* remove it from the bins */
	void *our_next_chunk = entry_to_same_range_addr(header_for_chunk(userptr)->next, userptr);
	void *our_prev_chunk = entry_to_same_range_addr(header_for_chunk(userptr)->prev, userptr);
	
	/* FIXME: make these atomic */
	if (our_prev_chunk) 
	{
		HEADER_SANITY_CHECK(header_for_chunk(our_prev_chunk));
		header_for_chunk(our_prev_chunk)->next = addr_to_entry(our_next_chunk);
	}
	else /* !our_prev_chunk */
	{
		/* removing head of the list */
		*INDEX_LOC_FOR_ADDR(userptr) = addr_to_entry(our_next_chunk);
		if (!our_next_chunk)
		{
			/* ... it's a singleton list, so 
			 * - no prev chunk to update
			 * - the index entry should be non-present
			 * - exit */
			assert(INDEX_LOC_FOR_ADDR(userptr)->present == 0);
			goto out;
		}
	}

	if (our_next_chunk) 
	{
		HEADER_SANITY_CHECK(header_for_chunk(our_next_chunk));
		
		/* may assign NULL here, if we're removing the head of the list */
		header_for_chunk(our_next_chunk)->prev = addr_to_entry(our_prev_chunk);
	}
	else /* !our_next_chunk */
	{
		/* removing tail of the list... */
		/* ... and NOT a singleton -- we've handled that case already */
		assert(our_prev_chunk);
	
		/* update the previous chunk's header */
		header_for_chunk(our_prev_chunk)->next = addr_to_entry(NULL);

		/* nothing else to do here, as we don't keep a tail pointer */
	}
	/* Now that we have deleted the record, our bin should be sane,
	 * modulo concurrent reallocs. */
out:
	list_sanity_check(INDEX_LOC_FOR_ADDR(userptr));
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
	 * the allocator might trash our header (by writing its own trailer over it). 
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

/* Mainly for the memtable-perf performance tests...  
 * this function returns a chunk pointer equal to mem,
 * if and only if mem is a valid chunk pointer. Otherwise
 * it returns NULL. FIXME: support interior pointers. */
void *lookup_metadata(void *mem)
{
	assert(index_region);
	
	struct entry *cur_head = INDEX_LOC_FOR_ADDR(mem);
	size_t object_minimum_size = 0;
	
	do
	{
		void *cur_chunk = entry_ptr_to_addr(cur_head);

		while (cur_chunk)
		{
			if (mem == cur_chunk) return cur_chunk;
			struct header *cur_header = header_for_chunk(cur_chunk);
			cur_chunk = entry_to_same_range_addr(cur_header->next, cur_chunk);
		}
		/* we reached the end of the list */
		return NULL; /* HACK: we can do this because the benchmark only passes object
						start addresses. Otherwise we'd have to keep on searching, up to 
						the size of the biggest object allocated so far in the program. */
	} while (object_minimum_size += entry_coverage_in_bytes,
		cur_head-- > &index_region[0]);
	/* We have to assume the object may be a big object whose record is in 
	 * an earlier bin. We should only iterate up to some sane "maximum object size",
	 * which we could track as the biggest object malloc'd so far; 
	 * terminate once object_minimum_size exceeds this. FIXME. */
	
}

/* A more client-friendly lookup function. */
struct header *lookup_object_info(const void *mem, void **out_object_start)
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
		void *cur_userchunk = entry_ptr_to_addr(cur_head);
		seen_object_starting_earlier = 0;

		while (cur_userchunk)
		{
			struct header *cur_header = header_for_chunk(cur_userchunk);
#ifndef NDEBUG
			/* Sanity check on the header. */
			if ((char*) cur_userchunk - (char*) cur_header != sizeof(struct header))
			{
				fprintf(stderr, "Saw insane header address %p for chunk beginning %p "
					"(usable size %zu, allocptr %p); memory corruption?\n", 
					cur_header, cur_userchunk, malloc_usable_size(userptr_to_allocptr(cur_userchunk)), userptr_to_allocptr(cur_userchunk));
			}	
#endif
			if (mem >= cur_userchunk
				&& mem < cur_userchunk + malloc_usable_size(userptr_to_allocptr(cur_userchunk))) 
			{
				if (out_object_start) *out_object_start = cur_userchunk;
				return cur_header;
			}
			
			// do that optimisation
			if (cur_userchunk < mem) seen_object_starting_earlier = 1;
			
			cur_userchunk = entry_to_same_range_addr(cur_header->next, cur_userchunk);
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

void __check_alloc_indexed(void *ptr) 
{
	// noop for now
}
