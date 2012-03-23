/* This set of hook definitions will maintain a memtable of all
 * allocated heap chunks, and will store a "trailer" in each chunk
 * tracking its allocation site. 
 *
 * Compile in C99 mode! We use raw "inline" and possibly other C99 things.
 *
 * For the fastest code, compile -O3 and -DNDEBUG. */

/* 
 * TODO:
 * some sort of thread safety
 * use headers, not trailers, to reduce changes of overrun bugs corrupting data
 * produce allocator-specific versions (dlmalloc, initially) that 
 * - don't need trailers...
 * - ... by stealing bits from the host allocator's "size" field (64-bit only)
 * keep chunk lists sorted within each bin?
 */

/* This file uses GNU C extensions */
#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
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
#if 1
#include "heap_index.h"
#else

/* We use a memtable -- implemented by some C99 static inline functions */
#include "memtable.h"

/* A thread-local variable to override the "caller" arguments. 
 * Platforms without TLS have to do without this feature. */
#ifndef NO_TLS
extern __thread void *__current_allocsite;
#else
#warning "Compiling without __current_allocsite TLS variable."
#define __current_allocsite ((void*)0)
#endif

struct entry
{
	unsigned present:1;
	unsigned removed:1;
	unsigned distance:7;
} __attribute__((packed));

#define WORD_BITSIZE ((sizeof (void*))<<3)
struct trailer
{
	unsigned alloc_site_flag:1;
	unsigned long alloc_site:(WORD_BITSIZE-1);
	/* You can add extra fields here if you like, 
	 * on a "manage them yourself" basis. This is
	 * useful if you do some analysis over the heap
	 * and need some extra per-object metadata. */
	struct entry next;
	struct entry prev;

} __attribute__((packed));
 #endif /* end #ifdef NO_HEADER */
/* ^^^ For now, keeping this structure means increasing memory usage.  
 * Ideally, we want to make this structure fit in reclaimed space. 
 * Specifically, we can steal bits from a "chunk size" field.
 * On 64-bit machines this is fairly easy. On 32-bit it's harder
 * because the size field is smaller! But it can be done.
 * I'll produce a hacked version of dlmalloc which does this,
 * at some point.... */ 

#ifndef NO_TLS
__thread void *__current_allocsite;
#endif

#ifdef MALLOC_USABLE_SIZE_HACK
#include "malloc_usable_size_hack.h"
#endif 

struct entry *index_region;
void *index_max_address;

#define entry_coverage_in_bytes /*1024*/ 512
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
	
	/* Use a memtable with one byte per 1024B (1KB) of memory. */
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

static inline struct trailer *trailer_for_chunk(void *addr)
{
	return (struct trailer*) ((char*) addr + malloc_usable_size(addr)) - 1;
}
static inline struct trailer *trailer_for_chunk_with_usable_size(void *addr, size_t usable_size)
{
	return (struct trailer*) ((char*) addr + usable_size) - 1;
}

#ifndef NDEBUG
/* In this newer, more space-compact implementation, we can't do as much
 * sanity checking. Check that if our entry is not present, our distance
 * is 0. */
#define TRAILER_SANITY_CHECK(p_t) assert( \
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
	void *cur_chunk = head_chunk;
	unsigned count = 0;
	while (cur_chunk != NULL)
	{
		++count;
		TRAILER_SANITY_CHECK(trailer_for_chunk(cur_chunk));
		/* If the next chunk link is null, entry_to_same_range_addr
		 * should detect this (.present == 0) and give us NULL. */
		void *next_chunk
		 = entry_to_same_range_addr(
			trailer_for_chunk(cur_chunk)->next, 
			cur_chunk
		);
#ifdef TRACE_HEAP_INDEX
		fprintf(stderr, "List has a chunk beginning at %p"
			" (usable_size %zu, trailer {next: %p, prev %p})\n",
			cur_chunk, 
			malloc_usable_size(cur_chunk),
			next_chunk,
			entry_to_same_range_addr(
				trailer_for_chunk(cur_chunk)->prev, 
				cur_chunk
			)
		);
#endif
		assert(next_chunk != head_chunk);
		assert(next_chunk != cur_chunk);

		/* If we're not the first element, we should have a 
		 * prev chunk. */
		if (count > 1) assert(NULL != entry_to_same_range_addr(
				trailer_for_chunk(cur_chunk)->prev, 
				cur_chunk
			));


		cur_chunk = next_chunk;
	}
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr,
		"Passed sanity check of list indexed at %p, head chunk %p, "
		"length %d\n", head, head_chunk, count);
#endif
}
#else /* NDEBUG */
#define TRAILER_SANITY_CHECK(p_t)
static void list_sanity_check(entry_type *head) {}
#endif

#define INDEX_LOC_FOR_ADDR(a) MEMTABLE_ADDR_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))

static void 
index_insert(void *new_chunkaddr, size_t modified_size, const void *caller)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	assert(index_region);
	
	/* The address *must* be in our tracked range. Assert this. */
	assert(new_chunkaddr <= (index_end_addr ? index_end_addr : MAP_FAILED));

	/* DEBUGGING: sanity check entire bin */
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Inserting chunk at %p into list indexed at %p\n", 
		new_chunkaddr, INDEX_LOC_FOR_ADDR(new_chunkaddr));
#endif
	list_sanity_check(INDEX_LOC_FOR_ADDR(new_chunkaddr));

	void *head_chunkptr = entry_ptr_to_addr(INDEX_LOC_FOR_ADDR(new_chunkaddr));
	
	/* Populate our extra fields */
	struct trailer *p_trailer = trailer_for_chunk(new_chunkaddr);
	p_trailer->alloc_site_flag = 0U;
	p_trailer->alloc_site = (unsigned long) caller;

	/* Add it to the index. We always add to the start of the list, for now. */
	/* 1. Initialize our trailer. */
	p_trailer->next = addr_to_entry(head_chunkptr);
	p_trailer->prev = addr_to_entry(NULL);
	assert(!p_trailer->prev.present);
	
	/* 2. Fix up the next trailer, if there is one */
	if (p_trailer->next.present)
	{
		trailer_for_chunk(entry_to_same_range_addr(p_trailer->next, new_chunkaddr))->prev
		 = addr_to_entry(new_chunkaddr);
	}
	/* 3. Fix up the index. */
	*INDEX_LOC_FOR_ADDR(new_chunkaddr) = addr_to_entry(new_chunkaddr); // FIXME: thread-safety

	/* sanity checks */
	struct entry *e = INDEX_LOC_FOR_ADDR(new_chunkaddr);
	assert(e->present); // it's there
	assert(trailer_for_chunk(entry_ptr_to_addr(e)));
	assert(trailer_for_chunk(entry_ptr_to_addr(e)) == p_trailer);
	TRAILER_SANITY_CHECK(p_trailer);
	if (p_trailer->next.present) TRAILER_SANITY_CHECK(
		trailer_for_chunk(entry_to_same_range_addr(p_trailer->next, new_chunkaddr)));
	if (p_trailer->prev.present) TRAILER_SANITY_CHECK(
		trailer_for_chunk(entry_to_same_range_addr(p_trailer->prev, new_chunkaddr)));
	list_sanity_check(INDEX_LOC_FOR_ADDR(new_chunkaddr));
}

static void 
post_successful_alloc(void *begin, size_t modified_size, const void *caller)
{
	index_insert(begin, modified_size, __current_allocsite ? __current_allocsite : caller);
}	

static void pre_alloc(size_t *p_size, const void *caller)
{
	/* We increase the size 
	 * by the amount of extra data we store. 
	 * We later use malloc_usable_size to work out where to store our data. */

	*p_size += sizeof (struct trailer);
}
static void index_delete(void *ptr/*, size_t freed_usable_size*/)
{
	/* The freed_usable_size is not strictly necessary. It was added
	 * for handling realloc after-the-fact. In this case, by the time we
	 * get called, the usable size has already changed. However, after-the-fact
	 * is a broken way to handle realloc(), because in the case of a *smaller*
	 * realloc'd size, where the realloc happens in-place, realloc() will overwrite
	 * our trailer with its own (regular heap metadata) trailer, breaking the list.
	 */
#ifdef TRACE_HEAP_INDEX
	fprintf(stderr, "*** Deleting entry for chunk %p, from list indexed at %p\n", 
		ptr, INDEX_LOC_FOR_ADDR(ptr));
#endif

	list_sanity_check(INDEX_LOC_FOR_ADDR(ptr));
	TRAILER_SANITY_CHECK(trailer_for_chunk/*_with_usable_size*/(ptr/*, freed_usable_size*/));

	/* (old comment; still true?) FIXME: we need a big lock around realloc()
	 * to avoid concurrent in-place realloc()s messing with the other trailers we access. */

	/* remove it from the bins */
	void *our_next_chunk = entry_to_same_range_addr(trailer_for_chunk(ptr)->next, ptr);
	void *our_prev_chunk = entry_to_same_range_addr(trailer_for_chunk(ptr)->prev, ptr);
	
	/* FIXME: make these atomic */
	if (our_prev_chunk) 
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(our_prev_chunk));
		trailer_for_chunk(our_prev_chunk)->next = addr_to_entry(our_next_chunk);
	}
	else /* !our_prev_chunk */
	{
		/* removing head of the list */
		*INDEX_LOC_FOR_ADDR(ptr) = addr_to_entry(our_next_chunk);
		if (!our_next_chunk)
		{
			/* ... it's a singleton list, so 
			 * - no prev chunk to update
			 * - the index entry should be non-present
			 * - exit */
			assert(INDEX_LOC_FOR_ADDR(ptr)->present == 0);
			goto out;
		}
	}

	if (our_next_chunk) 
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(our_next_chunk));
		
		/* may assign NULL here, if we're removing the head of the list */
		trailer_for_chunk(our_next_chunk)->prev = addr_to_entry(our_prev_chunk);
	}
	else /* !our_next_chunk */
	{
		/* removing tail of the list... */
		/* ... and NOT a singleton -- we've handled that case already */
		assert(our_prev_chunk);
	
		/* update the previous chunk's trailer */
		trailer_for_chunk(our_prev_chunk)->next = addr_to_entry(NULL);

		/* nothing else to do here, as we don't keep a tail pointer */
	}
	/* Now that we have deleted the record, our bin should be sane,
	 * modulo concurrent reallocs. */
out:
	list_sanity_check(INDEX_LOC_FOR_ADDR(ptr));
}

static void pre_nonnull_free(void *ptr, size_t freed_usable_size)
{
	index_delete(ptr/*, freed_usable_size*/);
}

static void post_nonnull_free(void *ptr) {}

static void pre_nonnull_nonzero_realloc(void *ptr, size_t size, const void *caller, void *__new)
{
	/* When this happens, we *may or may not be freeing an area*
	 * -- i.e. if the realloc fails, we will not actually free anything.
	 * However, in the case of realloc()ing a *slightly smaller* region, 
	 * the allocator might trash our trailer (by writing its own trailer over it). 
	 * So we *must* delete the entry first,
	 * then recreate it later, as it may not survive the realloc() uncorrupted. */
	index_delete(ptr/*, malloc_usable_size(ptr)*/);
}
static void post_nonnull_nonzero_realloc(void *ptr, 
	size_t modified_size, 
	size_t old_usable_size,
	const void *caller, void *__new)
{
	if (__new != NULL)
	{
		/* create a new bin entry */
		index_insert(__new, modified_size, __current_allocsite ? __current_allocsite : caller);
	}
	else 
	{
		/* *recreate* the old bin entry! The old usable size
		 * is the *modified* size, i.e. we modified it before
		 * allocating it, so we pass it as the modified_size to
		 * index_insert. */
		index_insert(ptr, old_usable_size, __current_allocsite ? __current_allocsite : caller);
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
			struct trailer *cur_trailer = trailer_for_chunk(cur_chunk);
			cur_chunk = entry_to_same_range_addr(cur_trailer->next, cur_chunk);
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
struct trailer *lookup_object_info(const void *mem, void **out_object_start)
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
		void *cur_chunk = entry_ptr_to_addr(cur_head);
		seen_object_starting_earlier = 0;

		while (cur_chunk)
		{
			struct trailer *cur_trailer = trailer_for_chunk(cur_chunk);
			if (mem >= cur_chunk
				&& mem < cur_chunk + malloc_usable_size(cur_chunk)) 
			{
				if (out_object_start) *out_object_start = cur_chunk;
				return cur_trailer;
			}
			
			// do that optimisation
			if (cur_chunk < mem) seen_object_starting_earlier = 1;
			
			cur_chunk = entry_to_same_range_addr(cur_trailer->next, cur_chunk);
		}
		
		/* we reached the end of the list */
	} while (!seen_object_starting_earlier
		&& (object_minimum_size += entry_coverage_in_bytes,
		cur_head-- > &index_region[0] && object_minimum_size <= BIGGEST_SENSIBLE_OBJECT));
	return NULL;
	/* FIXME: use the actual biggest allocated object, not a guess. */

#undef BIGGEST_SENSIBLE_OBJECT
}
