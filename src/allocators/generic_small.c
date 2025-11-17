#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"


struct entry {
	union {
		struct {
			unsigned long discr:48; /* zero? null; small? continuation; non-small lower-half? regular_initial; non-small upper-half? regular with type */
			unsigned bucket_offset:8; /* offset into the bucket of obj start (zero for continuations) */
			unsigned thisbucket_size:8;
		} common;
		struct{
			unsigned long alloc_site:47; /* never zero, never small */
			unsigned always_zero:1;
			unsigned bucket_offset:8;         /* obj start displacement from bucket start; may be zero */
			unsigned thisbucket_size:8;
		} regular_initial;
		struct{
			/* XXX: beware: we assume bitfields are allocated from least
			 * significant to most significant. This is required by the
			 * System V x86_64 ABI but others may vary. */
			unsigned alloc_site_id:16;
			unsigned long uniqtype_id:27;
			unsigned lifetime_policies:4; /* may be zero */
			unsigned always_one:1;
			/* The above fields constitute a 48-bit unsigned integer whose value is always
			 * in the top half of the range, because of the always_one MSB. */
			unsigned bucket_offset:8; /* may be zero */
			unsigned thisbucket_size:8;
		} regular_with_type;
		struct{
			unsigned long size:22; /* largest object is 4MB */ /* FIXME: define and use LOG_MINIMUM_USER_ADDRESS */
			unsigned long always_zero:26; /* ensure our 48-bit value is < MINIMUM_USER_ADDRESS */
			unsigned unused:8; /* continuations always *start* at offset zero */
			unsigned thisbucket_size:8;
		} continuation;
	};
} __attribute((packed));


#define ENTRY_IS_CONTINUATION(entry) \
	((entry)->common.discr != 0 && (entry)->common.discr < MINIMUM_USER_ADDRESS)

#define ENTRY_IS_NULL(entry) ((entry)->common.discr == 0)
#define ENTRY_GET_STORED_OFFSET(entry) ((entry)->common.bucket_offset)
#define ENTRY_GET_THISBUCKET_SIZE(entry) ((entry)->common.thisbucket_size)

#ifndef NO_PTHREADS
#define THE_MUTEX &mutex
/* We're recursive only because assertion failures sometimes want to do 
#define BIG_LOCK \
	lock_ret = pthread_mutex_lock(&mutex); \
	assert(lock_ret == 0);
#define BIG_UNLOCK \
	lock_ret = pthread_mutex_unlock(&mutex); \
	assert(lock_ret == 0);
/* We're recursive only because assertioalloc_siten failures sometimes want to do 
 * asprintf, so try to re-acquire our mutex. */
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#endif
#include "generic_malloc_index.h"

/* All new, new plan for sub-allocators. 
 * 
 * extract the bitmap code into memtable.h
 * extract the rectangular-array code similarly
 *     ** PROBLEM is that each rectangular element
 *        needs to record its offset from the chunk --
 *            use a user-supplied macro for this? YES, similar to entry_coverage_...
 * remove the caching stuff
 * split the "suballocated chunks" records
 *     into per-allocation metadata 
 *     OH. But what we want is *per-suballocator metadata* in the bigalloc,
 *     whereas current metadata is for the allocating allocator's use.
 *     Need to add suballocator metadata to the bigalloc record.
 */

/* The info that describes the whole arena that we're allocating out of. */
struct chunk_rec
{
	struct entry *metadata_recs;
	unsigned long *starts_bitmap;
	size_t power_of_two_size;
	char log_pitch;
	size_t one_layer_nbytes;
	unsigned long biggest_object;
};

/* A rectangular memtable, or memrect, is structured into "buckets" 
 * covering a certain address range. The width of this range is the 
 * "bucket pitch".
 *
 * Transversely, the table is structured in layers. Each bucket has one
 * entry per layer, up to some total number of layers. It follows that
 * the number of buckets multiplied by the number of layers is the total
 * (maximum) number of entries in the table.
 * 
 * Layers are populated from 0 downwards. If a bucket has nothing in
 * layer k, it will have nothing in layer k+1.
 * 
 * Layers, not buckets, are contiguous in virtual memory. Ordinarily,
 * the first N layers will be mostly used, and the remaining M layers
 * will be mostly unused, hence unallocated.
 * 
 * To read or write a entry in the table, keyed on some address K, we 
 * iterate along the bucket into which K maps. We start with the first
 * layer, then try deeper layers until we find the entry we're looking
 * for or an empty reord
 * 
 * A memrect is defined by the following parameters:
 *    base address covered,
 *    length of covered region,
 *    pitch (log-base-two)
 *    entry size
 *    maximum depth   (controls maximum density; set to the pitch, for one-rec-per-address)
 */

static inline 
uintptr_t memrect_nbucket_of(void *addr, void *table_coverage_start_addr, unsigned char log_bucket_pitch)
{
	return ((uintptr_t) addr - (uintptr_t) table_coverage_start_addr) >> log_bucket_pitch;
}

static inline
uintptr_t memrect_bucket_offset_of_addr(void *addr, void *table_coverage_start_addr, unsigned char log_bucket_pitch)
{
	return ((uintptr_t) addr - (uintptr_t) table_coverage_start_addr) % (1ul<<log_bucket_pitch);
}

static inline
unsigned memrect_entries_per_layer(size_t power_of_two_size, unsigned char log_bucket_pitch)
{
	return power_of_two_size >> log_bucket_pitch;
}

static inline
void *
memrect_bucket_range_base(void *bucket, void *rect_base, void *table_coverage_start_addr, 
		unsigned char log_bucket_pitch, unsigned char log_entry_size)
{
	size_t index_of_bucket = ((char*) bucket - (char*) rect_base) >> log_entry_size;
	return (char*) table_coverage_start_addr
			+ (index_of_bucket << log_bucket_pitch);
}

#define ENTRIES_PER_LAYER(p_chunk_rec) \
    (memrect_entries_per_layer((p_chunk_rec)->power_of_two_size, \
	 (p_chunk_rec)->log_pitch))
#define NLAYERS(p_chunk_rec) (1ul<<(p_chunk_rec)->log_pitch)

#define LOG_ENTRY_SIZE 3 /* entry size is 8; FIXME: static-assert 1<<this equals sizeof (struct entry) */

#define BUCKET_RANGE_BASE(p_bucket, p_chunk_rec, coverage_start) \
	(memrect_bucket_range_base((p_bucket), (p_chunk_rec)->metadata_recs, \
		(coverage_start), (p_chunk_rec)->log_pitch, LOG_ENTRY_SIZE))
    
#define BUCKET_RANGE_END(p_bucket, p_chunk_rec, coverage_start) \
    (((char*)BUCKET_RANGE_BASE((p_bucket), (p_chunk_rec), (coverage_start))) + (1u<<(p_chunk_rec)->log_pitch))
#define BUCKET_PTR_FROM_ENTRY_PTR(p_ent, p_chunk_rec, container) \
	((p_chunk_rec)->metadata_recs + (((p_ent) - (p_chunk_rec)->metadata_recs) % \
	memrect_entries_per_layer((p_chunk_rec)->power_of_two_size, (p_chunk_rec)->log_pitch)))

static
struct entry *lookup_small_alloc(const void *ptr, 
		struct chunk_rec *p_chunk_rec,
		struct big_allocation *container,
		void **out_object_start,
		size_t *out_object_size);

static void unindex_small_alloc_internal_with_ent(void *ptr, struct chunk_rec *p_chunk_rec, struct big_allocation *container,
	struct entry *p_ent);

static void unindex_small_alloc_internal(void *ptr, struct chunk_rec *p_chunk_rec,
	struct big_allocation *container);

static 
void 
check_bucket_sanity(struct entry *p_bucket, struct chunk_rec *p_chunk_rec, struct big_allocation *container);

#define MAX_PITCH 256 /* Don't support larger than 256-byte pitches, s.t. remainder fits in one byte */

static struct chunk_rec *make_suballocated_chunk(void *chunk_base, size_t chunk_size, 
		size_t guessed_average_size)
{
	assert(chunk_size != 0);
	struct chunk_rec *p_chunk_rec = __private_malloc(sizeof (struct chunk_rec));
	/* FIXME: free this somewhere! seems leaky right now */
	*p_chunk_rec = (struct chunk_rec) {
		.power_of_two_size = next_power_of_two_ge(chunk_size),
		.metadata_recs = NULL,
		.log_pitch = 0,
		.one_layer_nbytes = 0,
		.biggest_object = 0,
		.starts_bitmap = mmap(NULL, sizeof (unsigned long) * (chunk_size / UNSIGNED_LONG_NBITS),
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
	}; // others 0 for now
	
	if (guessed_average_size > MAX_PITCH) guessed_average_size = MAX_PITCH;
	p_chunk_rec->log_pitch = integer_log2(next_power_of_two_ge(guessed_average_size));
	
	/* The size of a layer is (normally) 
	 * the number of bytes required to store one metadata entry per average-size unit. */
	p_chunk_rec->one_layer_nbytes = (sizeof (struct entry)) * (p_chunk_rec->power_of_two_size >> p_chunk_rec->log_pitch);
	assert(is_power_of_two(p_chunk_rec->one_layer_nbytes));
	
	/* For small chunks, we might not fill a page, so resize the pitch so that we do. */
	if (__builtin_expect( p_chunk_rec->one_layer_nbytes < PAGE_SIZE, 0))
	{
		// force a one-page layer size, and recalculate the pitch
		p_chunk_rec->one_layer_nbytes = PAGE_SIZE;
		/* 
		      one_layer_nbytes == sizeof entry * chunk_size / pitch
		
		  =>  pitch            == sizeof entry * chunk_size / one_layer_nbytes
		  
		*/
		unsigned pitch = ((sizeof (struct entry)) * p_chunk_rec->power_of_two_size) >> LOG_PAGE_SIZE;
		assert(is_power_of_two(pitch));
		p_chunk_rec->log_pitch = integer_log2(pitch);
		/* Note also that 
		
		      one_layer_nrecs  == chunk_size / pitch
		*/
	}
	unsigned nbuckets = p_chunk_rec->one_layer_nbytes / sizeof (struct entry);
	assert(nbuckets < (uintptr_t) MINIMUM_USER_ADDRESS); // see note about size in index logic, below
	// FIXME: if this fails, increase the pitch until it's true
	
	/* The pitch equals the number of layers, because we allocate enough layers
	 * to go right down to byte-sized allocations.
	 * 
	 * It follows that we allocate enough virtual memory for one entry per byte. */
	unsigned long nbytes = (sizeof (struct entry)) * p_chunk_rec->power_of_two_size;

	p_chunk_rec->metadata_recs = mmap(NULL, nbytes,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	assert(p_chunk_rec->metadata_recs != MAP_FAILED);
	
	return p_chunk_rec;
}


static int index_small_alloc_internal(void *ptr, unsigned size_bytes, 
	struct big_allocation *container)
{
	if (!container) abort();
	
	/* This chunk already records a suballocated region. */
	struct chunk_rec *p_chunk_rec = container->suballocator_private;
	assert(p_chunk_rec);
#ifdef HEAP_INDEX_SMALL_BITMAP_ONLY
	/* Just maintain the bitmap. Set the first bit and clear up to the size of the object. */
	bitmap_set_le(p_chunk_rec->starts_bitmap, (char*) ptr - (char*) existing_object_start);
// 	/* We clear in three phases.
// 	 * 1. bytes from start + 1 */
// 	unsigned nbyte = 1;
// 	while (nbyte < size_bytes && nbyte < 8) 
// 	{
// 		bitmap_clear_le(p_chunk_rec->starts_bitmap, 
// 			((char*) ptr - (char*) existing_object_start) + nbyte);
// 		nbyte++;
// 	}
// 	/* 2. bytes from 8 to ROUND_DOWN(size, 8) */
// 	while (nbyte < size_bytes && nbyte < 8 * (size_bytes / 8))
// 	{
// 		p_chunk_rec->starts_bitmap[((char*) ptr - (char*) existing_object_start) / UNSIGNED_LONG_NBITS] = 0;
// 		nbyte += UNSIGNED_LONG_NBITS;
// 	}
// 	/* 3. remaining bytes at the end */
// 	while (nbyte < size_bytes)
// 	{
// 		bitmap_clear_le(p_chunk_rec->starts_bitmap, 
// 			((char*) ptr - (char*) existing_object_start) + nbyte);
// 		nbyte++;
// 	}
#else
	char *end_addr = (char*) ptr + size_bytes;
	
	/* Recall: bucket offset is the offset of ptr from the start of the memory range
	 * covered by its metadata bucket. */
	unsigned short bucket_offset = memrect_bucket_offset_of_addr(ptr, container->begin, p_chunk_rec->log_pitch);
	
	/* Get the relevant bucket. */
	unsigned long bucket_num = memrect_nbucket_of(ptr, container->begin, p_chunk_rec->log_pitch);
	struct entry *p_bucket = p_chunk_rec->metadata_recs + bucket_num;
	check_bucket_sanity(p_bucket, p_chunk_rec, container);

	/* Now we need to find a free metadata entry to index this allocation at. */
	/* What's the first layer that's free? */
	struct entry *p_ent = p_bucket;
	unsigned layer_num = 0;
	while (!ENTRY_IS_NULL(p_ent))
	{
		p_ent += ENTRIES_PER_LAYER(p_chunk_rec);
		++layer_num;
	}
	// we should never need to go beyond the last layer
	assert(layer_num < NLAYERS(p_chunk_rec));
		
	/* We also need to represent the object's size somehow. We choose to use 
	 * continuation entries since the entry doesn't have enough bits.
	 * The alloc site entries the bucket number in which the object starts. This limits us to
	 * 4M buckets, so a 32MByte chunk for 8-byte-pitch, etc., which seems
	 * bearable for the moment. 
	 */
	unsigned short thisbucket_size = (memrect_nbucket_of(end_addr, container->begin, p_chunk_rec->log_pitch) == bucket_num) 
			? size_bytes
			: (1u << p_chunk_rec->log_pitch) - bucket_offset;
	assert(thisbucket_size != 0);
	assert(thisbucket_size <= (1u << p_chunk_rec->log_pitch));
	

	*p_ent = (struct entry) { .regular_initial = {
		.alloc_site = (unsigned long) __current_allocsite,
		.bucket_offset = bucket_offset,
		.thisbucket_size = thisbucket_size
	} };
	
	/* We should be sane already, even though our continuation is not recorded. */
	check_bucket_sanity(p_bucket, p_chunk_rec, container);
	
	/* If we spill into the next bucket, set the continuation entry */
	if ((char*)(BUCKET_RANGE_END(p_bucket, p_chunk_rec, container->begin)) < end_addr)
	{
		struct entry *p_continuation_bucket = p_bucket + 1;
		assert(p_continuation_bucket - &p_chunk_rec->metadata_recs[0] < (uintptr_t) MINIMUM_USER_ADDRESS);
		check_bucket_sanity(p_continuation_bucket, p_chunk_rec, container);
		struct entry *p_continuation_ent = p_continuation_bucket;
		/* Find a free slot */
		unsigned layer_num = 0;
		while (!ENTRY_IS_NULL(p_continuation_ent))
		{ p_continuation_ent += ENTRIES_PER_LAYER(p_chunk_rec); ++layer_num; }
		assert(layer_num < NLAYERS(p_chunk_rec));
		
		unsigned long size_after_first_bucket = size_bytes - thisbucket_size;
		assert(size_after_first_bucket != 0);
		unsigned long size_in_continuation_bucket 
		 = (size_after_first_bucket > (1u<<p_chunk_rec->log_pitch)) ? 0 : size_after_first_bucket;

		// install the continuation entry
		assert(size_bytes > 0);
		assert(size_bytes < (uintptr_t) MINIMUM_USER_ADDRESS);
		*p_continuation_ent = (struct entry) {
			.continuation = {
				size: size_bytes,
				thisbucket_size: size_in_continuation_bucket
			}
		};
		assert(ENTRY_IS_CONTINUATION(p_continuation_ent));
		check_bucket_sanity(p_continuation_bucket, p_chunk_rec, container);
	}
	
	check_bucket_sanity(p_bucket, p_chunk_rec, container);
	if (p_chunk_rec->biggest_object < size_bytes) p_chunk_rec->biggest_object = size_bytes;
	
#ifndef NDEBUG
	struct entry *p_found_ent1 = lookup_small_alloc(ptr, p_chunk_rec, container, NULL, NULL);
	assert(p_found_ent1 == p_ent);
	struct entry *p_found_ent2 = lookup_small_alloc((char*) ptr + size_bytes - 1, 
		p_chunk_rec, container, NULL, NULL);
	assert(p_found_ent2 == p_ent);
#endif
	
#endif
	return 2; // FIXME
}
static void unindex_all_overlapping(void *unindex_start, void *unindex_end, 
		struct chunk_rec *p_chunk_rec, struct big_allocation *container)
{
	unsigned long bucket_num = memrect_nbucket_of(unindex_start, container->begin,
		p_chunk_rec->log_pitch);
	struct entry *p_bucket = p_chunk_rec->metadata_recs + bucket_num;
	// 0. handle the case of an object starting [maybe much] earlier
	// creeping over into this bucket.
	void *earlier_object_start;
	size_t earlier_object_size;
	struct entry *p_old_ent = lookup_small_alloc(unindex_start, p_chunk_rec,
		container, &earlier_object_start, &earlier_object_size);
	if (p_old_ent) 
	{
		unindex_small_alloc_internal_with_ent(earlier_object_start, p_chunk_rec, 
			container, p_old_ent);
	}
	
	unsigned short bucket_offset = memrect_bucket_offset_of_addr(unindex_start, container->begin, p_chunk_rec->log_pitch);
	// 1. now any object that overlaps us must start later than us, walk up the buckets
	for (struct entry *p_search_bucket = p_bucket;
			// we might find an object overlapping that starts in this bucket if 
			// -- our bucket range base is not later than the end of our object, and
			// -- our bucket range end is not earlier than the 
			(char*) BUCKET_RANGE_BASE(p_search_bucket, p_chunk_rec, container->begin) < (char*) unindex_end; 
					//|| (char*) ptr >= BUCKET_RANGE_BASE(p_search_bucket, p_chunk_rec);
			
			++p_search_bucket)
	{
		for (struct entry *i_layer = p_search_bucket; 
				!ENTRY_IS_NULL(i_layer); 
				i_layer += ENTRIES_PER_LAYER(p_chunk_rec))
		{
			/* Does this object overlap our allocation? */
			char *this_object_start;
			char *this_object_end_thisbucket;
			struct entry *this_object_ent;
			
			/* We don't care about continuation entrys; we'll find the 
			 * start record before any relevant continuation record. */
			if (ENTRY_IS_CONTINUATION(i_layer))
			{
				// FIXME: assert that it doesn't overlap
				continue;
			}
			
			/* We have a start entry. Check for overlap. */
			this_object_start = (char*) BUCKET_RANGE_BASE(p_search_bucket, p_chunk_rec, container->begin) + ENTRY_GET_STORED_OFFSET(i_layer);
			this_object_end_thisbucket = this_object_start + ENTRY_GET_THISBUCKET_SIZE(i_layer);
			// if it overlaps us at all, it must overlap us in this bucket
			if (this_object_start < (char*) unindex_end 
					&& this_object_end_thisbucket > (char*) unindex_start)
			{
				unindex_small_alloc_internal_with_ent(this_object_start, p_chunk_rec, 
					container, i_layer);
				/* HACK: this deletes i_layer, so move it back one. */
				i_layer -= ENTRIES_PER_LAYER(p_chunk_rec);
			}
		}
	}
}

int __index_small_alloc(void *ptr, int level, unsigned size_bytes)
{
	int lock_ret;
	BIG_LOCK
			
	/* Find the deepest existing chunk (>= l1) and its level. 
	 * Assert that the same such chunk is covering both the beginning and end 
	 * of this alloc. */
	assert(size_bytes >= 1);
	
	/* Find the deepest bigalloc that spans this address *and* the end
	 * address, and *isn't* a generic_small allocation. FIXME: this is
	 * a bit unsound. */
	/* Find the allocator that liballocs thinks is the one containing "ptr". */
	struct big_allocation *b = NULL;
	struct allocator *a = __liballocs_leaf_allocator_for(ptr, &b);
	if (!a) abort();
	// if one of our allocations somehow got promoted to bigalloc, look at *its* container
	struct big_allocation *container = (b->allocated_by == &__generic_small_allocator) ?
		BIDX(b->parent) : b;
	if (!container) abort();
	if (a == &__generic_small_allocator)
	{
		/* We hit an allocation of our own, which we'd like to silently delete
		 * (this is a HACK to deal with GCs that don't notify us on free). */
		struct chunk_rec *chunk_rec = container->suballocator_private;
		// HACK: do the unindexing
		unindex_all_overlapping(ptr, (char*) ptr + size_bytes, chunk_rec, container);
	}
	else if (container->suballocator != &__generic_small_allocator)
	{
		/* 'Container' is a higher-up bigalloc; it's not a bigalloc that we are suballocating.
		 * This means we need to promote our immediately containing alloc.
		 * We need to get its info first. */
		void *containing_alloc_base;
		size_t sz = (size_t) -1;
		liballocs_err_t err = a->get_info(ptr, /* maybe_the_alloc? NO GAH GAH */ /*container*/ NULL,
			NULL, &containing_alloc_base, &sz, NULL);
		if (err && err != &__liballocs_err_unrecognised_alloc_site) abort();
		// HMM. We're asking generic_malloc to ensure its own arena base (bigalloc_base) is big.
		// That won't work. Our chunk *should* be a real malloc alloc and it's not.
		// But also we're reutrning the wrong bigalloc base.
		container = a->ensure_big(containing_alloc_base, sz);
		// we will set up the chunk below
	}
	/* Else we hit the parent allocation, and it's already a bigalloc. */

	/* Are we already registered as the suballocator of the parent?
	 * It's an error if another allocator is.
	 * If no the suballocator is null, we have to make a new chunk record 
	 * for ourselves, AND update the cache. */
	struct chunk_rec *p_chunk_rec;
	if (__builtin_expect(!container->suballocator, 0))
	{
		container->suballocator = &__generic_small_allocator;
		container->suballocator_private = make_suballocated_chunk(container->begin, 
				(char*) container->end - (char*) container->begin, 
				/* guessed_average_size */ size_bytes);
	}
	else if (container->suballocator != &__generic_small_allocator) abort();
	
	int ret = index_small_alloc_internal(ptr, size_bytes, container);
	
	BIG_UNLOCK
	return ret;
}

static _Bool
get_start_from_continuation(struct entry *p_ent, struct entry *p_bucket, 
		struct chunk_rec *p_chunk_rec, struct big_allocation *container,
		void **out_object_start, size_t *out_object_size, struct entry **out_object_ent)
{
	/* NOTE: don't sanity check buckets in this function, because we might be 
	 * called from inside check_bucket_sanity(). */
	
	// the object starts somewhere in the previous bucket
	// okay: hop back to the object start
	struct entry *p_object_start_bucket = p_bucket - 1;

	// walk the object start bucket looking for the *last* object i.e. biggest bucket offset
	struct entry *object_ent;
	struct entry *biggest_bucket_offset_pos = NULL;
	for (struct entry *i_layer = p_object_start_bucket;
			!ENTRY_IS_NULL(i_layer);
			i_layer += ENTRIES_PER_LAYER(p_chunk_rec))
	{
		if (ENTRY_IS_CONTINUATION(i_layer)) continue;
		// the offset tells us where this object starts in the bucket range
		unsigned short bucket_offset = p_object_start_bucket->common.bucket_offset;
		if (!biggest_bucket_offset_pos || 
				ENTRY_GET_STORED_OFFSET(i_layer) > ENTRY_GET_STORED_OFFSET(biggest_bucket_offset_pos))
		{
			biggest_bucket_offset_pos = i_layer;
		}
	}
	// we must have seen the last object
	assert(biggest_bucket_offset_pos);
	object_ent = biggest_bucket_offset_pos;
	char *object_start = (char*)(BUCKET_RANGE_BASE(p_object_start_bucket, p_chunk_rec, container->begin)) 
			+ ENTRY_GET_STORED_OFFSET(biggest_bucket_offset_pos);
	uintptr_t object_size = p_ent->continuation.size;

	if (out_object_start) *out_object_start = object_start;
	if (out_object_size) *out_object_size = object_size;
	if (out_object_ent) *out_object_ent = object_ent;
	
	return 1;
}

static 
void 
check_bucket_sanity(struct entry *p_bucket, struct chunk_rec *p_chunk_rec, struct big_allocation *container)
{
#ifndef NDEBUG
	unsigned layer_num = 0;
	for (struct entry *i_layer = p_bucket;
			!ENTRY_IS_NULL(i_layer);
			i_layer += ENTRIES_PER_LAYER(p_chunk_rec), ++layer_num)
	{
		// we should never need to go beyond the last layer
		assert(layer_num < NLAYERS(p_chunk_rec));

		if (ENTRY_IS_CONTINUATION(i_layer))
		{
			assert(i_layer->continuation.thisbucket_size != 0);
			/* Check that the *previous* bucket contains the object start */
			assert(get_start_from_continuation(i_layer, p_bucket, p_chunk_rec, container,
					NULL, NULL, NULL));
		} else {
			unsigned short bucket_offset = i_layer->common.bucket_offset;
			unsigned short thisbucket_size = i_layer->common.thisbucket_size;

			assert(bucket_offset < (1u << p_chunk_rec->log_pitch));

			/* Check we don't overlap with anything else in this bucket. */
			for (struct entry *i_earlier_layer = p_bucket;
				i_earlier_layer != i_layer;
				i_earlier_layer += ENTRIES_PER_LAYER(p_chunk_rec))
			{

				const unsigned our_end = bucket_offset + thisbucket_size;

				if(ENTRY_IS_CONTINUATION(i_earlier_layer))
				{
					assert(i_earlier_layer->continuation.thisbucket_size != 0);
				} else {
					const unsigned short thisbucket_earlier_size = i_earlier_layer->common.thisbucket_size;
					const unsigned short earlier_bucket_offset = i_earlier_layer->common.bucket_offset;
					const unsigned earlier_end = earlier_bucket_offset + thisbucket_earlier_size;

					// conventional overlap
					assert(!(earlier_end > bucket_offset && earlier_bucket_offset < our_end));
					assert(!(our_end > earlier_bucket_offset && bucket_offset < earlier_end));
				}				
			}
		}
		
	}

#endif
}
static void delete_suballocated_chunk(struct chunk_rec *p_rec)
{
#if 0
	/* Remove it from the bitmap. */
	unsigned long *p_bitmap_word = suballocated_chunks_bitmap
			 + (p_rec - &suballocated_chunks[0]) / UNSIGNED_LONG_NBITS;
	int bit_index = (p_rec - &suballocated_chunks[0]) % UNSIGNED_LONG_NBITS;
	*p_bitmap_word &= ~(1ul<<bit_index);

	/* munmap it. */
	int ret = munmap(p_rec->metadata_recs, (sizeof (struct entry)) * p_rec->size);
	assert(ret == 0);
	ret = munmap(p_rec->starts_bitmap,
		sizeof (unsigned long) * (p_rec->real_size / UNSIGNED_LONG_NBITS));
	assert(ret == 0);
	
	// bzero the chunk rec
	bzero(p_rec, sizeof (struct suballocated_chunk_rec));
			
	/* We might want to restore the previous alloc_site bits in the higher-level 
	 * chunk. But we assume that's been/being deleted, so we don't bother. */
#else 
	abort();
#endif
}

static
struct entry *lookup_small_alloc(const void *ptr,
		struct chunk_rec *p_chunk_rec,
		struct big_allocation *container,
		void **out_object_start,
		size_t *out_object_size)
{
	/* We've been given the containing (l1) chunk info. */

	/* How to do look-up? We walk the buckets, starting from the one that
	 * would index* an object starting at ptr. 
	 * If it has itself been sub-allocated, we recurse (FIXME), 
	 * and if that fails, stick with the result we have. */
	unsigned start_bucket_num = memrect_nbucket_of((void*) ptr, container->begin, p_chunk_rec->log_pitch);
	struct entry *p_start_bucket = &p_chunk_rec->metadata_recs[start_bucket_num];
	struct entry *p_bucket = p_start_bucket;
	_Bool must_see_continuation = 0; // a bit like seen_object_starting_earlier
	char *earliest_possible_start = (char*) ptr - p_chunk_rec->biggest_object;
	do 
	{
		/* walk this bucket looking for an object overlapping us */
		char *thisbucket_base_addr = BUCKET_RANGE_BASE(p_bucket, p_chunk_rec, container->begin);

		check_bucket_sanity(p_bucket, p_chunk_rec, container);
		
		unsigned layer_num = 0;
		for (struct entry *p_ent = p_bucket;
			!ENTRY_IS_NULL(p_ent);
			p_ent += ENTRIES_PER_LAYER(p_chunk_rec), ++layer_num)
		{
			// we should never need to go beyond the last layer
			assert(layer_num < NLAYERS(p_chunk_rec));
			/* We are walking the bucket. Possibilities: 
			 * 
			 * it's a continuation entry (may or may not overlap our ptr);
			 *
			 * it's an object start entry (ditto).
			 */

			if (ENTRY_IS_CONTINUATION(p_ent))
			{
				/* Does this continuation overlap our search address? */
			
				void *object_start;
				size_t object_size;
				struct entry *object_ent;
				_Bool success = get_start_from_continuation(p_ent, p_bucket,
						p_chunk_rec, container,
						&object_start, &object_size, &object_ent);
				
				if ((char*) object_start + object_size > (char*) ptr)
				{
					// hit! 
					if (out_object_start) *out_object_start = object_start;
					return object_ent;
				}
				// else it's a continuation that we don't overlap
				// -- we can give up 
				if (must_see_continuation) goto fail;
			}
			else 
			{
				/* It's an object start entry. Does it overlap? */
				unsigned bucket_offset = p_ent->common.bucket_offset;
				unsigned short object_size_in_this_bucket = p_ent->common.thisbucket_size;
				char *object_start_addr = thisbucket_base_addr + bucket_offset;
				void *object_end_addr = object_start_addr + object_size_in_this_bucket;

				if ((char*) object_start_addr <= (char*) ptr && (char*) object_end_addr > (char*) ptr)
				{
					// hit!
					if (out_object_start) *out_object_start = object_start_addr;
					if (out_object_size) *out_object_size = object_size_in_this_bucket;
					return p_ent;
				}
			}
		} // end for each layer
		
		must_see_continuation = 1;
		
	} while (--p_bucket >= &p_chunk_rec->metadata_recs[0]
			&& (char*) BUCKET_RANGE_END(p_bucket, p_chunk_rec, container->begin) > earliest_possible_start);
fail:
	// failed!
	return NULL;
}

static void remove_one_entry(struct entry *p_ent, struct entry *p_bucket, struct chunk_rec *p_chunk_rec)
{
	struct entry *replaced_ent = p_ent;
	do
	{
		struct entry *p_next_layer = replaced_ent + ENTRIES_PER_LAYER(p_chunk_rec);
		/* Copy the next layer's entry over ours. */
		*replaced_ent = *p_next_layer;
		/* Point us at the next layer to replace (i.e. if it's not null). */
		replaced_ent = p_next_layer;
	} while (!ENTRY_IS_NULL(replaced_ent));
}


static void unindex_small_alloc_internal(void *ptr, struct chunk_rec *p_chunk_rec, struct big_allocation *container)
{
	if (!p_chunk_rec) abort();

	void *alloc_start;
	size_t alloc_size;
	struct entry *p_ent = lookup_small_alloc(ptr, p_chunk_rec, container, &alloc_start, 
		&alloc_size);
	assert(p_ent);
	
	unindex_small_alloc_internal_with_ent(ptr, p_chunk_rec, container, p_ent);
}

static void unindex_small_alloc_internal_with_ent(void *ptr, struct chunk_rec *p_chunk_rec, struct big_allocation *container,
	struct entry *p_ent)
{
	struct entry *p_bucket = BUCKET_PTR_FROM_ENTRY_PTR(p_ent, p_chunk_rec, container);
	check_bucket_sanity(p_bucket, p_chunk_rec, container);
	
	unsigned short our_bucket_offset = ENTRY_GET_STORED_OFFSET(p_ent);
	_Bool we_are_biggest_offset = 1;
	for (struct entry *i_layer = p_bucket;
			we_are_biggest_offset && !ENTRY_IS_NULL(i_layer);
			i_layer += ENTRIES_PER_LAYER(p_chunk_rec))
	{
		we_are_biggest_offset &= (our_bucket_offset >= ENTRY_GET_STORED_OFFSET(i_layer));
	}
	
	/* Delete this entry and "shift left" any later in the bucket. */
	remove_one_entry(p_ent, p_bucket, p_chunk_rec);
	check_bucket_sanity(p_bucket, p_chunk_rec, container);
	
	/* If we were the biggest offset, delete any continuation entry in the next bucket. */
	if (we_are_biggest_offset)
	{
		for (struct entry *i_layer = p_bucket + 1;
				!ENTRY_IS_NULL(i_layer);
				i_layer += ENTRIES_PER_LAYER(p_chunk_rec))
		{
			if (ENTRY_IS_CONTINUATION(i_layer))
			{
				remove_one_entry(i_layer, p_bucket + 1, p_chunk_rec);
				check_bucket_sanity(p_bucket + 1, p_chunk_rec, container);
				break;
			}
		}
	}
	
	check_bucket_sanity(p_bucket, p_chunk_rec, container);
}

void __unindex_small_alloc(void *ptr) __attribute__((visibility("protected")));
void __unindex_small_alloc(void *ptr) 
{
	int lock_ret;
	BIG_LOCK
	
	void *existing_object_start;
	
	struct big_allocation *b = __lookup_deepest_bigalloc(ptr);
	while (b && b->suballocator != &__generic_small_allocator)
		b = BIDX(b->parent);
	if (!b) abort();
	
	unindex_small_alloc_internal(ptr, (struct chunk_rec *) b->suballocator_private, b);
	
	BIG_UNLOCK
}

static liballocs_err_t get_info(void *obj, struct big_allocation *b, 
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site)
{
	struct big_allocation *container =
		(b->allocated_by == &__generic_small_allocator)
		? BIDX(b->parent)
		 : __lookup_deepest_bigalloc(obj);
	
	struct entry *p_ent = lookup_small_alloc(obj, container->suballocator_private,
		container, out_base, out_size);
	if (!p_ent)
	{
		++__liballocs_aborted_unindexed_heap;
		return &__liballocs_err_unindexed_heap_object;
	}
	struct uniqtype *alloc_uniqtype = NULL;
	/* Now we have a uniqtype or an allocsite. For long-lived objects 
	 * the uniqtype will have been installed in the heap header already.
	 * This is the expected case. */
	assert(p_ent->common.discr != 0); // null entry -- we should not be passed these
	assert(p_ent->common.discr >= MINIMUM_USER_ADDRESS); // continuation entry -- ditto
	if (p_ent->common.discr < (1ull << (ADDR_BITSIZE - 1))) // 'regular initial' entry
	{
		void *alloc_site = (void*)(unsigned long) p_ent->regular_initial.alloc_site;
		if (out_site) *out_site = alloc_site;
		if (out_type)
		{
			struct allocsite_entry *entry = __liballocs_find_allocsite_entry_at(alloc_site);
			alloc_uniqtype = entry ? entry->uniqtype : NULL;
			/* Remember the unrecog'd alloc sites we see. */
			if (!alloc_uniqtype && alloc_site && 
					!__liballocs_addrlist_contains(&__liballocs_unrecognised_heap_alloc_sites, alloc_site))
			{
				__liballocs_addrlist_add(&__liballocs_unrecognised_heap_alloc_sites, alloc_site);
			}
			*out_type = alloc_uniqtype;
		}
	}
	else // 'regular with type' entry
	{
		assert(0); // currently we never progress to the with_type state
	}
	// FIXME: same optimizations as generic_malloc (use thewith_type state, and in
	// non-debug builds, zero out unrecognised alloc sites after the first failing lookup)

	// if we didn't get an alloc uniqtype, record the abort we abort
	if (out_type && !alloc_uniqtype) 
	{
		++__liballocs_aborted_unrecognised_allocsite;
		return &__liballocs_err_unrecognised_alloc_site;;
	}
	/* return success */
	return NULL;
}

struct allocator __generic_small_allocator = {
	.name = "generic small-object heap",
	.is_cacheable = 1,
	.get_info = get_info
};
