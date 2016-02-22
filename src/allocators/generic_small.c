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
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"

#if 0 

static
struct insert *lookup_deep_alloc(const void *ptr, int max_levels, 
		struct insert *start,
		void **out_object_start,
		size_t *out_object_size,
		struct suballocated_chunk_rec **out_containing_chunk);

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

static inline _Bool bitmap_get(unsigned long *p_bitmap, unsigned long index)
{
	return p_bitmap[index / UNSIGNED_LONG_NBITS] & (1ul << (index % UNSIGNED_LONG_NBITS));
}
static inline void bitmap_set(unsigned long *p_bitmap, unsigned long index)
{
	p_bitmap[index / UNSIGNED_LONG_NBITS] |= (1ul << (index % UNSIGNED_LONG_NBITS));
}
static inline void bitmap_clear(unsigned long *p_bitmap, unsigned long index)
{
	p_bitmap[index / UNSIGNED_LONG_NBITS] &= ~(1ul << (index % UNSIGNED_LONG_NBITS));
}
static inline unsigned long bitmap_find_first_set(unsigned long *p_bitmap, unsigned long *p_limit, unsigned long *out_test_bit)
{
	unsigned long *p_initial_bitmap;
			
	while (*p_bitmap == (unsigned long) 0
				&& p_bitmap < p_limit) ++p_bitmap;
	if (p_bitmap == p_limit) return (unsigned long) -1;
	
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	// while the test bit is unset...
	while (!(*p_bitmap & test_bit))
	{
		if (__builtin_expect(test_bit != 1ul<<(UNSIGNED_LONG_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap - p_initial_bitmap) * UNSIGNED_LONG_NBITS
			+ test_bit_index;
	
	if (out_test_bit) *out_test_bit = test_bit;
	return free_index;	
}
static inline unsigned long bitmap_find_first_clear(unsigned long *p_bitmap, unsigned long *p_limit, unsigned long *out_test_bit)
{
	unsigned long *p_initial_bitmap;
			
	while (*p_bitmap == (unsigned long) -1
				&& p_bitmap < p_limit) ++p_bitmap;
	if (p_bitmap == p_limit) return (unsigned long) -1;
	
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	while (*p_bitmap & test_bit)
	{
		if (__builtin_expect(test_bit != 1ul<<(UNSIGNED_LONG_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap - p_initial_bitmap) * UNSIGNED_LONG_NBITS
			+ test_bit_index;
	
	if (out_test_bit) *out_test_bit = test_bit;
	return free_index;
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
		.size = next_power_of_two_ge(chunk_size),
		.metadata_recs = NULL,
		.log_pitch = 0,
		.one_layer_nbytes = 0,
		.biggest_object = 0,
		.starts_bitmap = mmap(NULL, sizeof (unsigned long) * (chunk_size / UNSIGNED_LONG_NBITS),
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
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
	
	/* Update the old insert with our info. We have to remove it from the 
	 * cache if it's there.  */
	check_cache_sanity();
	chunk_existing_ins->alloc_site = free_index;
	chunk_existing_ins->alloc_site_flag = 0;
	cache_clear_deepest_flag_and_update_ins(
		chunk_base, (1u<<0)|(1u<<1), NULL, chunk_existing_ins, 1,
		&p_rec->higherlevel_ins);
	// NO! WE DON'T do this because we need to leave the l1 linked list intact! 
	// chunk_existing_ins->un.bits = 0;
	check_cache_sanity();
	
	return p_rec;
}

static void unindex_deep_alloc_internal(void *ptr, struct insert *existing_ins, 
		struct suballocated_chunk_rec *p_rec);


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

int __index_deep_alloc(void *ptr, int level, unsigned size_bytes) __attribute__((visibility("protected")));
int __index_deep_alloc(void *ptr, int level, unsigned size_bytes) 
{
	int lock_ret;
	BIG_LOCK
			
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) do_init();
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
	}
	else
	{
		/* This chunk already records a suballocated region. */
		p_rec = &suballocated_chunks[(uintptr_t) found_ins->alloc_site];
	}
#ifdef HEAP_INDEX_DEEP_BITMAP_ONLY
	/* Just maintain the bitmap. Set the first bit and clear up to the size of the object. */
	bitmap_set(p_rec->starts_bitmap, (char*) ptr - (char*) existing_object_start);
// 	/* We clear in three phases.
// 	 * 1. bytes from start + 1 */
// 	unsigned nbyte = 1;
// 	while (nbyte < size_bytes && nbyte < 8) 
// 	{
// 		bitmap_clear(p_rec->starts_bitmap, 
// 			((char*) ptr - (char*) existing_object_start) + nbyte);
// 		nbyte++;
// 	}
// 	/* 2. bytes from 8 to ROUND_DOWN(size, 8) */
// 	while (nbyte < size_bytes && nbyte < 8 * (size_bytes / 8))
// 	{
// 		p_rec->starts_bitmap[((char*) ptr - (char*) existing_object_start) / UNSIGNED_LONG_NBITS] = 0;
// 		nbyte += UNSIGNED_LONG_NBITS;
// 	}
// 	/* 3. remaining bytes at the end */
// 	while (nbyte < size_bytes)
// 	{
// 		bitmap_clear(p_rec->starts_bitmap, 
// 			((char*) ptr - (char*) existing_object_start) + nbyte);
// 		nbyte++;
// 	}
#else
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
				!INSERT_IS_TERMINATOR(i_layer); 
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
	while (!INSERT_IS_TERMINATOR(p_ins))
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
		check_bucket_sanity(p_continuation_bucket, p_rec);
		struct insert *p_continuation_ins = p_continuation_bucket;
		/* Find a free slot */
		unsigned layer_num = 0;
		while (!INSERT_IS_TERMINATOR(p_continuation_ins))
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

		// install the continuation record
		assert(size_bytes > 0);
		assert(size_bytes < (uintptr_t) MINIMUM_USER_ADDRESS);
		*p_continuation_ins = (struct insert) {
			.alloc_site = size_bytes, // NOTE what we're doing here! the object size goes into the alloc_site field
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
	
#endif
	check_cache_sanity();
	
	BIG_UNLOCK
	
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
			!INSERT_IS_TERMINATOR(i_layer);
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
			!INSERT_IS_TERMINATOR(i_layer);
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
	if (!index_region) do_init();
	if (!suballocated_chunks) init_suballocs();
	
	assert(max_levels == 1);// i.e. we go down to l2 only
	assert(start);
	assert(INSERT_IS_SUBALLOC_CHAIN(start));
	
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
			!INSERT_IS_TERMINATOR(p_ins);
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
					if (out_object_size) *out_object_size = object_size_in_this_bucket;
					if (out_containing_chunk) *out_containing_chunk = p_rec;
					return p_ins;
				}
			}
		} // end for each layer
		
		must_see_continuation = 1;
		
	} while (--p_bucket >= &p_rec->metadata_recs[0]
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
	} while (!INSERT_IS_TERMINATOR(replaced_ins));
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
			we_are_biggest_modulus && !INSERT_IS_TERMINATOR(i_layer);
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
				!INSERT_IS_TERMINATOR(i_layer);
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

void __unindex_deep_alloc(void *ptr, int level) __attribute__((visibility("protected")));
void __unindex_deep_alloc(void *ptr, int level) 
{
	int lock_ret;
	BIG_LOCK
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) do_init();
	if (!suballocated_chunks) init_suballocs();
	
	/* Support cases where level>2. */
	assert(level == 2);
	
	void *existing_object_start;
	struct suballocated_chunk_rec *p_rec = NULL;
	struct insert *found_ins = lookup_object_info(ptr, &existing_object_start, NULL, &p_rec);
	assert(found_ins);
	assert(p_rec); 
	
	unindex_deep_alloc_internal(ptr, found_ins, p_rec);
	
	BIG_UNLOCK
}

#endif /* 0 */

struct allocator __generic_small_allocator = {
	.name = "generic small-object heap",
	.is_cacheable = 1
};
