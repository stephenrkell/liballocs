#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <string.h>
#include <wchar.h>
#include "liballocs_private.h"

#ifndef NO_PTHREADS
#include <pthread.h>
#define BIG_LOCK \
	lock_ret = pthread_mutex_lock(&mutex); \
	assert(lock_ret == 0);
#define BIG_UNLOCK \
	lock_ret = pthread_mutex_unlock(&mutex); \
	assert(lock_ret == 0);
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

#else
#define BIG_LOCK
#define BIG_UNLOCK
#endif

/* How many big allocs? 256 is a bit stingy. 
 * Each bigalloc record is 48--64 bytes, so 4096 of them would take 256KB.
 * Maybe stick to 1024? */
#define NBIGALLOCS 1024
struct big_allocation big_allocations[NBIGALLOCS]; // NOTE: we *don't* use big_allocations[0]; the 0 byte means "empty"

// FIXME: support 
#define SANITY_CHECK_BIGALLOC(b) \
	do { \
		if (BIGALLOC_IN_USE((b))) { \
			for (unsigned long i = PAGENUM((b)->begin); i < PAGENUM((b)->end); ++i) { \
				assert(pageindex[i] == ((b) - &big_allocations[0])); \
			} \
			assert(pageindex[PAGENUM((b)->begin)-1] != ((b) - &big_allocations[0])); \
			assert(pageindex[PAGENUM((b)->end)] != ((b) - &big_allocations[0])); \
		} \
	} while (0)
	
bigalloc_num_t *pageindex __attribute__((visibility("hidden")));

static void memset_bigalloc(bigalloc_num_t *begin, bigalloc_num_t num, size_t n)
{
	assert(1ull<<(8*sizeof(bigalloc_num_t)) >= NBIGALLOCS - 1);
	assert(sizeof (wchar_t) == 2 * sizeof (bigalloc_num_t));

	/* We use wmemset with special cases at the beginning and end */
	if (n > 0 && (uintptr_t) begin % sizeof (wchar_t) != 0)
	{
		*begin++ = num;
		--n;
	}
	assert(n == 0 || (uintptr_t) begin % sizeof (wchar_t) == 0);
	
	// double up the value
	wchar_t wchar_val = ((wchar_t) num) << (8 * sizeof(bigalloc_num_t)) | num;
	
	// do the memset
	if (n != 0) wmemset((wchar_t *) begin, wchar_val, n / 2);
	
	// if we missed one off the end, do it now
	if (n % 2 == 1)
	{
		*(begin + (n-1)) = num;
	}
}

static void (__attribute__((constructor)) init)(void)
{
	if (!pageindex)
	{
		/* Mmap our region. We map one 16-bit number for every page in the user address region. */
		pageindex = MEMTABLE_NEW_WITH_TYPE(bigalloc_num_t, PAGE_SIZE, (void*) 0, (void*) STACK_BEGIN);
		if (pageindex == MAP_FAILED) abort();
	}
}

_Bool __attribute__((visibility("hidden"))) 
insert_equal(struct insert *p_ins1, struct insert *p_ins2)
{
	return p_ins1->alloc_site_flag == p_ins2->alloc_site_flag &&
		p_ins1->alloc_site == p_ins2->alloc_site;
		// don't compare prev/next, at least not for now
}
_Bool __attribute__((visibility("hidden"))) 
bigalloc_meta_info_equal(struct mapping_flags f1, struct meta_info *meta1, struct mapping_flags f2, struct meta_info *meta2)
{
	return 
	mapping_flags_equal(f1, f2) && 
	meta1->what == meta2->what && 
	(meta1->what == DATA_PTR ? bigalloc_data_ptr_equal(f1, meta1, meta2->un.data_ptr)
	            : (assert(meta1->what == INS_AND_BITS), 
					(insert_equal(&meta1->un.ins_and_bits.ins, &meta2->un.ins_and_bits.ins)
						&& meta1->un.ins_and_bits.npages == meta2->un.ins_and_bits.npages
						&& meta1->un.ins_and_bits.obj_offset == meta2->un.ins_and_bits.obj_offset)
					)
	);
}
_Bool  __attribute__((visibility("hidden"))) 
bigalloc_data_ptr_equal(struct mapping_flags f, struct meta_info *meta1, const char *data_ptr2)
{
	return meta1->what == DATA_PTR
			&& (
					// -- it should be value-equal for stack and string-equal for static/mapped
							(f.kind == STACK && meta1->un.data_ptr == data_ptr2)
							|| 
						((meta1->un.data_ptr == NULL && data_ptr2 == NULL)
							|| (meta1->un.data_ptr != NULL && data_ptr2 != NULL && 
							0 == strcmp(meta1->un.data_ptr, data_ptr2))));
}

_Bool __attribute__((visibility("hidden"))) mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2)
{
	return f1.kind == f2.kind
			&& f1.r == f2.r
			&& f1.w == f2.w
			&& f1.x == f2.x;
}

static struct big_allocation *find_free_bigalloc(void)
{
	for (struct big_allocation *p = &big_allocations[1]; p < &big_allocations[NBIGALLOCS]; ++p)
	{
		SANITY_CHECK_BIGALLOC(p);
		
		if (!BIGALLOC_IN_USE(p))
		{
			return p;
		}
	}
	abort();
}

static _Bool
is_unindexed(void *begin, void *end)
{
	bigalloc_num_t *pos = &pageindex[PAGENUM(begin)];
	while (pos < pageindex + PAGENUM(end) && !*pos) { ++pos; }
	
	if (pos == pageindex + PAGENUM(end)) return 1;
	
	debug_printf(6, "Found already-indexed position %p (mapping %d)\n", 
			ADDR_OF_PAGENUM(pos - pageindex), *pos);
	return 0;
}

static _Bool
is_unindexed_or_heap(void *begin, void *end)
{
	bigalloc_num_t *pos = &pageindex[PAGENUM(begin)];
	while (pos < pageindex + PAGENUM(end) && (!*pos || big_allocations[*pos].f.kind == HEAP)) { ++pos; }
	
	if (pos == pageindex + PAGENUM(end)) return 1;
	
	debug_printf(6, "Found already-indexed non-heap position %p (bigalloc %d)\n", 
			ADDR_OF_PAGENUM(pos - pageindex), *pos);
	return 0;
}

static _Bool range_overlaps_bigalloc(struct big_allocation *b, void *base, size_t s)
{
	return (char*) base < (char*) b->end && (char*) base + s > (char*) b->begin;
}

#define SANITY_CHECK_NEW_BIGALLOC(base, s) \
	/* We have to tolerate overlaps in the case of anonymous mappings, because */ \
	/* they come and go without our direct oversight. */ \
	do { \
		for (unsigned i = 1; i < NBIGALLOCS; ++i) { \
			assert(big_allocations[i].f.kind == HEAP || \
				!range_overlaps_bigalloc(&big_allocations[i], (base), (s))); \
		} \
	} while (0)
#define STRICT_SANITY_CHECK_NEW_BIGALLOC(base, s) \
	/* Don't tolerate overlaps! */ \
	do { \
		for (unsigned i = 1; i < NBIGALLOCS; ++i) { \
			assert(!range_overlaps_bigalloc(&big_allocations[i], (base), (s))); \
		} \
	} while (0)

#define MAXPTR(a, b) \
	((((char*)(a)) > ((char*)(b))) ? (a) : (b))

#define MINPTR(a, b) \
	((((char*)(a)) < ((char*)(b))) ? (a) : (b))

static void check_page_size(void) __attribute__((constructor));
static void check_page_size(void)
{
	if (PAGE_SIZE != sysconf(_SC_PAGE_SIZE)) abort();
}

static
struct big_allocation *create_or_extend_bigalloc_l0(void *base, size_t s, mapping_flags_t f, struct meta_info meta)
{
	assert((uintptr_t) base % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	assert(s % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening	
	
	debug_printf(6, "%s: creating bigalloc base %p, size %lu, kind %u\n", 
		__func__, base, (unsigned long) s, f.kind);
	
	/* In the case of heap regions, libc can munmap them without our seeing it. 
	 * So, we might be surprised to find that our index is out-of-date here. 
	 * We force a deletion if so. NOTE that we have to repeat the procedure
	 * until we've found all overlapping mappings. The best way to do this
	 * is to linear search all mappings, and short-circuit once we've unmapped
	 * the whole amount.
	 * 
	 * Instead of iterating over all 1024 bigallocs, can we use the pageindex to help us?
	 * 
	 * Not directly, because two bytes per page might still be a lot of memory to
	 * walk over. Suppose we're a 4GB bigalloc. That's 1M pages, each a 2-byte entry.
	 * We don't want to walk over 2MB of memory.
	 
	 * But we could keep a bitmap of the pageindex 
	 * memtable, possibly over multiple levels (2^47 bits would be 512GB, so a lot
	 * of memory to walk over; 512GB in page-sized chunks can be bitmapped in 2^27
	 * bits, so 16MB... so two levels should suffice). Then walking a 4GB bigalloc
	 * which is currently unused (pageindex all zero) would require us to walk 4M bits
	 * in the bottom bitmap, i.e. 512KB, which would be covered by only 128 bits in
	 * the top-level bitmap, i.e. two words. That's nice! Note that the two-word
	 * comparison only suffices if the memory has been untouched up to this point;
	 * if it has been touched, we have to scan the bottom-level bitmap. But we only
	 * scan 512KB of bitmap in the maximal case of a 4GB bigalloc. For small bigallocs
	 * it's still tiny.
	 * */
	unsigned long bytes_unmapped = 0;
	for (int i_big = 1; i_big < NBIGALLOCS && bytes_unmapped < s; ++i_big)
	{
		if ((char*) big_allocations[i_big].begin < (char*) base + s
				&& (char*) big_allocations[i_big].end > (char*) base)
		{
			/* We have overlap. Unmap the whole thing? Or just the portion we overlap? 
			 * Since heap regions can shrink as well as grow, it seems safest to unmap
			 * only the overlapping portion. */
			if (big_allocations[i_big].f.kind == HEAP)
			{
				// force an unmapping of the overlapping region
				char *overlap_begin = MAXPTR((char*) big_allocations[i_big].begin, (char*) base);
				char *overlap_end = MINPTR((char*) big_allocations[i_big].end, (char*) base + s);
				
				debug_printf(6, "%s: forcing unmapping of %p-%p (from bigalloc number %d), overlapping %p-%p\n", 
					__func__, overlap_begin, overlap_end, i_big,  base, (char*) base + s);
				bigalloc_del_l0(overlap_begin, overlap_end - overlap_begin);
				bytes_unmapped += overlap_end - overlap_begin;
			}
			else
			{
				/* We found an overlapping mapping that's NOT a heap one.
				 * 
				 * It's possible that the mapping we're adding already exists, e.g. if we're
				 * called during re-dlopening a dlopen'd library. To allow for subsequent
				 * coalescings, we have to test for containment and not an exact match.
				 * If we find it, we're okay. */
				if (big_allocations[i_big].begin <= base
							&& (char*) big_allocations[i_big].end >= (char*) base + s
							&& mapping_flags_equal(big_allocations[i_big].f, f)
							&& bigalloc_meta_info_equal(big_allocations[i_big].f, 
								&big_allocations[i_big].meta, 
								f, &meta))
				{
					debug_printf(6, "%s: bigalloc already present\n", __func__);
					// if we're STATIC and have a data ptr, we borrow the new data_ptr 
					// because it's more likely to be up-to-date
					if (f.kind == STATIC && meta.what == DATA_PTR)
					{
						big_allocations[i_big].meta.un.data_ptr = meta.un.data_ptr;
					}
					return &big_allocations[i_big];
				}
				else if (big_allocations[i_big].f.kind == STACK && f.kind == STACK
					/* for stack, upper bound must be unchanged */
					&& big_allocations[i_big].end == (char*) base + s)
				{
					_Bool contracting __attribute__((unused)) = base > big_allocations[i_big].begin;
					/* assert that we're not contracting -- we're expanding! */
					assert(!contracting);

//					if (contracting)
//					{
//						// simply update the lower bound, do the memset, sanity check and exit
//						void *old_begin = b->begin;
//						b->begin = base;
//						assert(b->end == (char*) base + s);
//						memset_bigalloc(pageindex + PAGENUM(old_begin), 0, 
//									((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
//						SANITY_CHECK_MAPPING(b);
//						return b;
//					}
//					else // expanding or zero-growth
//					{
						// simply update the lower bound, do the memset, sanity check and exit
						void *old_begin = big_allocations[i_big].begin;
						big_allocations[i_big].begin = base;
						assert(big_allocations[i_big].end == (char*) base + s);
						if (old_begin != base)
						{
							memset_bigalloc(pageindex + PAGENUM(base), i_big, 
										((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
						}
						SANITY_CHECK_BIGALLOC(&big_allocations[i_big]);
						return &big_allocations[i_big];
//					}
				}
				/* We overlap, it's not heap, and the containment check failed. 
				 * Something weird is going on. */
				assert(0);
			}
		} // end if overlaps
		// else no overlap; continue
	}
	
	/* If we got here, we've unmapped anything overlapping us. */
	bigalloc_num_t bigalloc_num = pageindex[PAGENUM(base)];
	//SANITY_CHECK_BIGALLOC(&mappings[bigalloc_num]);
	assert(bigalloc_num == 0);
	
	// test for nearby mappings to extend
	bigalloc_num_t abuts_existing_start = pageindex[PAGENUM((char*) base + s)];
	bigalloc_num_t abuts_existing_end = pageindex[PAGENUM((char*) base - 1)];
	
	// FIXME: the following ovelrap logic appears to be dead code... delete it?
	
	/* Tolerate overlapping either of these two, if we're mapping heap (anonymous). 
	 * We simply adjust our base and size so that we fit exactly. 
	 */
	if (f.kind == HEAP)
	{
		SANITY_CHECK_NEW_BIGALLOC(base, s);
		// adjust w.r.t. abutments
		if (abuts_existing_start 
			&& range_overlaps_bigalloc(&big_allocations[abuts_existing_start], base, s)
			&& big_allocations[abuts_existing_start].f.kind == HEAP)
		{
			s = (char*) big_allocations[abuts_existing_start].begin - (char*) base;
		}
		if (abuts_existing_end
			&& range_overlaps_bigalloc(&big_allocations[abuts_existing_end], base, s)
			&& big_allocations[abuts_existing_start].f.kind == HEAP)
		{
			base = big_allocations[abuts_existing_end].end;
		}
		
		// also adjust w.r.t. overlaps
		bigalloc_num_t our_end_overlaps = pageindex[PAGENUM((char*) base + s) - 1];
		bigalloc_num_t our_begin_overlaps = pageindex[PAGENUM((char*) base)];

		if (our_end_overlaps
			&& range_overlaps_bigalloc(&big_allocations[our_end_overlaps], base, s)
			&& big_allocations[our_end_overlaps].f.kind == HEAP)
		{
			// move our end earlier, but not to earlier than base
			void *cur_end __attribute__((unused)) = (char *) base + s;
			void *new_end = MAXPTR(base, big_allocations[our_end_overlaps].begin);
			s = (char*) new_end - (char*) base;
		}
		if (our_begin_overlaps
			&& range_overlaps_bigalloc(&big_allocations[our_begin_overlaps], base, s)
			&& big_allocations[our_begin_overlaps].f.kind == HEAP)
		{
			// move our begin later, but not to later than base + s
			void *new_begin = MINPTR(big_allocations[our_begin_overlaps].begin, (char*) base + s); 
			ptrdiff_t length_reduction = (char*) new_begin - (char*) base;
			assert(length_reduction >= 0);
			base = new_begin;
			s -= length_reduction;
		}		
		
		STRICT_SANITY_CHECK_NEW_BIGALLOC(base, s);
	}
	else if (f.kind == STACK)
	{
		/* Tolerate sharing an upper boundary with an existing bigalloc. */
		bigalloc_num_t our_end_overlaps = pageindex[PAGENUM((char*) base + s) - 1];
		
		if (our_end_overlaps)
		{
			_Bool contracting = base > big_allocations[our_end_overlaps].begin;
			struct big_allocation *m = &big_allocations[our_end_overlaps];
			
			if (contracting)
			{
				// simply update the lower bound, do the memset, sanity check and exit
				void *old_begin = m->begin;
				m->begin = base;
				assert(m->end == (char*) base + s);
				memset_bigalloc(pageindex + PAGENUM(old_begin), 0, 
							((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
				SANITY_CHECK_BIGALLOC(m);
				return m;
			}
			else // expanding or zero-growth
			{
				// simply update the lower bound, do the memset, sanity check and exit
				void *old_begin = m->begin;
				m->begin = base;
				assert(m->end == (char*) base + s);
				if (old_begin != base)
				{
					memset_bigalloc(pageindex + PAGENUM(base), our_end_overlaps, 
								((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
				}
				SANITY_CHECK_BIGALLOC(m);
				return m;
			}
		}
		
		// neither expanding nor contracting, so we look for strictly correct
		STRICT_SANITY_CHECK_NEW_BIGALLOC(base, s);
	}
	assert(is_unindexed_or_heap(base, (char*) base + s));
	
	debug_printf(6, "bigalloc rec is at %p (%d)\n", &big_allocations[bigalloc_num], (int) bigalloc_num);
	
	debug_printf(6, "%s: abuts_existing_start: %d, abuts_existing_end: %d\n",
			__func__, abuts_existing_start, abuts_existing_end);

	_Bool flags_matches = 1;
	_Bool node_matches = 1;
	
	_Bool can_coalesce_after = abuts_existing_start
				&& (flags_matches = (mapping_flags_equal(big_allocations[abuts_existing_start].f, f)))
				&& (node_matches = (bigalloc_meta_info_equal(big_allocations[abuts_existing_start].f, &big_allocations[abuts_existing_start].meta, f, &meta)));
	_Bool can_coalesce_before = abuts_existing_end
				&& (flags_matches = (mapping_flags_equal(big_allocations[abuts_existing_end].f, f)))
				&& (node_matches = (bigalloc_meta_info_equal(big_allocations[abuts_existing_end].f, &big_allocations[abuts_existing_end].meta, f, &meta)));
	debug_printf(6, "%s: can_coalesce_after: %s, can_coalesce_before: %s, "
			"flags_matches: %s, node_matches: %s \n",
			__func__, can_coalesce_after ? "true" : "false", can_coalesce_before ? "true" : "false", 
			flags_matches ? "true": "false", node_matches ? "true": "false" );
	
	/* If we *both* abut a start and an end, we're coalescing 
	 * three bigallocs. If so, just bump up our base and s, 
	 * free the spare bigalloc and coalesce before. */
	if (__builtin_expect(can_coalesce_before && can_coalesce_after, 0))
	{
		s += (char*) big_allocations[abuts_existing_start].end - (char*) big_allocations[abuts_existing_start].begin;
		big_allocations[abuts_existing_start].begin = 
			big_allocations[abuts_existing_start].end =
				NULL;
		debug_printf(6, "%s: bumped up size to join two bigallocs\n", __func__);
		can_coalesce_after = 0;
	}
	
	if (can_coalesce_before)
	{
		debug_printf(6, "%s: post-extending existing bigalloc ending at %p\n", __func__,
				big_allocations[abuts_existing_end].end);
		memset_bigalloc(pageindex + PAGENUM(big_allocations[abuts_existing_end].end), abuts_existing_end, 
			s >> LOG_PAGE_SIZE);
		big_allocations[abuts_existing_end].end = (char*) base + s;
		SANITY_CHECK_BIGALLOC(&big_allocations[abuts_existing_end]);
		return &big_allocations[abuts_existing_end];
	}
	if (can_coalesce_after)
	{
		debug_printf(6, "%s: pre-extending existing bigalloc at %p-%p\n", __func__,
				big_allocations[abuts_existing_start].begin, big_allocations[abuts_existing_start].end);
		big_allocations[abuts_existing_start].begin = (char*) base;
		memset_bigalloc(pageindex + PAGENUM(base), abuts_existing_start, s >> LOG_PAGE_SIZE);
		SANITY_CHECK_BIGALLOC(&big_allocations[abuts_existing_start]);
		return &big_allocations[abuts_existing_start];
	}
	
	debug_printf(6, "%s: forced to assign new bigalloc\n", __func__);
	
	// else create new
	struct big_allocation *found = find_free_bigalloc();
	if (found)
	{
		*found = (struct big_allocation) {
			.begin = base,
			.end = (char*) base + s,
			.f = f,
			.meta = meta
		};
		memset_bigalloc(pageindex + PAGENUM(base), (bigalloc_num_t) (found - &big_allocations[0]), s >> LOG_PAGE_SIZE);
		SANITY_CHECK_BIGALLOC(found);
		return found;
	}
	
	return NULL;
}

static _Bool path_is_realpath(const char *path)
{
	const char *rp = realpath_quick(path);
	return 0 == strcmp(path, rp);
}

struct big_allocation *bigalloc_add_l0(void *base, size_t s, mapping_flags_t f, const void *data_ptr)
{
	if (!pageindex) init();
	
	assert(!data_ptr || f.kind == STACK || path_is_realpath((const char *) data_ptr));
	
	struct meta_info info = { .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	return bigalloc_add_l0_full(base, s, f, info);
}

void bigalloc_add_l0_sloppy(void *base, size_t s, mapping_flags_t f, const void *data_ptr)
{
	int lock_ret;
	BIG_LOCK
			
	if (!pageindex) init();

	/* What's the biggest mapping you can think of? 
	 * 
	 * We don't want to index our memtables. I'm going to be conservative
	 * and avoid indexing anything above 4GB. */
	if (__builtin_expect(s >= BIGGEST_BIGALLOC, 0))
	{
		debug_printf(3, "Warning: not indexing huge mapping (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return;
	}
	if (__builtin_expect((uintptr_t) base + s > STACK_BEGIN, 0))
	{
		debug_printf(3, "Warning: not indexing high-in-VAS mapping (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return;
	}
	
	struct meta_info info = { .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	
	/* Just add the as-yet-unmapped bits of the range. */
	uintptr_t begin_pagenum = PAGENUM(base);
	uintptr_t current_pagenum = begin_pagenum;
	uintptr_t end_pagenum = PAGENUM((char*) base + s);
	while (current_pagenum < end_pagenum)
	{
		uintptr_t next_indexed_pagenum = current_pagenum;
		while (next_indexed_pagenum < end_pagenum && !pageindex[next_indexed_pagenum])
		{ ++next_indexed_pagenum; }
		
		if (next_indexed_pagenum > current_pagenum)
		{
			bigalloc_add_l0_full((void*) ADDR_OF_PAGENUM(current_pagenum), 
				(char*) ADDR_OF_PAGENUM(next_indexed_pagenum)
					 - (char*) ADDR_OF_PAGENUM(current_pagenum), 
				f, info);
		}
		
		current_pagenum = next_indexed_pagenum;
		// skip over any indexed bits so we're pointing at the next unindexed bit
		while (pageindex[current_pagenum] && ++current_pagenum < end_pagenum);
	}
	
	BIG_UNLOCK
}

struct big_allocation *bigalloc_add_l0_full(void *base, size_t s, struct mapping_flags f, struct meta_info meta)
{
	int lock_ret;
	BIG_LOCK
	
	if (!pageindex) init();

	assert((uintptr_t) base % PAGE_SIZE == 0);
	assert(s % PAGE_SIZE == 0);
	
	/* What's the biggest bigalloc you can think of? 
	 * 
	 * We don't want to index our memtables. I'm going to be conservative
	 * and avoid indexing anything above 4GB. */
	if (s >= BIGGEST_BIGALLOC)
	{
		debug_printf(3, "Warning: not indexing huge bigalloc (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return NULL;
	}
	if (__builtin_expect((uintptr_t) base + s > STACK_BEGIN, 0))
	{
		debug_printf(3, "Warning: not indexing high-in-VAS bigalloc (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return NULL;
	}
	
	uintptr_t first_page_num = (uintptr_t) base >> LOG_PAGE_SIZE;
	uintptr_t npages = s >> LOG_PAGE_SIZE;

	struct big_allocation *b = create_or_extend_bigalloc_l0(base, s, f, meta);
	SANITY_CHECK_BIGALLOC(b);

	BIG_UNLOCK
	return b;
}

static struct big_allocation *split_bigalloc(struct big_allocation *b, void *split_addr)
{
	assert(b);
	assert((char*) split_addr > (char*) b->begin);
	assert((char*) split_addr < (char*) b->end);
	
	// make a new entry for the remaining-after part, then just chop before
	struct big_allocation *new_b = find_free_bigalloc();
	assert(new_b);
	*new_b = (struct big_allocation) {
		.begin = split_addr,
		.end = b->end,
		.f = b->f,
		.meta = b->meta
	};
	assert((char*) new_b->end > (char*) new_b->begin);

	// rewrite uses of the old mapping number in the new-mapping portion of the memtable
	bigalloc_num_t new_bigalloc_num = new_b - &big_allocations[0];
	unsigned long npages
	 = ((char*) new_b->end - ((char*) new_b->begin)) >> LOG_PAGE_SIZE;
	memset_bigalloc(pageindex + PAGENUM((char*) new_b->begin), new_bigalloc_num, npages);

	// delete (from m) the part now covered by new_m
	b->end = new_b->begin;
	
	SANITY_CHECK_BIGALLOC(b);
	SANITY_CHECK_BIGALLOC(new_b);
	
	return new_b;
}

void bigalloc_del(struct big_allocation *b) __attribute__((visibility("hidden")));
void bigalloc_del(struct big_allocation *b)
{
	// FIXME: Support non-l0
	int lock_ret;
	BIG_LOCK

	// check sanity
	assert(pageindex[PAGENUM(b->begin)] == b - &big_allocations[0]);
	
	bigalloc_del_l0(b->begin, (char*) b->end - (char*) b->begin);
	
	BIG_UNLOCK
}

static void clear_bigalloc(struct big_allocation *b)
{
	b->begin = b->end = NULL;
	memset(&b->meta, 0, sizeof b->meta);
}

void bigalloc_del_l0(void *base, size_t s) __attribute__((visibility("hidden")));
void bigalloc_del_l0(void *base, size_t s)
{
	int lock_ret;
	BIG_LOCK
			
	if (!pageindex) init();
	
	assert(s % PAGE_SIZE == 0);
	assert((uintptr_t) base % PAGE_SIZE == 0);

	if (s >= BIGGEST_BIGALLOC)
	{
		debug_printf(3, "Warning: not unindexing huge bigalloc (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return;
	}
	
	unsigned long cur_pagenum = PAGENUM(base); 
	unsigned long end_pagenum = PAGENUM((char*)base + s);
	bigalloc_num_t bigalloc_num;
	// if we get bigalloc num 0 at first, try again after forcing __liballocs_init_l0()
	/* We might span multiple bigallocs, because munmap() is like that. */
	bigalloc_num = pageindex[PAGENUM(base)];
	if (bigalloc_num == 0)
	{
		__liballocs_init_pageindex();
		bigalloc_num = pageindex[PAGENUM(base)];
		/* Give up if we still can't get it. */
		if (bigalloc_num == 0) return;
	}

	do
	{
		// if we see some zero bigalloc nums, skip forward
		unsigned long initial_cur_pagenum = cur_pagenum;
		if (__builtin_expect(cur_pagenum < end_pagenum && pageindex[cur_pagenum] == 0, 0))
		{
			while (cur_pagenum < end_pagenum)
			{
				if (pageindex[cur_pagenum]) break;
				++cur_pagenum;
			}
			if (cur_pagenum == end_pagenum) break;
			debug_printf(3, "Warning: l0-unindexing a partially unmapped region %p-%p\n",
				ADDR_OF_PAGENUM(initial_cur_pagenum), ADDR_OF_PAGENUM(cur_pagenum));
		}
		bigalloc_num = pageindex[cur_pagenum];
		/* If bigalloc num is 0 when we get here, it means there's no bigalloc here. 
		 * This might happen because users are allowed to call munmap() on unmapped
		 * regions. */
		assert(bigalloc_num != 0);
		struct big_allocation *b = &big_allocations[bigalloc_num];
		SANITY_CHECK_BIGALLOC(b);
		size_t this_bigalloc_size = (char*) b->end - (char*) b->begin;
		
		/* Do we need to chop an entry? */
		_Bool remaining_before = b->begin < base;
		_Bool remaining_after
		 = (char*) b->end > (char*) base + s;

		void *next_addr = NULL;
		/* If we're chopping before and after, we need to grab a *new* 
		 * mapping number. This can happen if we munmap part of an
		 * anonymous region. We should *not* have any suballocations
		 * in the unmapped region. */
		if (__builtin_expect(remaining_before && remaining_after, 0))
		{
			struct big_allocation *new_b = split_bigalloc(b, (char*) base + s);

			// we might still need to chop before, but not after
			remaining_after = 0;

			assert((uintptr_t) new_b->begin % PAGE_SIZE == 0);
			assert((uintptr_t) new_b->end % PAGE_SIZE == 0);
		}

		if (__builtin_expect(remaining_before, 0))
		{
			// means the to-be-unmapped range starts *after* the start of the current mapping
			char *this_unmapping_begin = (char*) base;
			assert((char*) b->end <= ((char*) base + s)); // we should have dealt with the other case above
			char *this_unmapping_end = //((char*) m->end > ((char*) base + s))
					//? ((char*) base + s)
					/*:*/ b->end;
			assert(this_unmapping_end > this_unmapping_begin);
			unsigned long npages = (this_unmapping_end - this_unmapping_begin)>>LOG_PAGE_SIZE;
			// zero out the to-be-unmapped part of the memtable
			memset_bigalloc(pageindex + PAGENUM(this_unmapping_begin), 0, npages);
			// this mapping now ends at the unmapped base addr
			next_addr = b->end;
			b->end = base;
			SANITY_CHECK_BIGALLOC(b);
		}
		else if (__builtin_expect(remaining_after, 0))
		{
			// means the to-be-unmapped range ends *before* the end of the current mapping
			void *new_begin = (char*) base + s;
			assert((char*) new_begin > (char*) b->begin);
			unsigned long npages
			 = ((char*) new_begin - (char*) b->begin) >> LOG_PAGE_SIZE;
			memset_bigalloc(pageindex + PAGENUM(b->begin), 0, npages);
			b->begin = new_begin;
			next_addr = new_begin; // should terminate us
			SANITY_CHECK_BIGALLOC(b);
		}
		else 
		{
			// else we're just deleting the whole entry
			memset_bigalloc(pageindex + PAGENUM(b->begin), 0, 
					PAGENUM((char*) b->begin + this_bigalloc_size)
					 - PAGENUM(b->begin));
			next_addr = b->end;
			clear_bigalloc(b);
			SANITY_CHECK_BIGALLOC(b);
		}
		
		assert((uintptr_t) b->begin % PAGE_SIZE == 0);
		assert((uintptr_t) b->end % PAGE_SIZE == 0);
		
		/* How far have we got?  */
		assert(next_addr);
		cur_pagenum = PAGENUM(next_addr);
		
	} while (cur_pagenum < end_pagenum);
	
	assert(is_unindexed(base, (char*) base + s));
	BIG_UNLOCK
}

enum object_memory_kind __liballocs_get_memory_kind(const void *obj) __attribute__((visibility("protected")));
enum object_memory_kind __liballocs_get_memory_kind(const void *obj)
{
	if (__builtin_expect(!pageindex, 0)) init();
	if (__builtin_expect(obj == 0, 0)) return UNUSABLE;
	if (__builtin_expect(obj == (void*) -1, 0)) return UNUSABLE;
	
	bigalloc_num_t bigalloc_num = pageindex[PAGENUM(obj)];
	if (bigalloc_num == 0) return UNKNOWN;
	else return big_allocations[bigalloc_num].f.kind;
}

void __liballocs_print_l0_to_stream_err(void) __attribute__((visibility("protected")));
void __liballocs_print_l0_to_stream_err(void)
{
	int lock_ret;
	BIG_LOCK
			
	if (!pageindex) init();
	for (struct big_allocation *b = &big_allocations[1]; b < &big_allocations[NBIGALLOCS]; ++b)
	{
		if (BIGALLOC_IN_USE(b) && !b->parent) fprintf(stream_err, "%p-%p %01d %s %s %p\n", 
				b->begin, b->end, b->f.kind, name_for_memory_kind(b->f.kind), 
				b->meta.what == DATA_PTR ? "(data ptr) " : "(insert + bits) ", 
				b->meta.what == DATA_PTR ? b->meta.un.data_ptr : (void*)(uintptr_t) b->meta.un.ins_and_bits.ins.alloc_site);
	}
	
	BIG_UNLOCK
}

struct big_allocation * 
bigalloc_lookup_l0(void *base)
{
	int lock_ret;
	BIG_LOCK
	struct big_allocation *ret;
	
	if (!pageindex) init();
	bigalloc_num_t bigalloc_num = pageindex[PAGENUM(base)];
	if (bigalloc_num == 0) { ret = NULL; }
	else { ret = &big_allocations[bigalloc_num]; }
	
	BIG_UNLOCK
	return ret;
}

size_t
bigalloc_get_overlapping_l0(unsigned short *out_begin, 
		size_t out_size, void *begin, void *end) __attribute__((visibility("hidden")));
size_t bigalloc_get_overlapping_l0(unsigned short *out_begin, 
		size_t out_size, void *begin, void *end)
{
	int lock_ret;
	BIG_LOCK
	
	unsigned short *out = out_begin;
	uintptr_t end_pagenum = PAGENUM(end);
	uintptr_t begin_pagenum = PAGENUM(begin);
	while (out - out_begin < out_size)
	{
		// look for the next bigalloc that overlaps: skip unmapped bits
		while (begin_pagenum < end_pagenum && !pageindex[begin_pagenum])
		{ ++begin_pagenum; }
		
		if (begin_pagenum >= end_pagenum) break; // normal termination case
		
		bigalloc_num_t num = pageindex[begin_pagenum];
		*out++ = num;
		
		// advance begin_pagenum to one past the end of this bigalloc
		begin_pagenum = PAGENUM(big_allocations[num].end);
	}
	
	BIG_UNLOCK
	return out - out_begin;
}

struct big_allocation *
bigalloc_bounds_l0(const void *ptr, const void **out_begin, const void **out_end) __attribute__((visibility("hidden")));
struct big_allocation *
bigalloc_bounds_l0(const void *ptr, const void **out_begin, const void **out_end)
{
	// FIXME: support non-l0
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *ret;
	if (!pageindex) init();
	bigalloc_num_t num = pageindex[PAGENUM(ptr)];
	if (num == 0) { ret = NULL; }
	else 
	{
		if (out_begin) *out_begin = big_allocations[num].begin;
		if (out_end) *out_end = big_allocations[num].end;
		ret = &big_allocations[num];
	}
	
	BIG_UNLOCK
	return ret;
}

void *__try_index_bigalloc(const void *ptr, size_t modified_size, const void *caller) __attribute__((visibility("hidden")));
void *__try_index_bigalloc(const void *ptr, size_t modified_size, const void *caller)
{
	/* We get called from heap_index when the malloc'd address is a multiple of the 
	 * page size. Check whether it fills (more-or-less) the alloc'd region, and if so,  
	 * install its trailer into the maps. We will fish it out in get_alloc_info. */
	int lock_ret;
	BIG_LOCK
	
	__liballocs_ensure_init();

	char *chunk_end = (char*) ptr + malloc_usable_size((void*) ptr);
	
	if ((uintptr_t) ptr % PAGE_SIZE <= MAXIMUM_MALLOC_HEADER_OVERHEAD
			&& (uintptr_t) chunk_end % PAGE_SIZE == 0
			&& (uintptr_t) ptr - ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) ptr) <= MAXIMUM_MALLOC_HEADER_OVERHEAD)
	{
		// ensure we have this in the maps
		enum object_memory_kind k1 = __liballocs_get_memory_kind(ptr);
		enum object_memory_kind k2 = __liballocs_get_memory_kind((char*) ptr + modified_size);
		if (k1 == UNKNOWN || k2 == UNKNOWN) 
		{
			__liballocs_add_missing_maps();
			assert(__liballocs_get_memory_kind(ptr) != UNKNOWN);
			assert(__liballocs_get_memory_kind((char*) ptr + modified_size) != UNKNOWN);
		}
		
		/* Collect a contiguous sequence of so-far-without-insert bigallocs, 
		 * starting from ptr. */
		const void *lowest_bound = NULL;
		bigalloc_num_t num;
		unsigned nbigallocs = 0;
		_Bool saw_fit = 0;
		
		bigalloc_num_t cur_num;
		for (cur_num = pageindex[PAGENUM(ptr)]; 
				cur_num != 0 && big_allocations[cur_num].meta.what == DATA_PTR; 
				cur_num = pageindex[PAGENUM(big_allocations[cur_num].end)])
		{
			struct big_allocation *b = &big_allocations[cur_num];
			SANITY_CHECK_BIGALLOC(b);
			
			// on our first run, remember the lowest ptr
			if (!lowest_bound)
			{
				// if we have an early part of the first mapping in the way, split it
				if ((char*) b->begin < (char*) ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) ptr))
				{
					b = split_bigalloc(b, (void*) ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) ptr));
					cur_num = b - &big_allocations[0];
				}
				lowest_bound = b->begin;
			}

			++nbigallocs;

			if ((char*) b->end >= chunk_end)
			{
				// we've successfully reached an end point
				saw_fit = 1;
				
				// if we leave a later part of the mapping remaining, split off
				if ((char*) b->end > chunk_end)
				{
					SANITY_CHECK_BIGALLOC(b);
					split_bigalloc(b, chunk_end);
					SANITY_CHECK_BIGALLOC(b);
				}
				
				break;
			}
		}
		
		if (saw_fit)
		{
			/* We think we've got a mmap()'d region. 
			 * Grab the bottom region in the sequence, 
			 * delete the others, 
			 * then create_or_extend the bottom one to the required length.
			 */
			bigalloc_num_t last_num = cur_num;
			assert(caller);
			assert(lowest_bound);
			uintptr_t npages = ((uintptr_t) chunk_end - (uintptr_t) lowest_bound) >> LOG_PAGE_SIZE;
			uintptr_t bottom_pagenum = PAGENUM(lowest_bound);
			bigalloc_num_t bigalloc_num = pageindex[bottom_pagenum];
			assert(bigalloc_num != 0);
			struct big_allocation *b = &big_allocations[bigalloc_num];
			SANITY_CHECK_BIGALLOC(b);
			
			assert(big_allocations[last_num].end == chunk_end);
			
			assert(b->meta.what == DATA_PTR);
			assert(b->f.kind == HEAP);
			b->meta = (struct meta_info) {
				.what = INS_AND_BITS,
				.un = {
					ins_and_bits: { 
						.ins = (struct insert) {
							.alloc_site_flag = 0,
							.alloc_site = (uintptr_t) caller
						},
						.is_object_start = 1, 
						.npages = npages, 
						.obj_offset = (char*) ptr - (char*) lowest_bound
					}
				}
			};
			
			// delete the other mappings, then extend over them
			if ((char*) b->end < chunk_end) 
			{
				size_t s = chunk_end - (char*) b->end;
				bigalloc_del_l0(b->end, s);
				debug_printf(6, "big_allocation is %p\n,", b); 
				debug_printf(6, "We want to extend our bottom bigalloc number %ld (%p-%p) "
					"to include %ld bytes from %p\n", 
					(long)(b - &big_allocations[0]), b->begin, b->end, s, b->end); 
				assert(pageindex[PAGENUM((char*) b->end - 1)] == b - &big_allocations[0]);
				SANITY_CHECK_BIGALLOC(b);
				struct big_allocation *new_b = create_or_extend_bigalloc_l0(
						b->end, s, b->f, b->meta);
				SANITY_CHECK_BIGALLOC(new_b);
				assert(new_b == b);
			}

			BIG_UNLOCK
			return &b->meta.un.ins_and_bits.ins;
		}
		else
		{
			debug_printf(3, "Warning: could not pageindex pointer %p, size %lu "
				"in bigalloc range %p-%p (%lu bytes)\n,", ptr, modified_size, 
				lowest_bound, big_allocations[cur_num].end, 
				(char*) big_allocations[cur_num].end - (char*) lowest_bound);
		}
	}
	else
	{
		debug_printf(3, "Warning: could not pageindex pointer %p, size %lu: doesn't end "
			"on page boundary\n", ptr, modified_size);
	}

	BIG_UNLOCK
	return NULL;
}

unsigned __unindex_bigalloc(const void *mem) __attribute__((visibility("hidden")));
unsigned __unindex_bigalloc(const void *mem)
{
	// FIXME: support non-l0
	int lock_ret;
	BIG_LOCK
	
	const void *lower;
	const void *upper;
	struct big_allocation *b = bigalloc_bounds_l0(mem, &lower, &upper);
	unsigned lower_to_upper_npages = ((uintptr_t) upper - (uintptr_t) lower) >> LOG_PAGE_SIZE;
	assert(b);

	/* We want to unindex the same number of pages we indexed. */
	unsigned npages_to_unindex = b->meta.un.ins_and_bits.npages;
	unsigned total_size_to_unindex = npages_to_unindex << LOG_PAGE_SIZE;

	unsigned total_size_unindexed = lower_to_upper_npages << LOG_PAGE_SIZE;
	do
	{
		b->meta.what = 0;
		total_size_unindexed += (char*) upper - (char*) lower;
		if (total_size_unindexed < total_size_to_unindex)
		{
			// advance to the next bigalloc
			b = bigalloc_bounds_l0(upper, &lower, &upper);
		}
	} while (total_size_unindexed < total_size_to_unindex);
	
	BIG_UNLOCK
	return total_size_unindexed;
}

struct insert *__lookup_bigalloc(const void *mem, void **out_object_start) __attribute__((visibility("hidden")));
struct insert *__lookup_bigalloc(const void *mem, void **out_object_start)
{
	// FIXME: support non-l0
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *b = bigalloc_lookup_l0((void*) mem);
	if (b && b->meta.what)
	{
		// 1. we have to search backwards for the start of the mmapped region
		const void *cur = mem;
		const void *lower, *upper;
		// walk backwards through contiguous bigallocs, til we find one with the object-start bit set
		do
		{
			b = bigalloc_bounds_l0(cur, &lower, &upper);
			cur = b ? (const char*) lower - 1  : cur;
		} while (b && (assert(b->meta.what), !b->meta.un.ins_and_bits.is_object_start));
		
		// if n is null, it means we ran out of mappings before we saw the high bit
		assert(b);
		
		*out_object_start = (char*) lower + b->meta.un.ins_and_bits.obj_offset;
		BIG_UNLOCK
		return &b->meta.un.ins_and_bits.ins;
	}
	else 
	{
		BIG_UNLOCK
		return NULL;
	}
}
