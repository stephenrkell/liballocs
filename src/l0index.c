#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <string.h>
#include <wchar.h>
#include "liballocs_private.h"

#define MAPPING_IN_USE(m) ((m)->begin && (m)->end)
struct mapping
{
	void *begin;
	void *end;
	struct mapping_info n;
};

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


static struct mapping *get_mapping_from_node(struct mapping_info *n)
{
	/* HACK: FIXME: please get rid of this stupid node-based interface. */
	return (struct mapping *)((char*) n - offsetof(struct mapping, n));
}

/* How many mappings? 256 is a bit stingy. 
 * Each mapping is 48--64 bytes, so 4096 of them would take 256KB.
 * Maybe stick to 1024? */
#define NMAPPINGS 1024
struct mapping mappings[NMAPPINGS]; // NOTE: we *don't* use mappings[0]; the 0 byte means "empty"

#define SANITY_CHECK_MAPPING(m) \
	do { \
		if (MAPPING_IN_USE((m))) { \
			for (unsigned long i = PAGENUM((m)->begin); i < PAGENUM((m)->end); ++i) { \
				assert(l0index[i] == ((m) - &mappings[0])); \
			} \
			assert(l0index[PAGENUM((m)->begin)-1] != ((m) - &mappings[0])); \
			assert(l0index[PAGENUM((m)->end)] != ((m) - &mappings[0])); \
		} \
	} while (0)
	
mapping_num_t *l0index __attribute__((visibility("hidden")));

static void memset_mapping(mapping_num_t *begin, mapping_num_t num, size_t n)
{
	assert(1ull<<(8*sizeof(mapping_num_t)) >= NMAPPINGS - 1);
	assert(sizeof (wchar_t) == 2 * sizeof (mapping_num_t));

	/* We use wmemset with special cases at the beginning and end */
	if (n > 0 && (uintptr_t) begin % sizeof (wchar_t) != 0)
	{
		*begin++ = num;
		--n;
	}
	assert(n == 0 || (uintptr_t) begin % sizeof (wchar_t) == 0);
	
	// double up the value
	wchar_t wchar_val = ((wchar_t) num) << (8 * sizeof(mapping_num_t)) | num;
	
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
	if (!l0index)
	{
		/* Mmap our region. We map one byte for every page in the user address region. */
		assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE);
		l0index = MEMTABLE_NEW_WITH_TYPE(mapping_num_t, PAGE_SIZE, (void*) 0, (void*) STACK_BEGIN);
		if (l0index == MAP_FAILED) abort();
	}
}

_Bool __attribute__((visibility("hidden"))) insert_equal(struct insert *p_ins1, struct insert *p_ins2)
{
	return p_ins1->alloc_site_flag == p_ins2->alloc_site_flag &&
		p_ins1->alloc_site == p_ins2->alloc_site;
		// don't compare prev/next, at least not for now
}
_Bool __attribute__((visibility("hidden"))) mapping_info_equal(mapping_flags_t f, struct mapping_info *p_info1, struct mapping_info *p_info2)
{
	return p_info1->what == p_info2->what && 
	(p_info1->what == DATA_PTR ? mapping_info_has_data_ptr_equal_to(f, p_info2, p_info1->un.data_ptr)
	            : (assert(p_info1->what == INS_AND_BITS), 
					(insert_equal(&p_info1->un.ins_and_bits.ins, &p_info2->un.ins_and_bits.ins)
						&& p_info1->un.ins_and_bits.npages == p_info2->un.ins_and_bits.npages
						&& p_info1->un.ins_and_bits.obj_offset == p_info2->un.ins_and_bits.obj_offset)
					)
	);
}
_Bool  __attribute__((visibility("hidden"))) mapping_info_has_data_ptr_equal_to(mapping_flags_t f, const struct mapping_info *p_info, const void *data_ptr)
{
	return p_info->what == DATA_PTR
			&& (
					// -- it should be value-equal for stack and string-equal for static/mapped
							(f.kind == STACK && data_ptr == p_info->un.data_ptr)
							|| 
						((data_ptr == NULL && p_info->un.data_ptr == NULL)
							|| (data_ptr != NULL && p_info->un.data_ptr  != NULL && 
							0 == strcmp(p_info->un.data_ptr, data_ptr))));
}

_Bool __attribute__((visibility("hidden"))) mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2)
{
	return f1.kind == f2.kind
			&& f1.r == f2.r
			&& f1.w == f2.w
			&& f1.x == f2.x;
}

static struct mapping *find_free_mapping(void)
{
	for (struct mapping *p = &mappings[1]; p < &mappings[NMAPPINGS]; ++p)
	{
		SANITY_CHECK_MAPPING(p);
		
		if (!MAPPING_IN_USE(p))
		{
			return p;
		}
	}
	assert(0);
}

static _Bool
is_unindexed(void *begin, void *end)
{
	mapping_num_t *pos = &l0index[PAGENUM(begin)];
	while (pos < l0index + PAGENUM(end) && !*pos) { ++pos; }
	
	if (pos == l0index + PAGENUM(end)) return 1;
	
	debug_printf(6, "Found already-indexed position %p (mapping %d)\n", 
			ADDR_OF_PAGENUM(pos - l0index), *pos);
	return 0;
}

static _Bool
is_unindexed_or_heap(void *begin, void *end)
{
	mapping_num_t *pos = &l0index[PAGENUM(begin)];
	while (pos < l0index + PAGENUM(end) && (!*pos || mappings[*pos].n.f.kind == HEAP)) { ++pos; }
	
	if (pos == l0index + PAGENUM(end)) return 1;
	
	debug_printf(6, "Found already-indexed non-heap position %p (mapping %d)\n", 
			ADDR_OF_PAGENUM(pos - l0index), *pos);
	return 0;
}

static _Bool range_overlaps_mapping(struct mapping *m, void *base, size_t s)
{
	return (char*) base < (char*) m->end && (char*) base + s > (char*) m->begin;
}

#define SANITY_CHECK_NEW_MAPPING(base, s) \
	/* We have to tolerate overlaps in the case of anonymous mappings, because */ \
	/* they come and go without our direct oversight. */ \
	do { \
		for (unsigned i = 1; i < NMAPPINGS; ++i) { \
			assert(mappings[i].n.f.kind == HEAP || \
				!range_overlaps_mapping(&mappings[i], (base), (s))); \
		} \
	} while (0)
#define STRICT_SANITY_CHECK_NEW_MAPPING(base, s) \
	/* Don't tolerate overlaps! */ \
	do { \
		for (unsigned i = 1; i < NMAPPINGS; ++i) { \
			assert(!range_overlaps_mapping(&mappings[i], (base), (s))); \
		} \
	} while (0)

#define MAXPTR(a, b) \
	((((char*)(a)) > ((char*)(b))) ? (a) : (b))

#define MINPTR(a, b) \
	((((char*)(a)) < ((char*)(b))) ? (a) : (b))

static
struct mapping *create_or_extend_mapping(void *base, size_t s, mapping_flags_t f, struct mapping_info *p_info)
{
	assert((uintptr_t) base % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	assert(s % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	
	debug_printf(6, "%s: creating mapping base %p, size %lu, kind %u, info %p\n", 
		__func__, base, (unsigned long) s, f.kind, p_info);
	
	/* In the case of heap regions, libc can munmap them without our seeing it. 
	 * So, we might be surprised to find that our index is out-of-date here. 
	 * We force a deletion if so. NOTE that we have to repeat the procedure
	 * until we've found all overlapping mappings. The best way to do this
	 * is to linear search all mappings, and short-circuit once we've unmapped
	 * the whole amount.
	 * 
	 * Instead of iterating over all 1024 mappings, can we use the l0index to help us?
	 * 
	 * Not directly, because two bytes per page might still be a lot of memory to
	 * walk over. Suppose we're a 4GB mapping. That's 1M pages, each a 2-byte entry.
	 * We don't want to walk over 2MB of memory.
	 
	 * But we could keep a bitmap of the l0index 
	 * memtable, possibly over multiple levels (2^47 bits would be 512GB, so a lot
	 * of memory to walk over; 512GB in page-sized chunks can be bitmapped in 2^27
	 * bits, so 16MB... so two levels should suffice). Then walking a 4GB mapping
	 * which is currently unused (l0index all zero) would require us to walk 4M bits
	 * in the bottom bitmap, i.e. 512KB, which would be covered by only 128 bits in
	 * the top-level bitmap, i.e. two words. That's nice! Note that the two-word
	 * comparison only suffices if the memory has been untouched up to this point;
	 * if it has been touched, we have to scan the bottom-level bitmap. But we only
	 * scan 512KB of bitmap in the maximal case of a 4GB mapping. For small mappings
	 * it's still tiny.
	 * */
	unsigned long bytes_unmapped = 0;
	for (int i_map = 1; i_map < NMAPPINGS && bytes_unmapped < s; ++i_map)
	{
		if ((char*) mappings[i_map].begin < (char*) base + s
				&& (char*) mappings[i_map].end > (char*) base)
		{
			/* We have overlap. Unmap the whole thing? Or just the portion we overlap? 
			 * Since heap regions can shrink as well as grow, it seems safest to unmap
			 * only the overlapping portion. */
			if (mappings[i_map].n.f.kind == HEAP)
			{
				// force an unmapping of the overlapping region
				char *overlap_begin = MAXPTR((char*) mappings[i_map].begin, (char*) base);
				char *overlap_end = MINPTR((char*) mappings[i_map].end, (char*) base + s);
				
				debug_printf(6, "%s: forcing unmapping of %p-%p (from mapping number %d), overlapping %p-%p\n", 
					__func__, overlap_begin, overlap_end, i_map,  base, (char*) base + s);
				mapping_del(overlap_begin, overlap_end - overlap_begin);
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
				if (mappings[i_map].begin <= base
							&& (char*) mappings[i_map].end >= (char*) base + s
							&& mapping_flags_equal(mappings[i_map].n.f, f)
							&& mapping_info_equal(f, &mappings[i_map].n, p_info))
				{
					debug_printf(6, "%s: mapping already present\n", __func__);
					// if we're STATIC and have a data pt, we borrow the new data_ptr 
					// because it's more likely to be up-to-date
					if (f.kind == STATIC && p_info->what == DATA_PTR)
					{
						mappings[i_map].n.un.data_ptr = p_info->un.data_ptr;
					}
					return &mappings[i_map];
				}
				else if (mappings[i_map].n.f.kind == STACK && f.kind == STACK
					/* for stack, upper bound must be unchanged */
					&& mappings[i_map].end == (char*) base + s)
				{
					_Bool contracting = base > mappings[i_map].begin;
					/* assert that we're not contracting -- we're expanding! */
					assert(!contracting);

//					if (contracting)
//					{
//						// simply update the lower bound, do the memset, sanity check and exit
//						void *old_begin = m->begin;
//						m->begin = base;
//						assert(m->end == (char*) base + s);
//						memset_mapping(l0index + PAGENUM(old_begin), 0, 
//									((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
//						SANITY_CHECK_MAPPING(m);
//						return m;
//					}
//					else // expanding or zero-growth
//					{
						// simply update the lower bound, do the memset, sanity check and exit
						void *old_begin = mappings[i_map].begin;
						mappings[i_map].begin = base;
						assert(mappings[i_map].end == (char*) base + s);
						if (old_begin != base)
						{
							memset_mapping(l0index + PAGENUM(base), i_map, 
										((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
						}
						SANITY_CHECK_MAPPING(&mappings[i_map]);
						return &mappings[i_map];
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
	
	mapping_num_t mapping_num = l0index[PAGENUM(base)];
	//SANITY_CHECK_MAPPING(&mappings[mapping_num]);
	assert(mapping_num == 0);
	
	// test for nearby mappings to extend
	mapping_num_t abuts_existing_start = l0index[PAGENUM((char*) base + s)];
	mapping_num_t abuts_existing_end = l0index[PAGENUM((char*) base - 1)];
	
	// FIXME: the following ovelrap logic appears to be dead code... delete it?
	
	/* Tolerate overlapping either of these two, if we're mapping heap (anonymous). 
	 * We simply adjust our base and size so that we fit exactly. 
	 */
	if (f.kind == HEAP)
	{
		SANITY_CHECK_NEW_MAPPING(base, s);
		// adjust w.r.t. abutments
		if (abuts_existing_start 
			&& range_overlaps_mapping(&mappings[abuts_existing_start], base, s)
			&& mappings[abuts_existing_start].n.f.kind == HEAP)
		{
			s = (char*) mappings[abuts_existing_start].begin - (char*) base;
		}
		if (abuts_existing_end
			&& range_overlaps_mapping(&mappings[abuts_existing_end], base, s)
			&& mappings[abuts_existing_start].n.f.kind == HEAP)
		{
			base = mappings[abuts_existing_end].end;
		}
		
		// also adjust w.r.t. overlaps
		mapping_num_t our_end_overlaps = l0index[PAGENUM((char*) base + s) - 1];
		mapping_num_t our_begin_overlaps = l0index[PAGENUM((char*) base)];

		if (our_end_overlaps
			&& range_overlaps_mapping(&mappings[our_end_overlaps], base, s)
			&& mappings[our_end_overlaps].n.f.kind == HEAP)
		{
			// move our end earlier, but not to earlier than base
			void *cur_end = (char *) base + s;
			void *new_end = MAXPTR(base, mappings[our_end_overlaps].begin);
			s = (char*) new_end - (char*) base;
		}
		if (our_begin_overlaps
			&& range_overlaps_mapping(&mappings[our_begin_overlaps], base, s)
			&& mappings[our_begin_overlaps].n.f.kind == HEAP)
		{
			// move our begin later, but not to later than base + s
			void *new_begin = MINPTR(mappings[our_begin_overlaps].begin, (char*) base + s); 
			ptrdiff_t length_reduction = (char*) new_begin - (char*) base;
			assert(length_reduction >= 0);
			base = new_begin;
			s -= length_reduction;
		}		
		
		STRICT_SANITY_CHECK_NEW_MAPPING(base, s);
	}
	else if (f.kind == STACK)
	{
		/* Tolerate sharing an upper boundary with an existing mapping. */
		mapping_num_t our_end_overlaps = l0index[PAGENUM((char*) base + s) - 1];
		
		if (our_end_overlaps)
		{
			_Bool contracting = base > mappings[our_end_overlaps].begin;
			struct mapping *m = &mappings[our_end_overlaps];
			
			if (contracting)
			{
				// simply update the lower bound, do the memset, sanity check and exit
				void *old_begin = m->begin;
				m->begin = base;
				assert(m->end == (char*) base + s);
				memset_mapping(l0index + PAGENUM(old_begin), 0, 
							((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
				SANITY_CHECK_MAPPING(m);
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
					memset_mapping(l0index + PAGENUM(base), our_end_overlaps, 
								((char*) old_begin - (char*) base) >> LOG_PAGE_SIZE);
				}
				SANITY_CHECK_MAPPING(m);
				return m;
			}
		}
		
		// neither expanding nor contracting, so we look for strictly correct
		STRICT_SANITY_CHECK_NEW_MAPPING(base, s);
	}
	assert(is_unindexed_or_heap(base, (char*) base + s));
	
	debug_printf(6, "node info is %p\n", p_info);
	
	debug_printf(6, "%s: abuts_existing_start: %d, abuts_existing_end: %d\n",
			__func__, abuts_existing_start, abuts_existing_end);

	_Bool flags_matches = 1;
	_Bool node_matches = 1;
	
	_Bool can_coalesce_after = abuts_existing_start
				&& (flags_matches = (mapping_flags_equal(mappings[abuts_existing_start].n.f, f)))
				&& (node_matches = (mapping_info_equal(f, &mappings[abuts_existing_start].n, p_info)));
	_Bool can_coalesce_before = abuts_existing_end
				&& (flags_matches = (mapping_flags_equal(mappings[abuts_existing_end].n.f, f)))
				&& (node_matches = (mapping_info_equal(f, &mappings[abuts_existing_end].n, p_info)));
	debug_printf(6, "%s: can_coalesce_after: %s, can_coalesce_before: %s, "
			"flags_matches: %s, node_matches: %s \n",
			__func__, can_coalesce_after ? "true" : "false", can_coalesce_before ? "true" : "false", 
			flags_matches ? "true": "false", node_matches ? "true": "false" );
	
	/* If we *both* abut a start and an end, we're coalescing 
	 * three mappings. If so, just bump up our base and s, 
	 * free the spare mapping and coalesce before. */
	if (__builtin_expect(can_coalesce_before && can_coalesce_after, 0))
	{
		s += (char*) mappings[abuts_existing_start].end - (char*) mappings[abuts_existing_start].begin;
		mappings[abuts_existing_start].begin = 
			mappings[abuts_existing_start].end =
				NULL;
		debug_printf(6, "%s: bumped up size to join two mappings\n", __func__);
		can_coalesce_after = 0;
	}
	
	if (can_coalesce_before)
	{
		debug_printf(6, "%s: post-extending existing mapping ending at %p\n", __func__,
				mappings[abuts_existing_end].end);
		memset_mapping(l0index + PAGENUM(mappings[abuts_existing_end].end), abuts_existing_end, 
			s >> LOG_PAGE_SIZE);
		mappings[abuts_existing_end].end = (char*) base + s;
		SANITY_CHECK_MAPPING(&mappings[abuts_existing_end]);
		return &mappings[abuts_existing_end];
	}
	if (can_coalesce_after)
	{
		debug_printf(6, "%s: pre-extending existing mapping at %p-%p\n", __func__,
				mappings[abuts_existing_start].begin, mappings[abuts_existing_start].end);
		mappings[abuts_existing_start].begin = (char*) base;
		memset_mapping(l0index + PAGENUM(base), abuts_existing_start, s >> LOG_PAGE_SIZE);
		SANITY_CHECK_MAPPING(&mappings[abuts_existing_start]);
		return &mappings[abuts_existing_start];
	}
	
	debug_printf(6, "%s: forced to assign new mapping\n", __func__);
	
	// else create new
	struct mapping *found = find_free_mapping();
	if (found)
	{
		found->begin = base;
		found->end = (char*) base + s;
		found->n.f = f;
		found->n.what = p_info->what;
		found->n.un = p_info->un;
		memset_mapping(l0index + PAGENUM(base), (mapping_num_t) (found - &mappings[0]), s >> LOG_PAGE_SIZE);
		SANITY_CHECK_MAPPING(found);
		return found;
	}
	
	return NULL;
}

static _Bool path_is_realpath(const char *path)
{
	const char *rp = realpath_quick(path);
	return 0 == strcmp(path, rp);
}

struct mapping_info *mapping_add(void *base, size_t s, mapping_flags_t f, const void *data_ptr) __attribute__((visibility("hidden")));
struct mapping_info *mapping_add(void *base, size_t s, mapping_flags_t f, const void *data_ptr)
{
	if (!l0index) init();
	
	assert(!data_ptr || f.kind == STACK || path_is_realpath((const char *) data_ptr));
	
	struct mapping_info info = { .f = f, .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	return mapping_add_full(base, s, &info);
}

void mapping_add_sloppy(void *base, size_t s, mapping_flags_t f, const void *data_ptr) __attribute__((visibility("hidden")));
void mapping_add_sloppy(void *base, size_t s, mapping_flags_t f, const void *data_ptr)
{
	int lock_ret;
	BIG_LOCK
			
	if (!l0index) init();

	/* What's the biggest mapping you can think of? 
	 * 
	 * We don't want to index our memtables. I'm going to be conservative
	 * and avoid indexing anything above 4GB. */
	if (__builtin_expect(s >= BIGGEST_MAPPING, 0))
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
	
	struct mapping_info info = { .f = f, .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	
	/* Just add the as-yet-unmapped bits of the range. */
	uintptr_t begin_pagenum = PAGENUM(base);
	uintptr_t current_pagenum = begin_pagenum;
	uintptr_t end_pagenum = PAGENUM((char*) base + s);
	while (current_pagenum < end_pagenum)
	{
		uintptr_t next_indexed_pagenum = current_pagenum;
		while (next_indexed_pagenum < end_pagenum && !l0index[next_indexed_pagenum])
		{ ++next_indexed_pagenum; }
		
		if (next_indexed_pagenum > current_pagenum)
		{
			mapping_add_full((void*) ADDR_OF_PAGENUM(current_pagenum), 
				(char*) ADDR_OF_PAGENUM(next_indexed_pagenum)
					 - (char*) ADDR_OF_PAGENUM(current_pagenum), 
				&info);
		}
		
		current_pagenum = next_indexed_pagenum;
		// skip over any indexed bits so we're pointing at the next unindexed bit
		while (l0index[current_pagenum] && ++current_pagenum < end_pagenum);
	}
	
	BIG_UNLOCK
}

int mapping_lookup_exact(struct mapping_info *n, void *begin, void *end)__attribute__((visibility("hidden")));
int mapping_lookup_exact(struct mapping_info *n, void *begin, void *end)
{
	int lock_ret;
	BIG_LOCK
	struct mapping *m = get_mapping_from_node(n);
	_Bool ret = m->begin == begin && m->end == end;
	BIG_UNLOCK
	return ret;
}

struct mapping_info *mapping_add_full(void *base, size_t s, struct mapping_info *p_arg) __attribute__((visibility("hidden")));
struct mapping_info *mapping_add_full(void *base, size_t s, struct mapping_info *p_arg)
{
	int lock_ret;
	BIG_LOCK
	
	if (!l0index) init();

	assert((uintptr_t) base % PAGE_SIZE == 0);
	assert(s % PAGE_SIZE == 0);
	
	mapping_flags_t f = p_arg->f;
	
	/* What's the biggest mapping you can think of? 
	 * 
	 * We don't want to index our memtables. I'm going to be conservative
	 * and avoid indexing anything above 4GB. */
	if (s >= BIGGEST_MAPPING)
	{
		debug_printf(3, "Warning: not indexing huge mapping (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return NULL;
	}
	if (__builtin_expect((uintptr_t) base + s > STACK_BEGIN, 0))
	{
		debug_printf(3, "Warning: not indexing high-in-VAS mapping (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return NULL;
	}
	
	uintptr_t first_page_num = (uintptr_t) base >> LOG_PAGE_SIZE;
	uintptr_t npages = s >> LOG_PAGE_SIZE;

	struct mapping *m = create_or_extend_mapping(base, s, f, p_arg);
	SANITY_CHECK_MAPPING(m);
	struct mapping_info *ret = &m->n;

	BIG_UNLOCK
	return ret;
}

static struct mapping *split_mapping(struct mapping *m, void *split_addr)
{
	assert(m);
	assert((char*) split_addr > (char*) m->begin);
	assert((char*) split_addr < (char*) m->end);
	
	// make a new entry for the remaining-after part, then just chop before
	struct mapping *new_m = find_free_mapping();
	assert(new_m);
	new_m->begin = split_addr;
	new_m->end = m->end;
	assert((char*) new_m->end > (char*) new_m->begin);
	new_m->n = m->n;

	// rewrite uses of the old mapping number in the new-mapping portion of the memtable
	mapping_num_t new_mapping_num = new_m - &mappings[0];
	unsigned long npages
	 = ((char*) new_m->end - ((char*) new_m->begin)) >> LOG_PAGE_SIZE;
	memset_mapping(l0index + PAGENUM((char*) new_m->begin), new_mapping_num, npages);

	// delete (from m) the part now covered by new_m
	m->end = new_m->begin;
	
	SANITY_CHECK_MAPPING(m);
	SANITY_CHECK_MAPPING(new_m);
	
	return new_m;
}

void mapping_del_node(struct mapping_info *n) __attribute__((visibility("hidden")));
void mapping_del_node(struct mapping_info *n)
{
	int lock_ret;
	BIG_LOCK
			
	/* HACK: FIXME: please get rid of this stupid node-based interface. */
	struct mapping *m = get_mapping_from_node(n);
	
	// check sanity
	assert(l0index[PAGENUM(m->begin)] == m - &mappings[0]);
	
	mapping_del(m->begin, (char*) m->end - (char*) m->begin);
	
	BIG_UNLOCK
}

static void clear_mapping(struct mapping *m)
{
	m->begin = m->end = NULL;
	memset(&m->n, 0, sizeof m->n);
}

void mapping_del(void *base, size_t s) __attribute__((visibility("hidden")));
void mapping_del(void *base, size_t s)
{
	int lock_ret;
	BIG_LOCK
			
	if (!l0index) init();
	
	assert(s % PAGE_SIZE == 0);
	assert((uintptr_t) base % PAGE_SIZE == 0);

	if (s >= BIGGEST_MAPPING)
	{
		debug_printf(3, "Warning: not unindexing huge mapping (size %lu) at %p\n", (unsigned long) s, base);
		BIG_UNLOCK
		return;
	}
	
	unsigned long cur_pagenum = PAGENUM(base); 
	unsigned long end_pagenum = PAGENUM((char*)base + s);
	mapping_num_t mapping_num;
	// if we get mapping num 0 at first, try again after forcing __liballocs_init_l0()
	/* We might span multiple mappings, because munmap() is like that. */
	mapping_num = l0index[PAGENUM(base)];
	if (mapping_num == 0)
	{
		__liballocs_init_l0();
		mapping_num = l0index[PAGENUM(base)];
		/* Give up if we still can't get it. */
		if (mapping_num == 0) return;
	}

	do
	{
		// if we see some zero mapping nums, skip forward
		unsigned long initial_cur_pagenum = cur_pagenum;
		if (__builtin_expect(cur_pagenum < end_pagenum && l0index[cur_pagenum] == 0, 0))
		{
			while (cur_pagenum < end_pagenum)
			{
				if (l0index[cur_pagenum]) break;
				++cur_pagenum;
			}
			if (cur_pagenum == end_pagenum) break;
			debug_printf(3, "Warning: l0-unindexing a partially unmapped region %p-%p\n",
				ADDR_OF_PAGENUM(initial_cur_pagenum), ADDR_OF_PAGENUM(cur_pagenum));
		}
		mapping_num = l0index[cur_pagenum];
		/* If mapping num is 0 when we get here, it means there's no mapping here. 
		 * This might happen because users are allowed to call munmap() on unmapped
		 * regions. */
		assert(mapping_num != 0);
		struct mapping *m = &mappings[mapping_num];
		SANITY_CHECK_MAPPING(m);
		size_t this_mapping_size = (char*) m->end - (char*) m->begin;
		
		/* Do we need to chop an entry? */
		_Bool remaining_before = m->begin < base;
		_Bool remaining_after
		 = (char*) m->end > (char*) base + s;

		void *next_addr = NULL;
		/* If we're chopping before and after, we need to grab a *new* 
		 * mapping number. */
		if (__builtin_expect(remaining_before && remaining_after, 0))
		{
			struct mapping *new_m = split_mapping(m, (char*) base + s);

			// we might still need to chop before, but not after
			remaining_after = 0;

			assert((uintptr_t) new_m->begin % PAGE_SIZE == 0);
			assert((uintptr_t) new_m->end % PAGE_SIZE == 0);
		}

		if (__builtin_expect(remaining_before, 0))
		{
			// means the to-be-unmapped range starts *after* the start of the current mapping
			char *this_unmapping_begin = (char*) base;
			assert((char*) m->end <= ((char*) base + s)); // we should have dealt with the other case above
			char *this_unmapping_end = //((char*) m->end > ((char*) base + s))
					//? ((char*) base + s)
					/*:*/ m->end;
			assert(this_unmapping_end > this_unmapping_begin);
			unsigned long npages = (this_unmapping_end - this_unmapping_begin)>>LOG_PAGE_SIZE;
			// zero out the to-be-unmapped part of the memtable
			memset_mapping(l0index + PAGENUM(this_unmapping_begin), 0, npages);
			// this mapping now ends at the unmapped base addr
			next_addr = m->end;
			m->end = base;
			SANITY_CHECK_MAPPING(m);
		}
		else if (__builtin_expect(remaining_after, 0))
		{
			// means the to-be-unmapped range ends *before* the end of the current mapping
			void *new_begin = (char*) base + s;
			assert((char*) new_begin > (char*) m->begin);
			unsigned long npages
			 = ((char*) new_begin - (char*) m->begin) >> LOG_PAGE_SIZE;
			memset_mapping(l0index + PAGENUM(m->begin), 0, npages);
			m->begin = new_begin;
			next_addr = new_begin; // should terminate us
			SANITY_CHECK_MAPPING(m);
		}
		else 
		{
			// else we're just deleting the whole entry
			memset_mapping(l0index + PAGENUM(m->begin), 0, 
					PAGENUM((char*) m->begin + this_mapping_size)
					 - PAGENUM(m->begin));
			next_addr = m->end;
			clear_mapping(m);
			SANITY_CHECK_MAPPING(m);
		}
		
		assert((uintptr_t) m->begin % PAGE_SIZE == 0);
		assert((uintptr_t) m->end % PAGE_SIZE == 0);
		
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
	if (__builtin_expect(!l0index, 0)) init();
	if (__builtin_expect(obj == 0, 0)) return UNUSABLE;
	if (__builtin_expect(obj == (void*) -1, 0)) return UNUSABLE;
	
	mapping_num_t mapping_num = l0index[PAGENUM(obj)];
	if (mapping_num == 0) return UNKNOWN;
	else return mappings[mapping_num].n.f.kind;
}

void __liballocs_print_mappings_to_stream_err(void) __attribute__((visibility("protected")));
void __liballocs_print_mappings_to_stream_err(void)
{
	int lock_ret;
	BIG_LOCK
			
	if (!l0index) init();
	for (struct mapping *m = &mappings[1]; m < &mappings[NMAPPINGS]; ++m)
	{
		if (MAPPING_IN_USE(m)) fprintf(stream_err, "%p-%p %01d %s %s %p\n", 
				m->begin, m->end, m->n.f.kind, name_for_memory_kind(m->n.f.kind), 
				m->n.what == DATA_PTR ? "(data ptr) " : "(insert + bits) ", 
				m->n.what == DATA_PTR ? m->n.un.data_ptr : (void*)(uintptr_t) m->n.un.ins_and_bits.ins.alloc_site);
	}
	
	BIG_UNLOCK
}
struct mapping_info *
mapping_lookup(void *base) __attribute__((visibility("hidden")));

struct mapping_info *__liballocs_mapping_lookup(const void *obj) __attribute__((visibility("default"), alias("mapping_lookup")));

struct mapping_info * 
mapping_lookup(void *base)
{
	int lock_ret;
	BIG_LOCK
	struct mapping_info *ret;
	
	if (!l0index) init();
	mapping_num_t mapping_num = l0index[PAGENUM(base)];
	if (mapping_num == 0) { ret = NULL; }
	else { ret = &mappings[mapping_num].n; }
	
	BIG_UNLOCK
	return ret;
}

size_t
mapping_get_overlapping(struct mapping_info **out_begin, 
		size_t out_size, void *begin, void *end) __attribute__((visibility("hidden")));
size_t mapping_get_overlapping(struct mapping_info **out_begin, 
		size_t out_size, void *begin, void *end)
{
	int lock_ret;
	BIG_LOCK
	
	struct mapping_info **out = out_begin;
	uintptr_t end_pagenum = PAGENUM(end);
	uintptr_t begin_pagenum = PAGENUM(begin);
	while (out - out_begin < out_size)
	{
		// look for the next mapping that overlaps: skip unmapped bits
		while (begin_pagenum < end_pagenum && !l0index[begin_pagenum])
		{ ++begin_pagenum; }
		
		if (begin_pagenum >= end_pagenum) break; // normal termination case
		
		mapping_num_t num = l0index[begin_pagenum];
		*out++ = &mappings[num].n;
		
		// advance begin_pagenum to one past the end of this mapping
		begin_pagenum = PAGENUM(mappings[num].end);
	}
	
	BIG_UNLOCK
	return out - out_begin;
}

struct mapping_info *
mapping_bounds(const void *ptr, const void **out_begin, const void **out_end) __attribute__((visibility("hidden")));
struct mapping_info *
mapping_bounds(const void *ptr, const void **out_begin, const void **out_end)
{
	int lock_ret;
	BIG_LOCK
	
	struct mapping_info *ret;
	if (!l0index) init();
	mapping_num_t mapping_num = l0index[PAGENUM(ptr)];
	if (mapping_num == 0) { ret = NULL; }
	else 
	{
		if (out_begin) *out_begin = mappings[mapping_num].begin;
		if (out_end) *out_end = mappings[mapping_num].end;
		ret = &mappings[mapping_num].n;
	}
	
	BIG_UNLOCK
	return ret;
}

void *__try_index_l0(const void *ptr, size_t modified_size, const void *caller) __attribute__((visibility("hidden")));
void *__try_index_l0(const void *ptr, size_t modified_size, const void *caller)
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
		
		/* Collect a contiguous sequence of so-far-without-insert mappings, 
		 * starting from ptr. */
		const void *lowest_bound = NULL;
		mapping_num_t num;
		unsigned nmappings = 0;
		_Bool saw_fit = 0;
		
		mapping_num_t cur_num;
		for (cur_num = l0index[PAGENUM(ptr)]; 
				cur_num != 0 && mappings[cur_num].n.what == DATA_PTR; 
				cur_num = l0index[PAGENUM(mappings[cur_num].end)])
		{
			struct mapping *m = &mappings[cur_num];
			SANITY_CHECK_MAPPING(m);
			
			// on our first run, remember the lowest ptr
			if (!lowest_bound)
			{
				// if we have an early part of the first mapping in the way, split it
				if ((char*) m->begin < (char*) ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) ptr))
				{
					m = split_mapping(m, (void*) ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) ptr));
					cur_num = m - &mappings[0];
				}
				lowest_bound = m->begin;
			}

			++nmappings;

			if ((char*) m->end >= chunk_end)
			{
				// we've successfully reached an end point
				saw_fit = 1;
				
				// if we leave a later part of the mapping remaining, split off
				if ((char*) m->end > chunk_end)
				{
					SANITY_CHECK_MAPPING(m);
					split_mapping(m, chunk_end);
					SANITY_CHECK_MAPPING(m);
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
			mapping_num_t last_num = cur_num;
			assert(caller);
			assert(lowest_bound);
			uintptr_t npages = ((uintptr_t) chunk_end - (uintptr_t) lowest_bound) >> LOG_PAGE_SIZE;
			uintptr_t bottom_pagenum = PAGENUM(lowest_bound);
			mapping_num_t mapping_num = l0index[bottom_pagenum];
			assert(mapping_num != 0);
			struct mapping *m = &mappings[mapping_num];
			SANITY_CHECK_MAPPING(m);
			
			assert(mappings[last_num].end == chunk_end);
			
			assert(m->n.what == DATA_PTR);
			assert(m->n.f.kind == HEAP);
			m->n.what = INS_AND_BITS;
			m->n.un = (union mapping_info_union) {
					ins_and_bits: { 
						.ins = (struct insert) {
							.alloc_site_flag = 0,
							.alloc_site = (uintptr_t) caller
						},
						.is_object_start = 1, 
						.npages = npages, 
						.obj_offset = (char*) ptr - (char*) lowest_bound
					}
				};
			
			// delete the other mappings, then extend over them
			if ((char*) m->end < chunk_end) 
			{
				size_t s = chunk_end - (char*) m->end;
				mapping_del(m->end, s);
				debug_printf(6, "mapping_info is %p\n,",&m->n ); 
				debug_printf(6, "We want to extend our bottom mapping number %ld (%p-%p) "
					"to include %ld bytes from %p\n", 
					(long)(m - &mappings[0]), m->begin, m->end, s, m->end); 
				assert(l0index[PAGENUM((char*) m->end - 1)] == m - &mappings[0]);
				SANITY_CHECK_MAPPING(m);
				struct mapping *new_m = create_or_extend_mapping(
						m->end, s, m->n.f, &m->n);
				SANITY_CHECK_MAPPING(new_m);
				assert(new_m == m);
			}

			BIG_UNLOCK
			return &m->n.un.ins_and_bits.ins;
		}
		else
		{
			debug_printf(3, "Warning: could not l0-index pointer %p, size %lu "
				"in mapping range %p-%p (%lu bytes, %u mappings)\n,", ptr, modified_size, 
				lowest_bound, mappings[cur_num].end, 
				(char*) mappings[cur_num].end - (char*) lowest_bound, nmappings);
		}
	}
	else
	{
		debug_printf(3, "Warning: could not l0-index pointer %p, size %lu: doesn't end "
			"on page boundary\n", ptr, modified_size);
	}

	BIG_UNLOCK
	return NULL;
}

static unsigned unindex_l0_one_mapping(struct mapping_info *n, const void *lower, const void *upper)
{
	n->what = 0;
	return (char*) upper - (char*) lower;
}

unsigned __unindex_l0(const void *mem) __attribute__((visibility("hidden")));
unsigned __unindex_l0(const void *mem)
{
	int lock_ret;
	BIG_LOCK
	
	const void *lower;
	const void *upper;
	struct mapping_info *n = mapping_bounds(mem, &lower, &upper);
	unsigned lower_to_upper_npages = ((uintptr_t) upper - (uintptr_t) lower) >> LOG_PAGE_SIZE;
	assert(n);

	/* We want to unindex the same number of pages we indexed. */
	unsigned npages_to_unindex = n->un.ins_and_bits.npages;
	unsigned total_size_to_unindex = npages_to_unindex << LOG_PAGE_SIZE;

	unsigned total_size_unindexed = lower_to_upper_npages << LOG_PAGE_SIZE;
	do
	{
		total_size_unindexed += unindex_l0_one_mapping(n, lower, upper);
		if (total_size_unindexed < total_size_to_unindex)
		{
			// advance to the next mapping
			n = mapping_bounds(upper, &lower, &upper);
		}
	} while (total_size_unindexed < total_size_to_unindex);
	
	BIG_UNLOCK
	return total_size_unindexed;
}

struct insert *__lookup_l0(const void *mem, void **out_object_start) __attribute__((visibility("hidden")));
struct insert *__lookup_l0(const void *mem, void **out_object_start)
{
	int lock_ret;
	BIG_LOCK
	
	struct mapping_info *n = mapping_lookup((void*) mem);
	if (n && n->what)
	{
		// 1. we have to search backwards for the start of the mmapped region
		const void *cur = mem;
		const void *lower, *upper;
		// walk backwards through contiguous mappings, til we find one with the high bit set
		do
		{
			n = mapping_bounds(cur, &lower, &upper);
			cur = n ? (const char*) lower - 1  : cur;
		} while (n && (assert(n->what), !n->un.ins_and_bits.is_object_start));
		
		// if n is null, it means we ran out of mappings before we saw the high bit
		assert(n);
		
		*out_object_start = (char*) lower + n->un.ins_and_bits.obj_offset;
		BIG_UNLOCK
		return &n->un.ins_and_bits.ins;
	}
	else 
	{
		BIG_UNLOCK
		return NULL;
	}
}
