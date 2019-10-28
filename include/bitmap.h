#ifndef LIBALLOCS_BITMAP_H_
#define LIBALLOCS_BITMAP_H_

#include <assert.h>
// want a truly word-sized integer... let's use uintptr_t for now
#include <stdint.h>
#include "bitops.h"

typedef uintptr_t bitmap_word_t;
#define BITMAP_WORD_NBITS (8*sizeof(bitmap_word_t))

/* We define both "big-endian" and "little-endian" *bit* orders.
 * These are intended for bitmaps whose elements denote bytes.
 * Big-endian mean the lowest-address bit is the most significant.
 * Little-endian means the lowest-address bit is the least significant.
 * Big-endian is best for reverse searches ("find the next lower address...")
 * whereas little-endian is best for forward searches ("find the next higher").
 * To see why, the following shows why big-endian is better for rfind.
	if (*p_bitmap < (1ul<<start_idx))
	{
		// The word has a value less than the query bit pattern, so
		// it can't have the query bit or any higher bit set.
	}
	else
	{
		// The word has a value greater than or equal to the query bit pattern, so
		// it may or may not have the query bit set.
	}
 */

/**********************************************
 * big-endian functions
 **********************************************/

static inline _Bool bitmap_get_b(bitmap_word_t *p_bitmap, unsigned long index)
{
	return p_bitmap[index / BITMAP_WORD_NBITS] & (1ul << (BITMAP_WORD_NBITS-1-(index % BITMAP_WORD_NBITS)));
}
static inline void bitmap_set_b(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] |= (1ul << (BITMAP_WORD_NBITS-1-(index % BITMAP_WORD_NBITS)));
}
static inline void bitmap_clear_b(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] &= ~(1ul << (BITMAP_WORD_NBITS-1-(index % BITMAP_WORD_NBITS)));
}
/* Here we do a reverse search
 * for the first bit set
 * at or below
 * bit position start_idx.
 * We return the index of that bit, or (bitmap_word_t) -1 if no set bit was found.
 */
static inline unsigned long bitmap_rfind_first_set_leq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, long start_pos)
{
	bitmap_word_t *p_base = p_bitmap;
	p_bitmap += start_pos / BITMAP_WORD_NBITS;
	start_pos %= BITMAP_WORD_NBITS;
	if (p_bitmap > p_limit) return (unsigned long) -1;
	while (1)
	{
		if (*p_bitmap < (1ul<<(BITMAP_WORD_NBITS-1-start_pos)))
		{
			// The word has a value less than the query bit pattern, so
			// it can't have the query bit or any higher-significance (lower-address) bit set.
			// So search lower
			if (p_bitmap == p_base) return (bitmap_word_t) -1;
			--p_bitmap;
			start_pos = BITMAP_WORD_NBITS - 1;
			continue;
		}
		else // *p_bitmap >= (1ul<<(BITMAP_WORD_NBITS-1-start_pos))
		{
			// This is our termination case.
			// The word has a value greater than or equal to the query bit pattern, so
			// it has one or more of the query or any higher-significance (lower-address) bit set.
			// First mask out so we have only the query bit or higher-significance bits set.
			// Then find the highest-address (lowest-significance) bit set.
			// The search result is the (bitmap-wide) position of that bit.
			unsigned query_bit_idx = BITMAP_WORD_NBITS-1-start_pos; // in the range 0..63
			// how many bits are equal-or-higher-significance than the query bit?
			// it's from the query bit idx up to 63
			bitmap_word_t w = *p_bitmap & TOP_N_BITS_SET(BITMAP_WORD_NBITS - query_bit_idx);
			unsigned lowest_significance_bit_idx = ntz(w);
			unsigned that_bit_relative_pos = BITMAP_WORD_NBITS-1-lowest_significance_bit_idx;
			unsigned that_bit_pos = (p_bitmap - p_base) * (BITMAP_WORD_NBITS) + that_bit_relative_pos;
			return that_bit_pos;
		}
	}
	return (bitmap_word_t) -1;
}
static inline unsigned long bitmap_find_first_set1_geq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long start_idx, unsigned long *out_test_bit)
{
	return (bitmap_word_t) -1; // FIXME
}
static inline unsigned long bitmap_find_first_set_geq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	return (bitmap_word_t) -1; // FIXME
}
static inline unsigned long bitmap_find_first_clear_geq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	return (bitmap_word_t) -1; // FIXME
}
static inline unsigned long bitmap_count_set_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit,
	unsigned long start_idx_ge, unsigned long end_idx_lt)
{
	return (bitmap_word_t) -1; // FIXME
}

/**********************************************
 * little-endian functions
 **********************************************/

static inline _Bool bitmap_get_l(bitmap_word_t *p_bitmap, unsigned long index)
{
	return p_bitmap[index / BITMAP_WORD_NBITS] & (1ul << (index % BITMAP_WORD_NBITS));
}
static inline void bitmap_set_l(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] |= (1ul << (index % BITMAP_WORD_NBITS));
}
static inline void bitmap_clear_l(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] &= ~(1ul << (index % BITMAP_WORD_NBITS));
}
/* Here we do a reverse search
 * for the first bit set
 * at or below
 * bit position start_idx.
 * We return the position (index) of that bit, or (bitmap_word_t) -1 if no set bit was found.
 * Optionally, via out_test_bit we return the bitmask identifying the found bit.
 */
static inline unsigned long bitmap_rfind_first_set_leq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, long start_idx, unsigned long *out_test_bit)
{
	bitmap_word_t *p_base = p_bitmap;
	p_bitmap += start_idx / BITMAP_WORD_NBITS;
	start_idx %= BITMAP_WORD_NBITS;
	if (p_bitmap > p_limit) return (unsigned long) -1;
	while (1)
	{
		while (start_idx >= 0)
		{
			bitmap_word_t test_bit = 1ul << start_idx;
			if (*p_bitmap & test_bit)
			{
				if (out_test_bit) *out_test_bit = test_bit;
				return start_idx + (p_bitmap - p_base) * BITMAP_WORD_NBITS;
			}
			--start_idx;
		}
		// now start_idx < 0
		if (p_bitmap == p_base) break;
		start_idx = BITMAP_WORD_NBITS - 1;
		--p_bitmap;
	}
	return (unsigned long) -1;
}
/* Here we do a forward search for the first bit set
 * starting at position start_idx.
 * We return its position, or (bitmap_word_t)-1 if not found.
 * Optionally, on success we also output the bitmask identifying that bit.
 */
static inline unsigned long bitmap_find_first_set1_geq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long start_idx, unsigned long *out_test_bit)
{
	unsigned long *p_base = p_bitmap;
	p_bitmap += start_idx / BITMAP_WORD_NBITS;
	start_idx %= BITMAP_WORD_NBITS;
	if (p_bitmap >= p_limit) return (unsigned long) -1;
	while (1)
	{
		while (start_idx < BITMAP_WORD_NBITS)
		{
			unsigned long test_bit = 1ul << start_idx;
			if (*p_bitmap & test_bit)
			{
				if (out_test_bit) *out_test_bit = test_bit;
				return start_idx + (p_bitmap - p_base) * BITMAP_WORD_NBITS;
			}
			++start_idx;
		}
		// now start_idx < 0
		++p_bitmap;
		if (p_bitmap == p_limit) break;
		start_idx = 0;
	}
	return (unsigned long) -1;
}
static inline unsigned long bitmap_find_first_set_geq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	bitmap_word_t *p_initial_bitmap;
			
	while (*p_bitmap == (bitmap_word_t) 0
				&& p_bitmap < p_limit) ++p_bitmap;
	if (p_bitmap == p_limit) return (unsigned long) -1;
	
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	// while the test bit is unset...
	while (!(*p_bitmap & test_bit))
	{
		if (__builtin_expect(test_bit != 1ul<<(BITMAP_WORD_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap - p_initial_bitmap) * BITMAP_WORD_NBITS
			+ test_bit_index;
	
	if (out_test_bit) *out_test_bit = test_bit;
	return free_index;	
}
static inline unsigned long bitmap_find_first_clear_geq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	bitmap_word_t *p_initial_bitmap;
			
	while (*p_bitmap == (bitmap_word_t) -1
				&& p_bitmap < p_limit) ++p_bitmap;
	if (p_bitmap == p_limit) return (unsigned long) -1;
	
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	while (*p_bitmap & test_bit)
	{
		if (__builtin_expect(test_bit != 1ul<<(BITMAP_WORD_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap - p_initial_bitmap) * BITMAP_WORD_NBITS
			+ test_bit_index;
	
	if (out_test_bit) *out_test_bit = test_bit;
	return free_index;
}
static inline unsigned long bitmap_count_set_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit,
	unsigned long start_idx_ge, unsigned long end_idx_lt)
{
	if (end_idx_lt <= start_idx_ge) return 0;
	bitmap_word_t *p_startword = p_bitmap + (start_idx_ge / BITMAP_WORD_NBITS);
	bitmap_word_t *p_endword = p_bitmap + ((end_idx_lt + (BITMAP_WORD_NBITS-1) / BITMAP_WORD_NBITS));
	start_idx_ge %= BITMAP_WORD_NBITS;
	end_idx_lt %= BITMAP_WORD_NBITS;
	if (p_startword >= p_limit) return (unsigned long) -1;
	if (p_endword >= p_limit) return (unsigned long) -1;
	unsigned long count = 0;
	while (p_startword != p_endword)
	{
		unsigned long long word; // make it 64 bits so we can use popcount64
		// (FIXME: not on 32-bit platforms )
		if (start_idx_ge)
		{
			// only count the higher-addressed (most-significant) 
			// BITMAP_WORD_NBITS - start_idx_ge
			// bits.
			word = (*p_startword) >> (BITMAP_WORD_NBITS - start_idx_ge);
		} else word = *p_startword;
		count += popcount64(word);
		++p_startword;
		start_idx_ge = 0; // start from the beginning of the next word
	}
	// now just handle the last word. BEWARE: start_idx_ge may still be nonzero,
	// if our first word and last words are the same.
	// create a bitmask in which only bits [start_idx_ge, end_idx_lt) are set.
	unsigned long long word;
	unsigned nbits = end_idx_lt - start_idx_ge;
	if (nbits < BITMAP_WORD_NBITS)
	{
		bitmap_word_t bitmask = 
			/* set bottom bits up to our end idx */
			BOTTOM_N_BITS_SET_T(bitmap_word_t, end_idx_lt) & 
			/* set top bits down to our start idx */
			TOP_N_BITS_SET_T(bitmap_word_t, BITMAP_WORD_NBITS - start_idx_ge)
			/* ANDed together... */
			;
		word = *p_startword & bitmask;
	} else word = *p_startword;
	count += popcount64(word);
	return count;
}

#endif
