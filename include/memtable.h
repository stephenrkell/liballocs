#ifndef MEMTABLE_H_
#define MEMTABLE_H_

// for asprintf (among other things?)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#include <stdlib.h>

#if defined (X86_64) || (defined (__x86_64__))
#define BIGGEST_MMAP_ALLOWED (1ULL<<46)
#else
#define BIGGEST_MMAP_ALLOWED (1ULL<<(((sizeof (void*))<<3)-2))
#warning "Guessing the maximum mmap() size for this architecture"
// go with 1/4 of the address space if we're not sure (x86-64 is special)
#endif

#ifdef USE_SYSCALL_FOR_MMAP
#include <unistd.h>
#include <sys/syscall.h>
#define MEMTABLE_MMAP(addr, length, prot, flags, fd, offset) \
	(void*) syscall(__NR_mmap, (addr), (length), (prot), (flags), (fd), (offset))
#else
#define MEMTABLE_MMAP mmap
#endif

#include <assert.h>
/* #include <math.h> */
#include <sys/mman.h>
#include <stddef.h>

#include <stdio.h> /* for stats printing */
#include <unistd.h> /* for stats printing */

#include "bitops.h"

/* Some bitmap stuff. */
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
static inline unsigned long bitmap_rfind_first_set(unsigned long *p_bitmap, unsigned long *p_limit, long start_idx, unsigned long *out_test_bit)
{
	unsigned long *p_base = p_bitmap;
	p_bitmap += start_idx / UNSIGNED_LONG_NBITS;
	start_idx %= UNSIGNED_LONG_NBITS;
	// FIXME: the following shows why if we're optimising for rfind,
	// we should use the *most* significant bit as the *lowest*-indexed position in the word.
// 	if (*p_bitmap < (1ul<<start_idx))
// 	{
// 		/* The word has a value less than the query bit pattern, so
// 		 * it can't have the query bit or any higher bit set. */
// 	}
// 	else
// 	{
// 		/* The word has a value greater than or equal to the query bit pattern, so
// 		 * it may or may not have the query bit set. */
// 		
// 	}
	if (p_bitmap > p_limit) return (unsigned long) -1;
	while (1)
	{
		while (start_idx >= 0)
		{
			unsigned long test_bit = 1ul << start_idx;
			if (*p_bitmap & test_bit)
			{
				if (out_test_bit) *out_test_bit = test_bit;
				return start_idx + (p_bitmap - p_base) * UNSIGNED_LONG_NBITS;
			}
			--start_idx;
		}
		// now start_idx < 0
		if (p_bitmap == p_base) break;
		start_idx = UNSIGNED_LONG_NBITS - 1;
		--p_bitmap;
	}
	return (unsigned long) -1;
}
static inline unsigned long bitmap_find_first_set1(unsigned long *p_bitmap, unsigned long *p_limit, long start_idx, unsigned long *out_test_bit)
{
	unsigned long *p_base = p_bitmap;
	p_bitmap += start_idx / UNSIGNED_LONG_NBITS;
	start_idx %= UNSIGNED_LONG_NBITS;
	if (p_bitmap > p_limit) return (unsigned long) -1;
	while (1)
	{
		while (start_idx < UNSIGNED_LONG_NBITS)
		{
			unsigned long test_bit = 1ul << start_idx;
			if (*p_bitmap & test_bit)
			{
				if (out_test_bit) *out_test_bit = test_bit;
				return start_idx + (p_bitmap - p_base) * UNSIGNED_LONG_NBITS;
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

INLINE_DECL size_t memtable_mapping_size(
	unsigned entry_size_in_bytes,
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL size_t INLINE_ATTRS memtable_mapping_size(
	unsigned entry_size_in_bytes,
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	/* NOTE: if addr_begin and addr_end are both zero, it means 
	 * we use the full range. */

	/* Got rid of the "long double" hack. Instead, we insist that
         * entry_coverage_in_bytes is a power of two. */
	assert(is_power_of_two(entry_coverage_in_bytes));
	unsigned log2_coverage = integer_log2(entry_coverage_in_bytes);

	unsigned long long range_size = (char*)addr_end - (char*)addr_begin;
	unsigned full_as_size_shift = ((sizeof (void*))<<3);
	/* divide AS size by coverage (in log space) */
	unsigned full_as_nentries_shift = full_as_size_shift - log2_coverage;
	unsigned long long nentries = 0ULL;
	if (range_size == 0ULL) nentries = 1ULL<<full_as_nentries_shift;
	else
	{
		assert(range_size % entry_coverage_in_bytes == 0ULL);
		nentries = range_size / entry_coverage_in_bytes;
	}
	assert(nentries != 0ULL);

	return (size_t) nentries * entry_size_in_bytes;
}
#define MEMTABLE_MAPPING_SIZE_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_mapping_size(sizeof(t), (range), (addr_begin), (addr_end))

/* Allocate a memtable. */
INLINE_DECL void *memtable_new(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL void *memtable_new_at_addr(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end,
	const void *placement_addr) INLINE_ATTRS;

INLINE_DECL void *INLINE_ATTRS memtable_new(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	return memtable_new_at_addr(entry_size_in_bytes, 
		entry_coverage_in_bytes,
		addr_begin, addr_end,
		NULL);
}
INLINE_DECL void *INLINE_ATTRS memtable_new_at_addr(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end,
	const void *placement_addr)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes,
		entry_coverage_in_bytes, addr_begin, addr_end);
	assert(mapping_size <= BIGGEST_MMAP_ALLOWED);
	void *ret = MEMTABLE_MMAP((void*) placement_addr, mapping_size, PROT_READ|PROT_WRITE, 
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE|
			(placement_addr ? MAP_FIXED : 0), -1, 0);
	return ret; /* MAP_FAILED on error */
}
#define MEMTABLE_NEW_WITH_TYPE(t, range, addr_begin, addr_end) \
	(t*) memtable_new(sizeof(t), (range), (addr_begin), (addr_end))
#define MEMTABLE_NEW_WITH_TYPE_AT_ADDR(t, range, addr_begin, addr_end, placement_addr) \
	(t*) memtable_new_at_addr(sizeof(t), (range), (addr_begin), (addr_end), (placement_addr))

#if 0 /* FIXME: finish this */
/* Instead of page bitmaps, generalise to a "sparseness bitmap hierarchy" 
 * of user-defined branching factor. E.g. we might want one-bit-per-cacheline,
 * i.e. a branching factor of 2^9 for 64B cache lines,
 * meaning a 2^46-entry memtable (the biggest, 1B per entry) will be
 * a 2^37-bit l1 bitmap (16GB VAS),
 * a 2^28-bit l2 bitmap (32MB VAS), 
 * a 2^19-bit l3 bitmap (64KB VAS)
 * a 2^10-bit l4 bitmap (128 bytes -- probably not worth having)
 *
 * Then instead of MEMTABLE_ADDR, we want MEMTABLE_GET and MEMTABLE_SET
 * so that we can automatically maintain the bitmaps. */

/* Allocate a "page bitmap" for a memtable. */
INLINE_DECL char *memtable_new_l1_page_bitmap(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL char *INLINE_ATTRS memtable_new_l1_page_bitmap(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	size_t table_mapping_size = memtable_mapping_size(entry_size_in_bytes,
		entry_coverage_in_bytes, addr_begin, addr_end);
	assert(table_mapping_size <= BIGGEST_MMAP_ALLOWED);
	/* bitmap has one bit per PAGESIZE bytes, i.e. 
	 * one byte per PAGESIZE<<3 bytes. */
/* Q. How big is a bitmap for each page of a max-size memtable?
 * A. For a 1<<46 byte memtable, we have 1<<34 pages, each requiring
 *    1 bit, so we have 1<<31 bytes. This is still a very large bitmap. 
 *    On the other hand, mapping it all to the zero page might not use much.
 *    But traversing it is still a no-no.
 */
	size_t bitmap_mapping_size = table_mapping_size / (sysconf(_SC_PAGE_SIZE) << 3);
	void *ret = MEMTABLE_MMAP(NULL, bitmap_mapping_size, PROT_READ|PROT_WRITE, 
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	return (char*) ret; /* MAP_FAILED on error */
}
#define MEMTABLE_NEW_L1_PAGE_BITMAP_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_new_l1_page_bitmap(sizeof(t), (range), (addr_begin), (addr_end))

/* Allocate a "second-order page bitmap" for a memtable. */
INLINE_DECL char *memtable_new_l2_page_bitmap(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL char *INLINE_ATTRS memtable_new_l2_page_bitmap(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	size_t table_mapping_size = memtable_mapping_size(entry_size_in_bytes,
		entry_coverage_in_bytes, addr_begin, addr_end);
	assert(table_mapping_size <= BIGGEST_MMAP_ALLOWED);
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	size_t l1_bitmap_mapping_size = table_mapping_size / (page_size << 3);
	size_t l2_bitmap_mapping_size = l1_bitmap_mapping_size / (page_size << 3);
/* Q. How big is a l2 bitmap for each page of a max-size memtable?
 * A. For a 1<<46 byte memtable, this is 1<<16 bytes i.e. 64K.
 *    Traversing it is not great.
 *    For smaller memtables, this might be a nice size e.g. a few dozens of bytes.
 */
	void *ret = MEMTABLE_MMAP(NULL, l2_bitmap_mapping_size, PROT_READ|PROT_WRITE, 
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	return (char*) ret; /* MAP_FAILED on error */
}
#define MEMTABLE_NEW_L2_PAGE_BITMAP_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_new_l2_page_bitmap(sizeof(t), (range), (addr_begin), (addr_end))

/* The "third-order page bitmap" case: don't allocate, just return the size.
 * Will return zero for all but the biggest memtables. */
INLINE_DECL size_t memtable_l3_page_bitmap_size(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL size_t INLINE_ATTRS memtable_l3_page_bitmap_size(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	size_t table_mapping_size = memtable_mapping_size(entry_size_in_bytes,
		entry_coverage_in_bytes, addr_begin, addr_end);
	assert(table_mapping_size <= BIGGEST_MMAP_ALLOWED);
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	size_t l1_bitmap_mapping_size = table_mapping_size / (page_size << 3);
	size_t l2_bitmap_mapping_size = l1_bitmap_mapping_size / (page_size << 3);
	size_t l3_bitmap_mapping_size = l2_bitmap_mapping_size / (page_size << 3);
/* Q. How big is a l3 bitmap for each page of a max-size memtable?
 * A. For a 1<<46 byte memtable, this is 1<<1 bytes, i.e. 2 bytes. 
 *    This is a pretty tractable amount of data. The caller should
 *    use malloc. */
	return l3_bitmap_mapping_size;
}
#define MEMTABLE_L3_PAGE_BITMAP_SIZE_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_l3_page_bitmap_size(sizeof(t), (range), (addr_begin), (addr_end))

#endif

/* Get a pointer to the index-th entry. */
INLINE_DECL void *memtable_index(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end,
	unsigned long index
	) INLINE_ATTRS;
INLINE_DECL void *INLINE_ATTRS memtable_index(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end,
	unsigned long index
	)
{
	return (char*) memtable + (entry_size_in_bytes * index);
}
#define MEMTABLE_INDEX_WITH_TYPE(m, t, range, addr_begin, addr_end, index) \
	((t*) memtable_index((m), sizeof(t), (range), (addr_begin), (addr_end), (index)))

/* Get a pointer to the entry for address addr. */
INLINE_DECL void *memtable_addr(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end,
	const void *addr
	) INLINE_ATTRS;
INLINE_DECL void *INLINE_ATTRS memtable_addr(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end,
	const void *addr
	)
{
	assert(addr >= addr_begin && (addr_end == 0 || addr < addr_end));
	return memtable_index(memtable, entry_size_in_bytes, entry_coverage_in_bytes,
		addr_begin, addr_end, ((char*)addr - (char*)addr_begin) / entry_coverage_in_bytes);
}
#define MEMTABLE_ADDR_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	((t*) memtable_addr((m), sizeof(t), (range), (addr_begin), (addr_end), (addr)))

/* The inverse of memtable_addr: given a pointer into the table, get the pointer
 * to the base of the region to which the pointed-at entry corresponds. */
INLINE_DECL void *memtable_entry_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *memtable_entry_ptr
) INLINE_ATTRS;
INLINE_DECL void *INLINE_ATTRS memtable_entry_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *memtable_entry_ptr
)
{
	// Disabled this check because integer_log2 in memtable_mapping_size
	// is surprisingly costly. 
	//assert((char*)memtable_entry_ptr - (char*)memtable < memtable_mapping_size(
	//	entry_size_in_bytes, entry_coverage_in_bytes, addr_begin, addr_end));

	return ((char*)memtable_entry_ptr - (char*)memtable) / entry_size_in_bytes
		* entry_coverage_in_bytes
		+ (char*) addr_begin;
}
#define MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(m, t, range, addr_begin, addr_end, entry_ptr) \
	memtable_entry_range_base((m), sizeof (t), (range), \
		(addr_begin), (addr_end), (entry_ptr))

/* For an address, get the base address of the region that it belongs to,
 * where a region is the memory covered by exactly one memtable entry. */
INLINE_DECL void *memtable_addr_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *addr
) INLINE_ATTRS;
INLINE_DECL void *INLINE_ATTRS memtable_addr_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *addr
)
{
	/* For robustness / testing, express in terms of previous two functions. */
	return memtable_entry_range_base(
			memtable, entry_size_in_bytes, entry_coverage_in_bytes,
			addr_begin, addr_end,
			memtable_addr(
				memtable,
				entry_size_in_bytes, entry_coverage_in_bytes,
				addr_begin, addr_end,
				addr));
}
#define MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	memtable_addr_range_base((m), sizeof (t), (range), (addr_begin), (addr_end), \
		(addr))

/* Like above, but get the offset. */
INLINE_DECL ptrdiff_t memtable_addr_range_offset(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *addr) INLINE_ATTRS;
INLINE_DECL ptrdiff_t INLINE_ATTRS memtable_addr_range_offset(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *addr)
{
	return (char*)addr - (char*)memtable_addr_range_base(
		memtable, entry_size_in_bytes, entry_coverage_in_bytes,
		addr_begin, addr_end, addr);
}
#define MEMTABLE_ADDR_RANGE_OFFSET_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	memtable_addr_range_offset((m), sizeof (t), (range), (addr_begin), (addr_end), \
		(addr))

/* Delete a memtable. */
INLINE_DECL int memtable_free(void *memtable, 
 	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL int INLINE_ATTRS memtable_free(void *memtable, 
 	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes, 
		entry_coverage_in_bytes, addr_begin, addr_end);
	return munmap(memtable, mapping_size);
}
#define MEMTABLE_FREE_WITH_TYPE(m, t, range, addr_begin, addr_end) \
	memtable_free((m), sizeof (t), (range), (addr_begin), (addr_end))

/* Print memory usage statistics for this memtable. We get 
 * these by reading from /proc/$PID/smaps */
INLINE_DECL void print_memtable_stats(void *memtable, 
 	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end) INLINE_ATTRS;
INLINE_DECL void INLINE_ATTRS print_memtable_stats(void *memtable, 
 	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	char *smaps_command = NULL;
	int ret;
	ret = fprintf(stderr, "Memtable at %p has size %lu kB\n", 
		memtable, 
		(unsigned long)(memtable_mapping_size(
			entry_size_in_bytes, 
			entry_coverage_in_bytes, 
			addr_begin, addr_end)
		>>10)
	);
	assert(ret != -1); if (ret == -1) return;
	ret = asprintf(&smaps_command, "cat /proc/%d/smaps | grep -A14 \"^%08llx\" 1>&2", 
		getpid(), (unsigned long long) memtable);
	assert(ret != -1); if (ret == -1) return;
	assert(smaps_command); if (!smaps_command) return;
	
	ret = system(smaps_command);
	if (WEXITSTATUS(ret) != 0) fprintf(stderr, "system(\"%s\") failed.\n", smaps_command);
	
	free(smaps_command);
}
#define PRINT_MEMTABLE_STATS_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	print_memtable_stats((m), sizeof (t), (range), (addr_begin), (addr_end), \
		(addr))

#if defined(__cplusplus) || defined(c_plusplus)
} /* end extern "C" */
#endif

#undef INLINE_DECL
#undef INLINE_ATTRS

#endif
