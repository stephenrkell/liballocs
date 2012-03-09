#ifndef MEMTABLE_H_
#define MEMTABLE_H_

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#if defined (X86_64) || (defined (__x86_64__))
#define BIGGEST_MMAP_ALLOWED (1ULL<<46)
#else
#define BIGGEST_MMAP_ALLOWED (1ULL<<(((sizeof (void*))<<3)-2))
#warning "Guessing the maximum mmap() size for this architecture"
// go with 1/4 of the address space if we're not sure (x86-64 is special)
#endif

#include <assert.h>
/* #include <math.h> */
#include <sys/mman.h>
#include <stddef.h>

static inline int is_power_of_two(size_t i)
{
	/* If we are a power of two, then one less than us 
	 * has a run of low-order bits set and no others set,
	 * whereas we have a single (higher) bit set. So when
	 * we AND, we get zero. In all other (non-power-of-two)
	 * cases except zero, not all lower-order bits will
	 * roll over between i-1 and i, so there will be a nonzero
	 * AND. */
  	return (i != 0) && !(i & (i - 1));
}

static inline unsigned integer_log2(size_t i)
{
	unsigned count = 0;
	assert(i != 0);
	while ((i & 0x1) == 0) { ++count; i >>= 1; }
	assert(i == 1);
	return count;
}

static inline size_t memtable_mapping_size(
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

	unsigned range_size = (char*)addr_end - (char*)addr_begin;
	unsigned nentries = range_size == 0 ?
		/* divide AS size by coverage (in log space) */
		1<<( ((sizeof (void*))<<3) - log2_coverage ) :
		/* divide actual range size by coverage */
		(assert(range_size % entry_coverage_in_bytes == 0),
			range_size / entry_coverage_in_bytes);

	return (size_t) nentries * entry_size_in_bytes;
}
#define MEMTABLE_MAPPING_SIZE_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_mapping_size(sizeof(t), (range), (addr_begin), (addr_end))

/* Allocate a memtable. */
static inline void *memtable_new(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes,
		entry_coverage_in_bytes, addr_begin, addr_end);
	assert(mapping_size <= BIGGEST_MMAP_ALLOWED);
	void *ret = mmap(NULL, mapping_size, PROT_READ|PROT_WRITE, 
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	return ret; /* MAP_FAILED on error */
}
#define MEMTABLE_NEW_WITH_TYPE(t, range, addr_begin, addr_end) \
	(t*) memtable_new(sizeof(t), (range), (addr_begin), (addr_end))

/* Get a pointer to the index-th entry. */
static inline void *memtable_index(
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
static inline void *memtable_addr(
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
static inline void *memtable_entry_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *memtable_entry_ptr
)
{
	assert((char*)memtable_entry_ptr - (char*)memtable < memtable_mapping_size(
		entry_size_in_bytes, entry_coverage_in_bytes, addr_begin, addr_end));

	return ((char*)memtable_entry_ptr - (char*)memtable) / entry_size_in_bytes
		* entry_coverage_in_bytes
		+ (char*) addr_begin;
}
#define MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(m, t, range, addr_begin, addr_end, entry_ptr) \
	memtable_entry_range_base((m), sizeof (t), (range), \
		(addr_begin), (addr_end), (entry_ptr))

/* For an address, get the base address of the region that it belongs to,
 * where a region is the memory covered by exactly one memtable entry. */
static inline void *memtable_addr_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end, 
	const void *addr
)
{
	/* For robustness / testing, express in terms of previous two functions. 
	 * Should compile with -O2 or -O3 to get good code! */
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
static inline ptrdiff_t memtable_addr_range_offset(
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
static inline int memtable_free(void *memtable, 
 	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	const void *addr_begin, const void *addr_end)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes, 
		entry_coverage_in_bytes, addr_begin, addr_end);
	return munmap(memtable, mapping_size);
}

#if defined(__cplusplus) || defined(c_plusplus)
} /* end extern "C" */
#endif

#endif
