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

static inline size_t memtable_mapping_size(
	unsigned entry_size_in_bytes,
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end)
{
	/* NOTE: if addr_begin and addr_end are both zero, we use the full range. */
	/* HACK: we use "long double" because 80-bit precision avoids 
	 * overflow in the whole-address-space case. To do this with
	 * integer arithmetic, we would be trying to construct the number
	 * one bigger than the maximum representable unsigned 64-bit integer. */
	
	// void *test1 = (void*) -1;
	// unsigned long long test2 = (unsigned long long) test1;
	// long double test3 = test2 + 1;
	// assert((long double)(unsigned long long)(void*)-1 != 0);
	
	long double nbytes_covered = (addr_begin == 0 && addr_end == 0) ?
		(((long double)(unsigned long long)(void*)-1) + 1)
		: (char*)addr_end - (char*)addr_begin;
	long double nbytes_in_table = nbytes_covered / entry_coverage_in_bytes;
	return (size_t) nbytes_in_table;
}
#define MEMTABLE_MAPPING_SIZE_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_mapping_size(sizeof(t), (range), (addr_begin), (addr_end))

/* Allocate a memtable. */
static inline void *memtable_new(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end)
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
	void *addr_begin, void *addr_end,
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
	void *addr_begin, void *addr_end,
	void *addr
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
	void *addr_begin, void *addr_end, 
	void *memtable_entry_ptr
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
	void *addr_begin, void *addr_end, 
	void *addr
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
	void *addr_begin, void *addr_end, 
	void *addr)
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
	void *addr_begin, void *addr_end)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes, 
		entry_coverage_in_bytes, addr_begin, addr_end);
	return munmap(memtable, mapping_size);
}

#if defined(__cplusplus) || defined(c_plusplus)
} /* end extern "C" */
#endif

#endif
