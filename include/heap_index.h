#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include <stdbool.h>
#include "pageindex.h"
#include "memtable.h"

#define entry_coverage_in_bytes 512
typedef struct entry entry_type;
extern void *index_begin_addr;
extern void *index_end_addr;

// #define IS_DEEP_ENTRY(e) (!(e)->present && (e)->removed && (e)->distance != 63)
#define IS_BIGALLOC_ENTRY(e) (!(e)->present && (e)->removed && (e)->distance == 63)
#define IS_EMPTY_ENTRY(e) (!(e)->present && !(e)->removed)

#define INDEX_LOC_FOR_ADDR(a) MEMTABLE_ADDR_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))
#define INDEX_BIN_START_ADDRESS_FOR_ADDR(a) MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))
#define INDEX_BIN_END_ADDRESS_FOR_ADDR(a) ((char*)(MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, ((char*)(a)))) + entry_coverage_in_bytes)
#define ADDR_FOR_INDEX_LOC(e) MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, index_begin_addr, index_end_addr, (e))

extern unsigned long biggest_unpromoted_object __attribute__((weak,visibility("protected")));
/* Inserts describing objects have user addresses. They may have the flag set or unset. */
#define INSERT_DESCRIBES_OBJECT(ins) \
	(!((ins)->alloc_site) || (char*)((uintptr_t)((unsigned long long)((ins)->alloc_site))) >= MINIMUM_USER_ADDRESS)
#define INSERT_IS_NULL(p_ins) (!(p_ins)->alloc_site && !(p_ins)->alloc_site_flag)

/* What's the most space that a malloc header will use? 
 * We use this figure to guess when an alloc has been satisfied with mmap().  
 * Making it too big hurts performance but not correctness. */
#define MAXIMUM_MALLOC_HEADER_OVERHEAD 16

#define DISTANCE_UNIT_SHIFT 3
/* NOTE: make sure that "distance" is wide enough to store offsets up to
 * entry_size_in_bytes bytes long! */

extern struct entry *index_region __attribute__((weak));
int safe_to_call_malloc __attribute__((weak));

struct allocator;
extern struct allocator __generic_malloc_allocator;
struct big_allocation;
struct big_allocation *__lookup_bigalloc(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));
struct insert *__lookup_bigalloc_with_insert(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));

struct insert *lookup_object_info(const void *mem, 
		void **out_object_start, size_t *out_object_size, 
		void **ignored) __attribute__((weak));

struct insert *__liballocs_insert_for_chunk_and_usable_size(void *userptr, size_t usable_size);
void __liballocs_index_delete(void *userptr);
void __liballocs_index_insert(void *new_userchunkaddr, size_t requested_size, const void *caller);

/* A thread-local variable to override the "caller" arguments. 
 * Platforms without TLS have to do without this feature. */
#ifndef NO_TLS
extern __thread void *__current_allocsite;
extern __thread void *__current_allocfn;
extern __thread size_t __current_allocsz;
extern __thread int __currently_freeing;
extern __thread int __currently_allocating;
#else
#warning "Using thread-unsafe __current_allocsite variable."
extern void *__current_allocsite;
extern void *__current_allocfn;
extern size_t __current_allocsz;
extern int __currently_freeing;
extern int __currently_allocating;
#endif

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
size_t malloc_usable_size(void *ptr);
static void *userptr_to_allocptr(void *userptr) { return userptr; }
static void *allocptr_to_userptr(void *allocptr) { return allocptr; }
static size_t allocsize_to_usersize(size_t usersize) { return usersize; }
static size_t usersize_to_allocsize(size_t allocsize) { return allocsize; }
static size_t usersize(void *userptr) { return allocsize_to_usersize(malloc_usable_size(userptr_to_allocptr(userptr))); }
static size_t allocsize(void *allocptr) { return malloc_usable_size(allocptr); }

#define LIFETIME_INSERT_TYPE uint8_t // TODO: Define it in configuration
typedef LIFETIME_INSERT_TYPE lifetime_insert_t;
#ifdef LIFETIME_INSERT_TYPE
#include <limits.h>
#define LIFETIME_POLICIES (CHAR_BIT * sizeof(lifetime_insert_t))
#define LIFETIME_POLICY_FLAG(id) (0x1 << (id))
// By convention lifetime policy 0 is the manual deallocation policy
#define MANUAL_DEALLOCATION_POLICY 0
#define MANUAL_DEALLOCATION_FLAG LIFETIME_POLICY_FLAG(MANUAL_DEALLOCATION_POLICY)
// Manual deallocation is not an "attached" policy
#define HAS_LIFETIME_POLICIES_ATTACHED(lti) ((lti) & ~(MANUAL_DEALLOCATION_FLAG))
#endif

struct extended_insert
{
#ifdef LIFETIME_POLICIES
	lifetime_insert_t lifetime;
#endif
	/* Include any padding inserted such that
	 * usable_size - insert_size = requested_size */
	uint8_t insert_size;
	/* The base insert is at the end because we want interoperabiliy between
	 * allocators using extended_insert and allocators only using insert.
	 * See insert_for_chunk. */
	struct insert base;
} __attribute__((packed)); // Alignment from the end guaranteed by ourselves

static inline struct insert *insert_for_chunk_and_usable_size(void *userptr, size_t usable_size)
{
	uintptr_t insertptr = (uintptr_t)((char*) userptr + usable_size -
			sizeof (struct insert));

#ifndef NDEBUG
	// Check alignment
	assert(insertptr % ALIGNOF(struct insert) == 0);
#endif

	return (struct insert*) insertptr;
}
static inline struct insert *insert_for_chunk(void *userptr)
{
	return insert_for_chunk_and_usable_size(userptr, malloc_usable_size(userptr));
}

static inline struct extended_insert *
extended_insert_for_chunk_and_usable_size(void *userptr, size_t usable_size)
{
	return (struct extended_insert *)((char*) userptr + usable_size -
			sizeof (struct extended_insert));
}
static inline struct extended_insert *extended_insert_for_chunk(void *userptr)
{
	return extended_insert_for_chunk_and_usable_size(userptr,
			malloc_usable_size(userptr));
}

static inline size_t requested_size_for_chunk(void *userptr, size_t usable_size)
{
	uint8_t insert_size = extended_insert_for_chunk_and_usable_size(userptr, usable_size)->insert_size;
	return usable_size - insert_size;
}

#ifdef LIFETIME_POLICIES
static inline lifetime_insert_t *lifetime_insert_for_chunk(void *userptr)
{
	return &extended_insert_for_chunk(userptr)->lifetime;
}
#endif

#endif
