#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include <stdbool.h>
#include "memtable.h"

struct entry
{
	unsigned present:1;
	unsigned removed:1;  /* whether this link is in the "removed" state in Harris's algorithm */
	unsigned distance:6; /* distance from the base of this entry's region, in 8-byte units */
} __attribute__((packed));
struct insert;

#define IS_DEEP_ENTRY(e) (!(e)->present && (e)->removed && (e)->distance != 63)
#define IS_L0_ENTRY(e) (!(e)->present && (e)->removed && (e)->distance == 63)
#define IS_EMPTY_ENTRY(e) (!(e)->present && !(e)->removed)

#define BIGGEST_SENSIBLE_OBJECT (256*1024*1024)
#define MINIMUM_USER_ADDRESS  ((char*)0x400000) /* FIXME: less {x86-64,GNU/Linux}-specific please */
#define MAX_SUBALLOCATED_CHUNKS ((unsigned long) MINIMUM_USER_ADDRESS)
#define INSERT_DESCRIBES_OBJECT(ins) \
	((char*)((uintptr_t)(ins)->alloc_site) >= MINIMUM_USER_ADDRESS)
#define INSERT_IS_SUBALLOC_CHAIN(ins) \
	(!(INSERT_DESCRIBES_OBJECT(ins)))
/* For ALLOC_IS_SUBALLOCATED, we try to check that `ptr' and `ins' are 
 * well-matched, i.e. ins is the physical l0 or l1 insert for the chunk
 * overlapping ptr. This is easy in the l1 case, but hard in the l0 case
 * since we don't implement the l0 index here. We have to call out to
 * __lookup_l0 to test this. */
static inline _Bool ALLOC_IS_SUBALLOCATED(const void *ptr, struct insert *ins);

#define IS_CONTINUATION_REC(ins) ((char*)((uintptr_t)(ins)->alloc_site) < MINIMUM_USER_ADDRESS && (ins)->alloc_site_flag)
#define MODULUS_OF_INSERT(ins) ((ins)->un.bits & 0xff)
#define THISBUCKET_SIZE_OF_INSERT(ins) (((ins)->un.bits >> 8) == 0 ? 256 : ((ins)->un.bits >> 8))

/* What's the most space that a malloc header will use? 
 * We use this figure to guess when an alloc has been satisfied with mmap().  
 * Making it too big hurts performance but not correctness. */
#define MAXIMUM_MALLOC_HEADER_OVERHEAD 16

#define DISTANCE_UNIT_SHIFT 3
/* NOTE: make sure that "distance" is wide enough to store offsets up to
 * entry_size_in_bytes bytes long! */

extern struct entry *index_region __attribute__((weak));
int safe_to_call_malloc __attribute__((weak));

#define WORD_BITSIZE ((sizeof (void*))<<3)
#if defined(__x86_64__) || defined(x86_64)
#define ADDR_BITSIZE 48
#else
#define ADDR_BITSIZE WORD_BITSIZE
#endif
struct ptrs 
{
	struct entry next;
	struct entry prev;
} __attribute__((packed));
struct insert
{
	unsigned alloc_site_flag:1;
	unsigned long alloc_site:(ADDR_BITSIZE-1);
#ifdef HEAP_INDEX_HEADER_INCLUDE
#include HEAP_INDEX_HEADER_INCLUDE
#endif
	union  __attribute__((packed))
	{
		struct ptrs ptrs;
		unsigned bits:16;
	} un;

} __attribute__((packed));

struct suballocated_chunk_rec
{
	struct insert higherlevel_ins;
	struct suballocated_chunk_rec *parent; // NULL except for level>2
	void *begin;
	size_t real_size;
	size_t size;
	struct insert *metadata_recs;
	char log_pitch;
	size_t one_layer_nbytes;
	unsigned long biggest_object;
};
int  __index_deep_alloc(void *ptr, int level, unsigned size_bytes) __attribute__((weak));
void __unindex_deep_alloc(void *ptr, int level) __attribute__((weak));

struct insert *lookup_object_info(const void *mem, void **out_object_start, size_t *out_object_size, struct suballocated_chunk_rec **out_containing_chunk) __attribute__((weak));

void *__try_index_l0(const void *, size_t modified_size, const void *caller) __attribute__((weak));
struct insert *__lookup_l0(const void *mem, void **out_object_start) __attribute__((weak));
unsigned __unindex_l0(const void *mem) __attribute__((weak));
static inline _Bool ALLOC_IS_SUBALLOCATED(const void *ptr, struct insert *ins)
{
	bool is_l0 = __lookup_l0 && __lookup_l0(ptr, NULL) == ins;
	bool is_sane_l01 = is_l0 || ((char*)(ins) - (char*)(ptr) >= 0
			&& (char*)(ins) - (char*)(ptr) < BIGGEST_SENSIBLE_OBJECT);
	return is_sane_l01 && ((char*)((uintptr_t)(ins)->alloc_site)) < MINIMUM_USER_ADDRESS;
}

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

#endif
