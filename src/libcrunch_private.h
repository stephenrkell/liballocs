#ifndef LIBCRUNCH_PRIVATE_H_
#define LIBCRUNCH_PRIVATE_H_

/* x86_64 only, for now */
#if !defined(__x86_64__) && !defined(X86_64)
#error Unsupported architecture.
#endif

#include "memtable.h"
#include "heap_index.h"
#include "allocsmt.h"
#include <stdint.h>
#include "addrmap.h"

#include "libcrunch.h"

extern uintptr_t page_size __attribute__((visibility("protected")));
extern uintptr_t log_page_size __attribute__((visibility("protected")));
extern uintptr_t page_mask __attribute__((visibility("protected")));

/* We use this prefix tree to map the address space. */
enum node_info_kind { DATA_PTR, INS_AND_BITS };
struct node_info
{
	enum node_info_kind what;
	union
	{
		const void *data_ptr;
		struct 
		{
			struct insert ins;
			unsigned is_object_start:1;
			unsigned npages:20;
			unsigned obj_offset:7;
		} ins_and_bits;
	} un;
};
extern unsigned char *l0index __attribute__((visibility("protected")));
extern _Bool initialized_maps __attribute__((visibility("protected")));
struct prefix_tree_node {
	unsigned kind:4; // UNKNOWN, STACK, HEAP, STATIC
	struct node_info info;
};
struct prefix_tree_node *prefix_tree_add(void *base, size_t s, unsigned kind, const void *arg);
void prefix_tree_add_sloppy(void *base, size_t s, unsigned kind, const void *arg);
struct prefix_tree_node *prefix_tree_add_full(void *base, size_t s, unsigned kind, struct node_info *arg);
void prefix_tree_del(void *base, size_t s);
void init_prefix_tree_from_maps(void);
void prefix_tree_add_missing_maps(void);
enum object_memory_kind prefix_tree_get_memory_kind(const void *obj);
void prefix_tree_print_all_to_stderr(void);
struct prefix_tree_node *
prefix_tree_deepest_match_from_root(void *base, struct prefix_tree_node ***out_prev_ptr);
struct prefix_tree_node *
prefix_tree_bounds(const void *ptr, const void **begin, const void **end);
void __libcrunch_scan_lazy_typenames(void *handle);
int __libcrunch_add_all_mappings_cb(struct dl_phdr_info *info, size_t size, void *data);
#define debug_printf(lvl, ...) do { \
    if ((lvl) <= __libcrunch_debug_level) { \
      warnx( __VA_ARGS__ );  \
    } \
  } while (0)
extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks

/* Copied from dumptypes.cpp */
struct rec
{
	const char *name;
	short pos_maxoff; // 16 bits
	short neg_maxoff; // 16 bits
	unsigned nmemb:12;         // 12 bits -- number of `contained's (always 1 if array)
	unsigned is_array:1;       // 1 bit
	unsigned array_len:19;     // 19 bits; 0 means undetermined length
	struct { 
		signed offset;
		struct rec *ptr;
	} contained[];
};

static inline struct rec *allocsite_to_uniqtype(const void *allocsite)
{
	assert(__libcrunch_allocsmt != NULL);
	struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, allocsite);
	struct allocsite_entry *bucket = *bucketpos;
	for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
	{
		if (p->allocsite == allocsite)
		{
			return p->uniqtype;
		}
	}
	return NULL;
}

#define maximum_vaddr_range_size (4*1024) // HACK
static inline struct rec *vaddr_to_uniqtype(const void *vaddr)
{
	assert(__libcrunch_allocsmt != NULL);
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)vaddr | STACK_BEGIN));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= vaddr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > vaddr))
			{
				return p->uniqtype;
			}
			might_start_in_lower_bucket &= (p->allocsite > vaddr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_vaddr_range_size);
	return NULL;
}
#undef maximum_vaddr_range_size

#define maximum_static_obj_size (64*1024) // HACK
static inline struct rec *static_addr_to_uniqtype(const void *static_addr, void **out_object_start)
{
	assert(__libcrunch_allocsmt != NULL);
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)static_addr | (STACK_BEGIN<<1)));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= static_addr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > static_addr)) 
			{
				if (out_object_start) *out_object_start = p->allocsite;
				return p->uniqtype;
			}
			might_start_in_lower_bucket &= (p->allocsite > static_addr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_static_obj_size);
	return NULL;
}
#undef maximum_vaddr_range_size

/* avoid dependency on libc headers (in this header only) */
void __assert_fail(const char *assertion, 
	const char *file, unsigned int line, const char *function);
void warnx(const char *fmt, ...);
unsigned long malloc_usable_size (void *ptr);

/* counters */
extern unsigned long __libcrunch_begun;
#ifdef LIBCRUNCH_EXTENDED_COUNTS
extern unsigned long __libcrunch_aborted_init;
extern unsigned long __libcrunch_trivially_succeeded_null;
#endif
extern unsigned long __libcrunch_aborted_stack;
extern unsigned long __libcrunch_aborted_static;
extern unsigned long __libcrunch_aborted_typestr;
extern unsigned long __libcrunch_aborted_unknown_storage;
extern unsigned long __libcrunch_hit_heap_case;
extern unsigned long __libcrunch_hit_stack_case;
extern unsigned long __libcrunch_hit_static_case;
extern unsigned long __libcrunch_aborted_unindexed_heap;
extern unsigned long __libcrunch_lazy_heap_type_assignment;
extern unsigned long __libcrunch_aborted_unrecognised_allocsite;
extern unsigned long __libcrunch_failed;
extern unsigned long __libcrunch_failed_in_alloc;
extern unsigned long __libcrunch_succeeded;

#endif
