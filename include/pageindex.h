#ifndef LIBALLOCS_PAGEINDEX_H_
#define LIBALLOCS_PAGEINDEX_H_

/* We maintain two structures:
 *
 * - a list of "big allocations";
 * - an index mapping from page numbers to
 *      the deepest big allocation that completely spans that page.
 *   (this was formerly called the "level 0 index", and only mapped to
 *    first-level allocations a.k.a. memory mappings).
 * 
 * Note that a suballocated chunk may still be small enough that it
 * doesn't span any whole pages. It will still have a bigalloc number.
 */

/* Since all indexed big allocations span some number of pages, 
 * we record the memory-mapping properties of those pages. */
typedef struct mapping_flags
{
	unsigned kind:4; // UNKNOWN, STACK, HEAP, STATIC, ...
	unsigned r:1;
	unsigned w:1;
	unsigned x:1;
} mapping_flags_t;
_Bool mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2);

/* Each big allocation has some metadata attached. The meaning of 
 * "insert" is down to the individual allocator. */
struct meta_info
{
	enum meta_info_kind { DATA_PTR, INS_AND_BITS } what;
	union
	{
		const void *data_ptr;
		struct 
		{
			struct insert ins;
			/* FIXME: document what these fields are for. I think it's when we 
			 * push malloc chunks' metadata down into the bigalloc metadata. */
			unsigned is_object_start:1;
			unsigned npages:20;
			unsigned obj_offset:7;
		} ins_and_bits;
	} un;
};

/* A "big allocation" is one that 
 * 
 * is suballocated from, or
 * spans at least BIG_ALLOC_THRESHOLD bytes of page-aligned memory. */
#define BIG_ALLOC_THRESHOLD (16*PAGE_SIZE)

struct big_allocation
{
	void *begin;
	void *end;
	struct big_allocation *parent;
	struct big_allocation *next_sib;
	struct big_allocation *prev_sib;
	struct big_allocation *first_child;
	struct mapping_flags f;
	/* PRIVATE i.e. change-prone impl details beyond here! */
	struct meta_info meta;
};
#define BIGALLOC_IN_USE(b) ((b)->begin && (b)->end)
extern struct big_allocation big_allocations[];

typedef uint16_t bigalloc_num_t;
bigalloc_num_t *pageindex __attribute__((visibility("hidden")));
extern _Bool initialized_maps;

/* FIXME: rename to __liballocs_ */
_Bool mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2);

void 
__liballocs_init_pageindex(void)
VIS(protected);

struct big_allocation *
bigalloc_add_l0(void *base, size_t s, mapping_flags_t f, const void *arg)
		__attribute__((visibility("hidden")));

void
bigalloc_add_l0_sloppy(void *base, size_t s, mapping_flags_t f, const void *arg)
__attribute__((visibility("hidden")));

struct big_allocation *
bigalloc_add_l0_full(void *base, size_t s, mapping_flags_t f, struct meta_info info)
__attribute__((visibility("hidden")));

void
bigalloc_del_l0(void *base, size_t s)
__attribute__((visibility("hidden")));

void
bigalloc_del(struct big_allocation *n)
__attribute__((visibility("hidden")));

int 
bigalloc_lookup_exact(struct big_allocation *n, void *begin, void *end)
__attribute__((visibility("hidden")));

size_t
bigalloc_get_overlapping_l0(unsigned short *out_begin, 
		size_t out_size, void *begin, void *end) 
__attribute__((visibility("hidden")));

// these ones are public, so use protected visibility
void __liballocs_add_missing_mappings_from_proc(void) VIS(protected);
enum object_memory_kind __liballocs_get_memory_kind(const void *obj) VIS(protected);;
void __liballocs_print_mappings_to_stream_err(void) VIS(protected);

// non-public helpers
_Bool 
insert_equal(struct insert *p_ins1, struct insert *p_ins2)
__attribute__((visibility("hidden")));
_Bool
bigalloc_meta_info_equal(mapping_flags_t f1, struct meta_info *meta1, mapping_flags_t f2, struct meta_info *meta2)
__attribute__((visibility("hidden")));
_Bool
bigalloc_data_ptr_equal(struct mapping_flags f, struct meta_info *meta, const char *data_ptr)
__attribute((visibility("hidden")));

struct big_allocation *
bigalloc_lookup_l0(void *base) __attribute__((visibility("hidden")));
struct big_allocation *
bigalloc_bounds_l0(const void *ptr, const void **begin, const void **end) __attribute__((visibility("hidden")));
int add_all_loaded_segments_cb(struct dl_phdr_info *info, size_t size, void *data) __attribute__((visibility("hidden")));

#define ROUND_DOWN_TO_PAGE_SIZE(n) \
	(assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE), ((n)>>LOG_PAGE_SIZE)<<LOG_PAGE_SIZE)
#define ROUND_UP_TO_PAGE_SIZE(n) \
	(assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE), (n) % PAGE_SIZE == 0 ? (n) : ((((n) >> LOG_PAGE_SIZE) + 1) << LOG_PAGE_SIZE))
// mappings over 4GB in size are assumed to be memtables and are ignored
#define BIGGEST_BIGALLOC (1ull<<32)

#define MAPPING_BASE_FROM_PHDR_VADDR(base_addr, vaddr) \
   (ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr)))
#define MAPPING_END_FROM_PHDR_VADDR(base_addr, vaddr, memsz) \
	(ROUND_UP_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr) + (memsz)))

/* We use these for PT_GNU_RELRO mappings. */
#define MAPPING_NEXT_PAGE_START_FROM_PHDR_BEGIN_VADDR(base_addr, vaddr) \
   (ROUND_UP_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr)))
#define MAPPING_PRECEDING_PAGE_START_FROM_PHDR_END_VADDR(base_addr, vaddr, memsz) \
	(ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr) + (memsz)))

/* The biggest virtual address that we might find in an executable image. */
#define BIGGEST_SANE_EXECUTABLE_VADDR  (1ull<<31)

#define PAGENUM(p) (((uintptr_t) (p)) >> LOG_PAGE_SIZE)
#define ADDR_OF_PAGENUM(p) ((const void *) ((p) << LOG_PAGE_SIZE))

inline _Bool can_be_leaf_bigalloc(void *alloc_start, void *alloc_end)
{
	return ((char*) ROUND_DOWN_TO_PAGE_SIZE((unsigned long) alloc_end)
			- (char*) ROUND_UP_TO_PAGE_SIZE((unsigned long) alloc_start))
	> BIG_ALLOC_THRESHOLD;
}


#endif
