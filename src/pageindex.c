#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <string.h>
#include <wchar.h>
#include "relf.h"
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
struct big_allocation big_allocations[NBIGALLOCS]; // NOTE: we *don't* use big_allocations[0]; the 0 byte means "empty"

#define SANITY_CHECK_BIGALLOC(b) \
	do { \
		if (BIGALLOC_IN_USE((b))) { \
			assert(pageindex[PAGENUM(((char*)(b)->begin)-1)] != ((b) - &big_allocations[0])); \
			assert(pageindex[PAGENUM((b)->end)] != ((b) - &big_allocations[0])); \
		} \
	} while (0)

bigalloc_num_t *pageindex __attribute__((visibility("hidden")));

static void memset_bigalloc(bigalloc_num_t *begin, bigalloc_num_t num, 
	bigalloc_num_t old_num, size_t n)
{
	assert(1ull<<(8*sizeof(bigalloc_num_t)) >= NBIGALLOCS - 1);
	assert(sizeof (wchar_t) == 2 * sizeof (bigalloc_num_t));

	/* We use wmemset with special cases at the beginning and end */
	if (n > 0 && (uintptr_t) begin % sizeof (wchar_t) != 0)
	{
#ifndef NDEBUG
		if (old_num != (bigalloc_num_t) -1 && *begin != old_num) abort();
#endif
		*begin++ = num;
		--n;
	}
	assert(n == 0 || (uintptr_t) begin % sizeof (wchar_t) == 0);
	
	// double up the value
	wchar_t wchar_val     = ((wchar_t) num)     << (8 * sizeof(bigalloc_num_t)) | num;
	wchar_t wchar_old_val = ((wchar_t) old_num) << (8 * sizeof(bigalloc_num_t)) | old_num;
	
	// do the memset
	wchar_t accept[] = { wchar_old_val, '\0' };
#ifndef NDEBUG
	ssize_t max_len = (ssize_t) -1;
	if (old_num != (bigalloc_num_t) -1) max_len = wcsspn((wchar_t *) begin, accept);
	if (max_len < n/2) abort();
#endif
	if (n != 0) wmemset((wchar_t *) begin, wchar_val, n / 2);
	
	// if we missed one off the end, do it now
	if (n % 2 == 1)
	{
#ifndef NDEBUG
		if (old_num != (bigalloc_num_t) -1 && *(begin + (n-1)) != old_num) abort();
#endif
		*(begin + (n-1)) = num;
	}
}

static void (__attribute__((constructor(101))) init)(void)
{
	sleep(10);
	if (!pageindex)
	{
		/* Mmap our region. We map one 16-bit number for every page in the user address region. */
		pageindex = MEMTABLE_NEW_WITH_TYPE(bigalloc_num_t, PAGE_SIZE, (void*) 0, (void*) (MAXIMUM_USER_ADDRESS + 1));
		if (pageindex == MAP_FAILED) abort();
	}
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

static void check_page_size(void) __attribute__((constructor));
static void check_page_size(void)
{
	sleep(10);
	if (PAGE_SIZE != sysconf(_SC_PAGE_SIZE)) abort();
}

static _Bool path_is_realpath(const char *path)
{
	const char *rp = realpath_quick(path);
	return 0 == strcmp(path, rp);
}

static void clear_bigalloc_nomemset(struct big_allocation *b)
{
	b->begin = b->end = NULL;
}
static void clear_bigalloc(struct big_allocation *b)
{
	clear_bigalloc_nomemset(b);
	memset(&b->meta, 0, sizeof b->meta);
}

static void bigalloc_del(struct big_allocation *b) __attribute__((visibility("hidden")));
static void bigalloc_del(struct big_allocation *b)
{
	/* Recursively delete all children. */
	for (struct big_allocation *p_child = b->first_child; p_child; p_child = p_child->next_sib)
	{
		bigalloc_del(p_child);
	}
	
	/* Delete the user metadata, if the user told us we need to. */
	if (b->meta.what == DATA_PTR && b->meta.un.opaque_data.free_func)
	{
		b->meta.un.opaque_data.free_func(b->meta.un.opaque_data.data_ptr);
	}
	struct big_allocation *parent = b->parent;
	bigalloc_num_t parent_num = parent ? parent - &big_allocations[0] : 0;
	clear_bigalloc_nomemset(b);
	memset_bigalloc(
		pageindex + PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)),
		parent_num, (bigalloc_num_t) -1, 
		PAGENUM(ROUND_DOWN((unsigned long) b->end, PAGE_SIZE))
			 - PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE))
	);
	
	assert(!BIGALLOC_IN_USE(b));
}

struct allocator *__liballocs_get_allocator_upper_bound(const void *obj) __attribute__((visibility("protected")));
struct allocator *__liballocs_get_allocator_upper_bound(const void *obj)
{
	struct big_allocation *alloc = __liballocs_get_bigalloc_containing(obj);
	if (alloc) return alloc->allocated_by;
	else return NULL;
}

void __liballocs_print_l0_to_stream_err(void) __attribute__((visibility("protected")));
void __liballocs_print_l0_to_stream_err(void)
{
	int lock_ret;
	BIG_LOCK
			
	if (!pageindex) init();
	for (struct big_allocation *b = &big_allocations[1]; b < &big_allocations[NBIGALLOCS]; ++b)
	{
		if (BIGALLOC_IN_USE(b) && !b->parent) fprintf(stream_err, "%p-%p %s %s %p\n", 
				b->begin, b->end, b->allocated_by->name, 
				b->meta.what == DATA_PTR ? "(data ptr) " : "(insert + bits) ", 
				b->meta.what == DATA_PTR ? b->meta.un.opaque_data.data_ptr : (void*)(uintptr_t) b->meta.un.ins_and_bits.ins.alloc_site);
	}
	
	BIG_UNLOCK
}

static struct big_allocation *get_common_parent_bigalloc(const void *ptr, const void *end);

struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size, struct meta_info meta, struct big_allocation *maybe_parent, struct allocator *a) __attribute__((visibility("hidden")));
struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size, struct meta_info meta, struct big_allocation *maybe_parent, struct allocator *a)
{
	/* We get called from heap_index when the malloc'd address is a multiple of the 
	 * page size, is big enough and fills (more-or-less) the alloc'd region. If so,  
	 * create a bigalloc record including the caller-supplied metadata. We will fish 
	 * it out in get_alloc_info. */
	int lock_ret;
	BIG_LOCK
	
	__liballocs_ensure_init();
	char *chunk_end = (char*) ptr + size;

	// ensure we have the parent entry
	struct big_allocation *parent = get_common_parent_bigalloc(ptr, chunk_end);
	if (!parent) abort();
	
	/* Grab a new bigalloc. */
	bigalloc_num_t parent_num = parent - &big_allocations[0];
	struct big_allocation *b = find_free_bigalloc();
	if (b)
	{
		*b = (struct big_allocation) {
			.begin = (void*) ptr,
			.end = (char*) ptr + size, 
			.parent = parent,
				/* Do we have any sibling bigallocs? 
				 * These are bigallocs allocated by the same allocator
				 * out of the same chunk. For now, assume no. FIXME. */
			.meta = meta,
			.allocated_by = a
		};
		SANITY_CHECK_BIGALLOC(b);
		
		/* For each page that this alloc spans, memset it in the page index. */
		memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)),
			b - &big_allocations[0], parent_num, 
				PAGENUM(ROUND_DOWN((unsigned long) b->end, PAGE_SIZE))
				 - PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)));
	}

	BIG_UNLOCK
	return b;
}

_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end) __attribute__((visibility("protected")));
_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end)
{
	int lock_ret;
	BIG_LOCK
	const void *old_end = b->end;
	b->end = (void*) new_end;
	bigalloc_num_t parent_num = b->parent ? b->parent - &big_allocations[0] : 0;
	
	/* For each page that this alloc spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_DOWN((unsigned long) old_end, PAGE_SIZE)),
		b - &big_allocations[0], parent_num,
			PAGENUM(ROUND_DOWN((unsigned long) new_end, PAGE_SIZE))
			 - PAGENUM(ROUND_DOWN((unsigned long) old_end, PAGE_SIZE)));
	
	BIG_UNLOCK
	return 1;
}

static struct big_allocation *find_bigalloc_recursive(struct big_allocation *start, 
	const void *addr, struct allocator *a)
{
	/* Is it this one? */
	if (start->allocated_by == a) return start;
	
	/* Okay, it's not this one. Is it one of the children? */
	for (struct big_allocation *child = start->first_child;
			child;
			child = child->next_sib)
	{
		if ((char*) child->begin <= (char*) addr && 
				child->end > addr)
		{
			/* okay, tail-recurse down here */
			return find_bigalloc_recursive(child, addr, a);
		}
	}
	
	/* We didn't find an overlapping child, so we fail. */
	return NULL;
}

static struct big_allocation *find_bigalloc(const void *addr, struct allocator *a)
{
	bigalloc_num_t start_idx = pageindex[PAGENUM(addr)];
	/* We should always have something at level0 spanning the whole page. */
	if (start_idx == 0) abort();
	return find_bigalloc_recursive(&big_allocations[start_idx], addr, a);
}

static struct big_allocation *find_deepest_bigalloc_recursive(struct big_allocation *start, 
	const void *addr)
{
	/* Is it one of the children? */
	for (struct big_allocation *child = start->first_child;
			child;
			child = child->next_sib)
	{
		if ((char*) child->begin <= (char*) addr && 
				child->end > addr)
		{
			/* Recurse down here */
			struct big_allocation *maybe_deeper = find_deepest_bigalloc_recursive(child, addr);
			if (maybe_deeper) return maybe_deeper;
		}
	}
	
	/* We didn't find an overlapping child, so start is the best we can do. */
	return start;
}

static struct big_allocation *find_deepest_bigalloc(const void *addr)
{
	bigalloc_num_t start_idx = pageindex[PAGENUM(addr)];
	if (start_idx == 0) abort();
	return find_deepest_bigalloc_recursive(&big_allocations[start_idx], addr);
}

_Bool __liballocs_delete_bigalloc(const void *begin, struct allocator *a) __attribute__((visibility("hidden")));
_Bool __liballocs_delete_bigalloc(const void *begin, struct allocator *a)
{
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *b = find_bigalloc(begin, a);
	if (!b) { BIG_UNLOCK; return 0; }
	bigalloc_del(b);
	memset_bigalloc(
		pageindex + PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)),
		b->parent ? b->parent - &big_allocations[0] : 0, (bigalloc_num_t) -1, 
		PAGENUM(ROUND_DOWN((unsigned long) b->end, PAGE_SIZE))
			 - PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE))
	);
	BIG_UNLOCK;
	return 1;
}

struct big_allocation *__lookup_bigalloc(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_bigalloc(const void *mem, struct allocator *a, void **out_object_start)
{
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *b = find_bigalloc(mem, a);
	if (b)
	{
		BIG_UNLOCK
		return b;
	}
	else
	{
		BIG_UNLOCK
		return NULL;
	}
}

struct insert *__lookup_bigalloc_with_insert(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));
struct insert *__lookup_bigalloc_with_insert(const void *mem, struct allocator *a, void **out_object_start)
{
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *b = find_bigalloc(mem, a);
	if (b && b->meta.what == INS_AND_BITS)
	{
		if (out_object_start) *out_object_start = b->begin;
		BIG_UNLOCK
		return &b->meta.un.ins_and_bits.ins;
	}
	else
	{
		BIG_UNLOCK
		return NULL;
	}
}

struct big_allocation *__lookup_bigalloc_top_level(const void *mem) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_bigalloc_top_level(const void *mem)
{
	int lock_ret;
	BIG_LOCK
	struct big_allocation *b = find_deepest_bigalloc(mem);
	BIG_UNLOCK
	while (b->parent) b = b->parent;
	return b;
}

struct allocator *__lookup_top_level_allocator(const void *mem) __attribute__((visibility("hidden")));
struct allocator *__lookup_top_level_allocator(const void *mem)
{
	struct big_allocation *b = __lookup_bigalloc_top_level(mem);
	if (!b) return NULL;
	else return b->allocated_by;
}

static struct big_allocation *get_common_parent_bigalloc_recursive(struct big_allocation *b1,
	unsigned depth1, struct big_allocation *b2, unsigned depth2)
{
	/* success case */
	if (b1 == b2) return b1;
	if (depth1 == 0 || depth2 == 0)
	{
		/* ran out of levels -- we fail */
		return NULL;
	}
	if (depth1 > depth2) return get_common_parent_bigalloc_recursive(
		b1->parent, depth1 - 1, b2, depth2 - 1);
	else return get_common_parent_bigalloc_recursive(
		b1, depth1, b2->parent, depth2 - 1);
}

static struct big_allocation *get_common_parent_bigalloc(const void *ptr, const void *end)
{
	struct big_allocation *b1 = find_deepest_bigalloc(ptr);
	struct big_allocation *b2 = find_deepest_bigalloc(end);
	unsigned depth1 = 0; 
	for (struct big_allocation *tmp = b1; tmp; tmp = tmp->parent) ++depth1;
	unsigned depth2 = 0; 
	for (struct big_allocation *tmp = b2; tmp; tmp = tmp->parent) ++depth2;
	return get_common_parent_bigalloc_recursive(b1, depth1, b2, depth2);
}

_Bool __liballocs_notify_unindexed_address(const void *ptr)
{
	/* We get called if the caller finds an address that's not indexed anywhere. 
	 * It's a way of asking us to check. 
	 * We ask all our allocators in turn whether they own this address.
	 * Only stack and sbrk are expected to reply positively, so we put them
	 * at the top. */
	_Bool ret = __stack_allocator_notify_unindexed_address(ptr);
	if (ret) return 1;
	ret = __sbrk_allocator_notify_unindexed_address(ptr);
	if (ret) return 1;
	// FIXME: loop through the others
	return 0;
}
