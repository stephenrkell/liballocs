#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <string.h>
#include <wchar.h>
#include "relf.h"
#include "liballocs_private.h"
#include "raw-syscalls.h"

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

/* Instantiate some inlines. */
extern struct allocator *__liballocs_leaf_allocator_for(const void *obj, 
	struct big_allocation **out_containing_bigalloc,
	struct big_allocation **out_maybe_the_allocation);
extern struct big_allocation *__liballocs_get_bigalloc_containing(const void *obj);

/* How many big allocs? 256 is a bit stingy. 
 * Each bigalloc record is 48--64 bytes, so 4096 of them would take 256KB.
 * Maybe stick to 1024? */
struct big_allocation big_allocations[NBIGALLOCS]; // NOTE: we *don't* use big_allocations[0]; the 0 byte means "empty"

static unsigned bigalloc_depth(struct big_allocation *b)
{
	unsigned depth = 0;
	for (struct big_allocation *tmp = b; tmp; tmp = tmp->parent) ++depth;
	return depth;
}

void sanity_check_bigalloc(struct big_allocation *b) __attribute__((visibility("hidden")));
void __liballocs_sanity_check_bigalloc(struct big_allocation *b) __attribute__((visibility("protected"),alias("sanity_check_bigalloc")));
void sanity_check_bigalloc(struct big_allocation *b)
{
#ifndef NDEBUG
	if (BIGALLOC_IN_USE(b))
	{
		assert(pageindex[PAGENUM(((char*)(b)->begin)-1)] != ((b) - &big_allocations[0]));
		assert(pageindex[PAGENUM((b)->end)] != ((b) - &big_allocations[0]));
		
		/* Check that our depth is 1 + our parent's depth */
		if (b->parent)
		{
			assert(bigalloc_depth(b) == 1 + bigalloc_depth(b->parent));
			/* Also check bounds w.r.t. parent. */
			assert(b->begin >= b->parent->begin);
			assert(b->end <= b->parent->end);
		}
		/* Check that old children all have the same depth as each other. */
		if (b->first_child)
		{
			unsigned first_child_depth = bigalloc_depth(b->first_child);
			for (struct big_allocation *child = b->first_child->next_sib; child; child = child->next_sib)
			{
				assert(bigalloc_depth(child) == first_child_depth);
				/* Also recursively sanity-check children. */
				sanity_check_bigalloc(child);
			}
		}
	}
#endif
}
#define SANITY_CHECK_BIGALLOC(b) sanity_check_bigalloc((b)) 

bigalloc_num_t *pageindex __attribute__((visibility("protected")));

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
	// PROBLEM: if our accept val is 0, 
#ifndef NDEBUG
	ssize_t max_len = (ssize_t) -1;
	if (old_num != (bigalloc_num_t) -1 && old_num) // FIXME: also check when old_num is zero
	{
		max_len = wcsspn((wchar_t *) begin, accept);
		if (max_len < n/2) abort();
	}
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
	if (!pageindex)
	{
		write_string("liballocs: process name ");
		raw_write(2, get_exe_basename(), strlen(get_exe_basename()));
		write_string(", pid ");
		int pid = raw_getpid();
		char a;
		_Bool seen_nonzero = 0;
#define CHAR_TO_PRINT(ord) ( ((pid/(ord)) % 10) ? \
        (seen_nonzero |= 1, '0' + ((pid/(ord)) % 10)) : \
		(seen_nonzero ? '0' : ' '))
		a = CHAR_TO_PRINT(10000); if (a != ' ') raw_write(2, &a, 1);
		a = CHAR_TO_PRINT(1000); if (a != ' ') raw_write(2, &a, 1);
		a = CHAR_TO_PRINT(100); if (a != ' ') raw_write(2, &a, 1);
		a = CHAR_TO_PRINT(10); if (a != ' ') raw_write(2, &a, 1);
		a = CHAR_TO_PRINT(1); raw_write(2, &a, 1);
		raw_write(2, "\n", 1);
#undef CHAR_TO_PRINT
		/* Mmap our region. We map one 16-bit number for every page in the user address region. */
		/* HACK: always place at 0x410000000000, to avoid problems with shadow space.
		 * The generic malloc index goes at 0x400000000000 
		 *          and is 2 ** 38 bytes or   0x4000000000 in size
		 *          but we don't want to assume too much about its size.
		 */
		pageindex = MEMTABLE_NEW_WITH_TYPE_AT_ADDR(bigalloc_num_t, PAGE_SIZE, (void*) 0,
			(void*) (MAXIMUM_USER_ADDRESS + 1), (const void *) 0x410000000000ul);
		if (pageindex == MAP_FAILED) abort();
		debug_printf(3, "pageindex at %p\n", pageindex);
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

_Bool __pages_unused(void *begin, void *end)
{
	return is_unindexed(begin, end);
}


static void check_page_size(void) __attribute__((constructor));
static void check_page_size(void)
{
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

static void add_child(struct big_allocation *child, struct big_allocation *parent)
{
	SANITY_CHECK_BIGALLOC(parent);
	assert(!child->parent);
	child->parent = parent;
	/* Hook it into the new list, at the head. FIXME: keep sorted? */
	struct big_allocation *previous_first_child = parent->first_child;
	parent->first_child = child;
	assert(!child->next_sib);
	child->next_sib = previous_first_child;
	assert(!previous_first_child || !previous_first_child->prev_sib);
	if (previous_first_child) previous_first_child->prev_sib = child;
	assert(!child->prev_sib);
	SANITY_CHECK_BIGALLOC(child);
	SANITY_CHECK_BIGALLOC(parent);
}

static void unlink_child(struct big_allocation *child)
{
	struct big_allocation *parent = child->parent;
	if (!parent) abort();
	SANITY_CHECK_BIGALLOC(child);
	SANITY_CHECK_BIGALLOC(parent);
	/* Unhook it from its current list. */
	if (child == parent->first_child)
	{
		parent->first_child = child->next_sib;
		assert(!child->prev_sib);
	}
	else
	{
		assert(child->prev_sib);
	}
	if (child->prev_sib) child->prev_sib->next_sib = child->next_sib;
	if (child->next_sib) child->next_sib->prev_sib = child->prev_sib;
	child->prev_sib = NULL;
	child->next_sib = NULL;
	child->parent = NULL;
	SANITY_CHECK_BIGALLOC(parent);
}
#define PAGE_DIST(first, second) \
( (PAGENUM((second)) > \
    PAGENUM((first))) ? \
	(PAGENUM((second)) - PAGENUM((first))) \
	: 0 )

static struct big_allocation *find_deepest_bigalloc(const void *addr);

static void bigalloc_del(struct big_allocation *b)
{
	SANITY_CHECK_BIGALLOC(b);
	
	/* Recursively delete all children. */
	struct big_allocation *child = b->first_child;
	while (child)
	{
		struct big_allocation *next_child = child->next_sib;
		bigalloc_del(child);
		child = next_child;
	}
	
	/* Delete the user metadata, if the user told us we need to. */
	if (b->meta.what == DATA_PTR && b->meta.un.opaque_data.free_func)
	{
		b->meta.un.opaque_data.free_func(b->meta.un.opaque_data.data_ptr);
	}
	struct big_allocation *parent = b->parent;
	if (parent) unlink_child(b);
	
	SANITY_CHECK_BIGALLOC(b);
	
	bigalloc_num_t parent_num = parent ? parent - &big_allocations[0] : 0;
	clear_bigalloc_nomemset(b);
	memset_bigalloc(
		pageindex + PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)),
		parent_num, (bigalloc_num_t) -1, 
		PAGE_DIST(ROUND_UP((unsigned long) b->begin, PAGE_SIZE),
		          ROUND_DOWN((unsigned long) b->end, PAGE_SIZE))
	);
	
	assert(!BIGALLOC_IN_USE(b));
}

struct allocator *__liballocs_get_allocator_upper_bound(const void *obj) __attribute__((visibility("protected")));
struct allocator *__liballocs_get_allocator_upper_bound(const void *obj)
{
	if (!pageindex) init();
	struct big_allocation *b = __liballocs_get_bigalloc_containing(obj);
	if (b) return b->allocated_by;
	else return NULL;
}
struct allocator *__liballocs_ool_get_allocator(const void *obj) __attribute__((visibility("protected")));
struct allocator *__liballocs_ool_get_allocator(const void *obj)
{
	return __liballocs_leaf_allocator_for(obj, NULL, NULL);
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

void __liballocs_report_wild_address(const void *ptr)
{
	if (ROUND_DOWN_PTR(ptr, PAGE_SIZE) == 0
			|| ROUND_UP_PTR(ptr, PAGE_SIZE) == 0)
	{
		/* suppress it if it's in the first or last pages,
		 * since some programs use these values quasi-legitimately. */
	}
	else
	{
		fprintf(stream_err, "*** saw wild pointer %p\n", ptr);
		__liballocs_print_l0_to_stream_err();
	}
}

static struct big_allocation *get_common_parent_bigalloc(const void *ptr, const void *end);
static struct big_allocation *bigalloc_new(const void *ptr, size_t size, struct big_allocation *parent, 
	struct meta_info meta, struct allocator *allocated_by);

struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size, struct meta_info meta, struct big_allocation *maybe_parent, struct allocator *allocated_by) __attribute__((visibility("hidden")));
struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size, struct meta_info meta, struct big_allocation *maybe_parent, struct allocator *allocated_by)
{
	/* We get called from heap_index when the malloc'd address is a multiple of the 
	 * page size, is big enough and fills (more-or-less) the alloc'd region. If so,  
	 * create a bigalloc record including the caller-supplied metadata. We will fish 
	 * it out in get_alloc_info. */
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	
	char *chunk_lastbyte = (char*) ptr + size - 1;
	if (size > BIGGEST_SANE_USER_ALLOC) 
	{
		write_string("Internal error: requested insanely big big allocation\n");
		abort();
	}

	// ensure we have the parent entry
	struct big_allocation *parent = NULL;
	if (maybe_parent) parent = maybe_parent;
	else 
	{
		// struct big_allocation *possible_parent = get_common_parent_bigalloc(ptr, chunk_lastbyte);
		struct big_allocation *deepest_at_start = find_deepest_bigalloc(ptr);
		struct big_allocation *deepest_at_end = find_deepest_bigalloc(chunk_lastbyte);
		
		/* These should all be equal. */
		if (deepest_at_start != deepest_at_end)
		{
			write_string("Internal error: requested big allocation not well nested\n");
			write_string("Created begin: ");
			write_ulong((unsigned long) ptr);
			write_string("\nCreated end: ");
			write_ulong((unsigned long) ((char*)ptr + size));
			if (deepest_at_start)
			{
				write_string("\nStart deepest existing begin: ");
				write_ulong((unsigned long) deepest_at_start->begin);
				write_string("\nStart deepest existing end: ");
				write_ulong((unsigned long) deepest_at_start->end);
				write_string("\nStart deepest existing allocator: ");
				write(2, deepest_at_start->allocated_by->name, strlen(deepest_at_start->allocated_by->name));
				write_string("\n");
			}
			if (deepest_at_end)
			{
				write_string("\nEnd deepest existing begin: ");
				write_ulong((unsigned long) deepest_at_end->begin);
				write_string("\nEnd deepest existing end: ");
				write_ulong((unsigned long) deepest_at_end->end);
				write_string("\nEnd deepest existing allocator: ");
				write(2, deepest_at_end->allocated_by->name, strlen(deepest_at_end->allocated_by->name));
				write_string("\n");
			}
			abort();
		}
		// else looks okay -- we'll check for overlaps in the memset thing (but only if not NDEBUG)
		else { parent = deepest_at_start; } // might still be NULL!
		
		if (!parent)
		{
			/* No parent is okay only if we're page-aligned (mmap or stack). */
			if (ROUND_UP_PTR(ptr, PAGE_SIZE) != ptr)
			{
				write_string("Internal error: requested top-level big allocation not page-aligned at start\n");
				abort();
			}
			if (ROUND_UP_PTR(chunk_lastbyte + 1, PAGE_SIZE) != chunk_lastbyte + 1)
			{
				write_string("Internal error: requested top-level big allocation not page-aligned at end\n");
				abort();
			}
		}
	}
	
	/* Grab a new bigalloc. */
	struct big_allocation *b = bigalloc_new(ptr, size, parent, meta, allocated_by);
	SANITY_CHECK_BIGALLOC(b);
	
	BIG_UNLOCK
	return b;
}

static void bigalloc_init(struct big_allocation *b, const void *ptr, size_t size, struct big_allocation *parent, 
	struct meta_info meta, struct allocator *allocated_by, struct allocator *suballocator,
		void *suballocator_meta, void(*suballocator_free)(void*));

static struct big_allocation *bigalloc_new(const void *ptr, size_t size, struct big_allocation *parent, 
	struct meta_info meta, struct allocator *allocated_by)
{
	struct big_allocation *b = find_free_bigalloc();
	if (!b) return b;
	bigalloc_init(b, ptr, size, parent, meta, allocated_by, /* suballocator */ NULL, NULL, NULL);
	return b;
}

static void bigalloc_init_nomemset(struct big_allocation *b, const void *ptr, size_t size, struct big_allocation *parent, 
	struct meta_info meta, struct allocator *allocated_by, struct allocator *suballocator,
	void *suballocator_meta, void (*suballocator_free_func)(void*))
{
	b->begin = (void*) ptr;
	b->end = (char*) ptr + size;
	b->meta = meta;
	b->allocated_by = allocated_by;
	b->suballocator = suballocator;
	b->suballocator_meta = suballocator_meta;
	b->suballocator_free_func = suballocator_free_func;
	b->first_child = b->next_sib = b->prev_sib = NULL;
	/* Add it to the child list of the parent, if we have one. */
	if (parent) 
	{
		add_child(b, parent);
		/* Check that the parent thinks that this allocator is its suballocator. 
		 * EXCEPTION: the executable's data segment also contains the sbrk area.
		 * EXCEPTION: the auxv allocator also "contains" (logically) the stack.
		 * Actually, only do this check if the child does not have any children
		 * of its own. Except initially, it won't do. Hmm. So just scrap the check. */
		// if (!parent->suballocator) parent->suballocator = allocated_by;
		// else if (parent->suballocator != allocated_by
		// 	&& !(parent == executable_data_segment_mapping_bigalloc
		// 		 && parent->suballocator == &__generic_malloc_allocator)
		// 	// && parent != auxv_bigalloc
		// ) abort();
	}
	
	SANITY_CHECK_BIGALLOC(b);
}

static void bigalloc_init(struct big_allocation *b, const void *ptr, size_t size, struct big_allocation *parent, 
	struct meta_info meta, struct allocator *allocated_by, struct allocator *suballocator,
		void *suballocator_meta, void (*suballocator_free_func)(void*))
{
	bigalloc_init_nomemset(b, ptr, size, parent, meta, allocated_by, suballocator,
		suballocator_meta, suballocator_free_func);

	bigalloc_num_t parent_num = parent ? parent - &big_allocations[0] : 0;
	/* For each page that this alloc spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)),
		b - &big_allocations[0], parent_num, 
			PAGE_DIST(ROUND_UP((unsigned long) b->begin, PAGE_SIZE),
				      ROUND_DOWN((unsigned long) b->end, PAGE_SIZE))
	);
	
	SANITY_CHECK_BIGALLOC(b);
}

_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end) __attribute__((visibility("protected")));
_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	const void *old_end = b->end;
	b->end = (void*) new_end;
	bigalloc_num_t parent_num = b->parent ? b->parent - &big_allocations[0] : 0;
	
	/* For each page that this alloc spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_DOWN((unsigned long) old_end, PAGE_SIZE)),
		b - &big_allocations[0], parent_num,
			PAGE_DIST(ROUND_DOWN((unsigned long) old_end, PAGE_SIZE),
			          ROUND_DOWN((unsigned long) new_end, PAGE_SIZE))
	);
	
	SANITY_CHECK_BIGALLOC(b);
	
	BIG_UNLOCK
	return 1;
}

static _Bool is_one_or_more_levels_under(bigalloc_num_t maybe_lower_n, struct big_allocation *b)
{
	/* Equality means the answer is false. */
	if (maybe_lower_n == b - &big_allocations[0]) return 0;
	
	/* Search b's children for bigalloc number maybe_lower_n. Be breadth-first. */
	for (struct big_allocation *child = b->first_child; child; child = child->next_sib)
	{
		if (child - &big_allocations[0] == maybe_lower_n) return 1;
	}
	for (struct big_allocation *child = b->first_child; child; child = child->next_sib)
	{
		_Bool rec = is_one_or_more_levels_under(maybe_lower_n, child);
		if (rec) return 1;
	}
	return 0;
}

_Bool __liballocs_pre_extend_bigalloc(struct big_allocation *b, const void *new_begin) __attribute__((visibility("protected")));
_Bool __liballocs_pre_extend_bigalloc(struct big_allocation *b, const void *new_begin)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	const void *old_begin = b->begin;
	b->begin = (void*) new_begin;
	bigalloc_num_t parent_num = b->parent ? b->parent - &big_allocations[0] : 0;
	
	/* For each page that this alloc spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) new_begin, PAGE_SIZE)),
		b - &big_allocations[0], parent_num,
			PAGE_DIST(ROUND_UP((unsigned long) new_begin, PAGE_SIZE),
			          /* GAH. Two cases: either we now cover the whole page that contains
			           * old_begin (e.g. if b->end is on the *next* page or later), or
			           * we don't (e.g. if b->end is later on the *same* page as old_begin).
			           * How do we test for that? Looking at PAGENUM(b->end) is not quite enough,
			           * because if a child was spanning the whole page, we don't want to
			           * clobber its presence in the index. */
			          ((PAGENUM(b->end) > PAGENUM(old_begin)) 
			            && !is_one_or_more_levels_under(pageindex[PAGENUM(old_begin)], b)) 
			              ? ROUND_UP((unsigned long) old_begin, PAGE_SIZE)
			              : ROUND_DOWN((unsigned long) old_begin, PAGE_SIZE) )
	);
	
	SANITY_CHECK_BIGALLOC(b);
	
	BIG_UNLOCK
	return 1;
}

static _Bool bigalloc_truncate_at_end(struct big_allocation *b, const void *new_end)
{
	const void *old_end = b->end;
	b->end = (void*) new_end;
	bigalloc_num_t parent_num = b->parent ? b->parent - &big_allocations[0] : 0;
	
	/* For each page that this alloc no longer spans, memset it back to the parent num. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_DOWN((unsigned long) new_end, PAGE_SIZE)),
		parent_num, b - &big_allocations[0], 
			PAGE_DIST(ROUND_DOWN((unsigned long) new_end, PAGE_SIZE),
			          ROUND_DOWN((unsigned long) old_end, PAGE_SIZE))
	);
	
	SANITY_CHECK_BIGALLOC(b);
	
	return 1;
}

_Bool __liballocs_truncate_bigalloc_at_end(struct big_allocation *b, const void *new_end)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	_Bool ret = bigalloc_truncate_at_end(b, new_end);
	SANITY_CHECK_BIGALLOC(b);
	BIG_UNLOCK
	return ret;
}

_Bool __liballocs_truncate_bigalloc_at_beginning(struct big_allocation *b, const void *new_begin)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	const void *old_begin = b->begin;
	b->begin = (void*) new_begin;
	bigalloc_num_t parent_num = b->parent ? b->parent - &big_allocations[0] : 0;
	
	/* For each page that this alloc no longer spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) old_begin, PAGE_SIZE)),
		parent_num, b - &big_allocations[0], 
			PAGE_DIST(ROUND_UP((unsigned long) old_begin, PAGE_SIZE),
			          ROUND_UP((unsigned long) new_begin, PAGE_SIZE))
	);
	SANITY_CHECK_BIGALLOC(b);
	BIG_UNLOCK
	return 1;
}

struct big_allocation *__liballocs_split_bigalloc_at_page_boundary(struct big_allocation *b, const void *split_addr)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	struct big_allocation tmp = *b;
	
	/* Partition the children between the two halves. It's an error
	 * if any child spans the boundary. */
	struct big_allocation *new_bigalloc = find_free_bigalloc();
	if (!new_bigalloc) abort();
	bigalloc_init_nomemset(new_bigalloc, 
		split_addr, (char*) tmp.end - (char*) split_addr, tmp.parent, tmp.meta, tmp.allocated_by,
		tmp.suballocator, tmp.suballocator_meta, tmp.suballocator_free_func);
	/* Danger: the new bigalloc now have the *same* metadata as the old one. 
	 * Our caller sorts this out, since the metadata is opaque to us. */
	
	/* We avoid memset because the old (before-the-split) allocation's children 
	 * might have taken over this elements in the index. Deal with children now. */
	struct big_allocation *child = b->first_child;
	while (child)
	{
		_Bool within_first_half = 
				(char*) child->begin >= (char*) b->begin
				&& (char*) child->end <= (char*) split_addr;
		_Bool within_second_half = 
				(char*) child->begin >= (char*) split_addr
				&& (char*) child->end <= (char*) b->end;
		assert(!(within_first_half && within_second_half));
		
		struct big_allocation *next_in_original_list = child->next_sib;
		
		if (within_first_half && within_second_half) abort();
		if (within_second_half)
		{
			/* Unhook it from its current list and hook it to the new bigalloc's. */
			unlink_child(child);
			add_child(child, new_bigalloc);
		}
		
		child = next_in_original_list;
	}
	
	/* Now we've reassigned children, just update the end. Don't memset... we'll do that
	 * manually. */
	b->end = (void*) split_addr;
	
	/* In the portion after the split, the old bigalloc id needs substituting with the
	 * new (second-half) one, but we don't want to clobber the child bigalloc ids. 
	 * For now, just do a stupid look-and-replace. FIXME: be faster somehow (wmemchr?). */
	for (bigalloc_num_t *pos = pageindex + 
			PAGENUM(ROUND_UP((unsigned long) new_bigalloc->begin, PAGE_SIZE));
			pos < pageindex + PAGENUM(ROUND_UP((unsigned long) new_bigalloc->end, PAGE_SIZE));
			++pos)
	{
		if (*pos == (b - &big_allocations[0])) *pos = (new_bigalloc - &big_allocations[0]);
	}
	SANITY_CHECK_BIGALLOC(b);
	SANITY_CHECK_BIGALLOC(new_bigalloc);
	BIG_UNLOCK
	return new_bigalloc;
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
static struct big_allocation *find_bigalloc_nofail(const void *addr, struct allocator *a);
static struct big_allocation *find_bigalloc(const void *addr, struct allocator *a)
{
	bigalloc_num_t start_idx = pageindex[PAGENUM(addr)];
	if (start_idx == 0) return NULL;
	return find_bigalloc_recursive(&big_allocations[start_idx], addr, a);
}

static struct big_allocation *find_bigalloc_nofail(const void *addr, struct allocator *a)
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
	if (unlikely(start_idx == 0))
	{
		__liballocs_notify_unindexed_address(addr);
		start_idx = pageindex[PAGENUM(addr)];
		if (start_idx == 0) return NULL;
	}
	return find_deepest_bigalloc_recursive(&big_allocations[start_idx], addr);
}

_Bool __liballocs_delete_bigalloc_at(const void *begin, struct allocator *a) __attribute__((visibility("hidden")));
_Bool __liballocs_delete_bigalloc_at(const void *begin, struct allocator *a)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *b = find_bigalloc(begin, a);
	if (!b) { BIG_UNLOCK; return 0; }
	
	// save the info we need for the memset
	void *old_begin = b->begin;
	void *old_end = b->end;
	bigalloc_num_t parent_num = b->parent ? b->parent - &big_allocations[0] : 0;
	
	bigalloc_del(b);
	memset_bigalloc(
		pageindex + PAGENUM(ROUND_UP((unsigned long) old_begin, PAGE_SIZE)),
		parent_num, (bigalloc_num_t) -1, 
		PAGE_DIST(ROUND_UP((unsigned long) old_begin, PAGE_SIZE),
			      ROUND_DOWN((unsigned long) old_end, PAGE_SIZE))
	);
	BIG_UNLOCK;
	return 1;
}

_Bool __liballocs_delete_all_bigallocs_overlapping_range(const void *begin, const void *end) __attribute__((visibility("hidden")));
_Bool __liballocs_delete_all_bigallocs_overlapping_range(const void *begin, const void *end)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	
	const void *deleted_up_to = begin;
	while ((char*) deleted_up_to < (char*) end)
	{
		/* Find the next nonzero entry in the pageindex. FIXME: faster loop than 16-bit iteration. */
		unsigned long initial_pagenum = PAGENUM((unsigned long) deleted_up_to);
		size_t max_len = PAGENUM(ROUND_UP((unsigned long) end, PAGE_SIZE))
					- initial_pagenum;
		bigalloc_num_t *pos = &pageindex[PAGENUM(deleted_up_to)];
		while (!*pos && pos != &pageindex[initial_pagenum + max_len]) ++pos;
		size_t actual_len_zero = pos - &pageindex[initial_pagenum];
		deleted_up_to = (char*) deleted_up_to + PAGE_SIZE * actual_len_zero;
		if ((char*) deleted_up_to >= (char*) end) break;
		
		/* Use the pageindex to find a bigalloc overlapping the range.
		 * By definition, it parent also overlaps the range, so it must go.
		 * And by definition, any children must go if their parents go.
		 * Luckily, bigalloc_del does recursive deletion. */
		bigalloc_num_t n = pageindex[PAGENUM(deleted_up_to)];
		if (n)
		{
			struct big_allocation *b = &big_allocations[n];
			assert(b->begin); if (!b->begin) abort(); if (!b->end) abort();
			while (b->parent) b = b->parent;
			assert((char*) b->end > (char*) deleted_up_to); if (!((char*) b->end > (char*) deleted_up_to)) abort();
			deleted_up_to = b->end;
			bigalloc_del(b);
		} else { assert(0 && "should not have found a bigalloc here"); abort(); }
	}
	
	BIG_UNLOCK;
	return 1;
}

struct big_allocation *__lookup_bigalloc(const void *mem, struct allocator *a, void **out_object_start) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_bigalloc(const void *mem, struct allocator *a, void **out_object_start)
{
	if (!pageindex) init();
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
	if (!pageindex) init();
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
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	struct big_allocation *b = find_deepest_bigalloc(mem);
	BIG_UNLOCK
	while (b && b->parent) b = b->parent;
	return b;
}

struct big_allocation *__lookup_deepest_bigalloc(const void *mem) __attribute__((visibility("hidden")));
struct big_allocation *__lookup_deepest_bigalloc(const void *mem)
{
	if (!pageindex) init();
	int lock_ret;
	BIG_LOCK
	struct big_allocation *b = find_deepest_bigalloc(mem);
	BIG_UNLOCK
	return b;
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
	unsigned depth1 = bigalloc_depth(b1);
	unsigned depth2 = bigalloc_depth(b2);
	return get_common_parent_bigalloc_recursive(b1, depth1, b2, depth2);
}

struct big_allocation * __liballocs_find_common_parent_bigalloc(const void *ptr, const void *end)
{
	if (!pageindex) init();
	return get_common_parent_bigalloc(ptr, end);
}

_Bool __liballocs_notify_unindexed_address(const void *ptr)
{
	if (!pageindex) init();
	/* We get called if the caller finds an address that's not indexed anywhere. 
	 * It's a way of asking us to check. 
	 * We ask all our allocators in turn whether they own this address.
	 * Usually only stack is expected to reply positively.
	 * Very early on, mmap may reply positively (if we're not yet systrapping mmap). */
	_Bool ret = __stack_allocator_notify_unindexed_address(ptr);
	if (ret) return 1;
	ret = __mmap_allocator_notify_unindexed_address(ptr);
	if (ret) return 1;
	// FIXME: loop through the others
	return 0;
}
