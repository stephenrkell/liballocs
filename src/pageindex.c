#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <signal.h>
#include <string.h>
#include <wchar.h>
#include <unistd.h>
#include <errno.h>
#include "raw-syscalls-defs.h"
#include "librunt.h"
#include "relf.h"
#include "liballocs_private.h"
#include "memtable.h"

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
	struct big_allocation **out_bigalloc);
extern struct big_allocation *__liballocs_get_bigalloc_containing(const void *obj);

/* How many big allocs? 256 is a bit stingy. 
 * Each bigalloc record is 48--64 bytes, so 4096 of them would take 256KB.
 * Maybe stick to 1024?
 * That is no longer enough! Let's go large. */
struct big_allocation big_allocations[NBIGALLOCS] __attribute__((visibility("protected"))); // NOTE: we *don't* use big_allocations[0]; the 0 byte means "empty"
extern struct big_allocation __liballocs_big_allocations[NBIGALLOCS] __attribute__((alias("big_allocations"))); // NOTE: we *don't* use big_allocations[0]; the 0 byte means "empty"

static unsigned bigalloc_depth(struct big_allocation *b)
{
	unsigned depth = 0;
	for (struct big_allocation *tmp = b; tmp; tmp = BIDX(tmp->parent)) ++depth;
	return depth;
}
#if 0 /* not used currently */
static int bigalloc_compare_df(struct big_allocation *b1, struct big_allocation *b2)
{
	/* b1 precedes b2 if its begin address precedes b2's, OR
	 * if its begin address is equal and its depth is greater. */
	if ((uintptr_t) b1->begin < (uintptr_t) b2->begin) return -1;
	if ((uintptr_t) b1->begin > (uintptr_t) b2->begin) return 1;
	unsigned d1 = bigalloc_depth(b1);
	unsigned d2 = bigalloc_depth(b2);
	if (d1 < d2) return -1;
	if (d2 > d1) return 1;
	return 0;
}
#endif
static int bigalloc_compare_toplevel(struct big_allocation *b1, struct big_allocation *b2)
{
	/* b1 precedes b2 if its begin address precedes b2's. */
	if ((uintptr_t) b1->begin < (uintptr_t) b2->begin) return -1;
	if ((uintptr_t) b1->begin > (uintptr_t) b2->begin) return 1;
	return 0;
}
static void sanity_check_bigallocs_toplevel(void)
{
	struct big_allocation *b = __liballocs_private_nommap_malloc_bigalloc;
	if (!b) return;
	bitmap_word_t bitmap[NBIGALLOCS / 8*sizeof(bitmap_word_t)];
	memset(bitmap, 0, sizeof bitmap);
	/* OK, found an in-use top-level bigalloc. Let's walk backwards to the start of the list,
	 * setting bits as we go and checking the order. */
	struct big_allocation *cur;
	struct big_allocation *prev = NULL;
	for (cur = b; cur; prev = cur, cur = BIDX(cur->prev_sib))
	{
		bitmap_set_b(bitmap, IDXB(cur));
		/* If we have a earlier, it's better be df-earlier. */
		if (BIDX(cur->prev_sib)) assert(-1 == bigalloc_compare_toplevel(BIDX(cur->prev_sib), cur));
	}
	struct big_allocation *first_top = prev;
	/* Same but walking forwards from b. */
	for (cur = b; cur; prev = cur, cur = BIDX(cur->next_sib))
	{
		bitmap_set_b(bitmap, IDXB(cur));
		/* If we have a later, it's better be df-later. */
		if (BIDX(cur->next_sib)) assert(-1 == bigalloc_compare_toplevel(cur, BIDX(cur->next_sib)));
	}
	struct big_allocation *last_top = prev;
	/* For each big allocation, check its state agrees with the bitmap.
	 * Since the bitmap only contains toplevel bigallocs, we simply check
	 * that they are in use. */
	unsigned n_toplevel_in_use = 0;
	for (unsigned idx = 1; idx < NBIGALLOCS; ++idx)
	{
		struct big_allocation *c = &big_allocations[idx];
		if (BIGALLOC_IN_USE(c) && !c->parent)
		{
			n_toplevel_in_use++;
			_Bool bit = bitmap_get_b(bitmap, idx);
			assert(bit);
		}
	}
	prev = NULL;
	unsigned n_seen = 0;
	/* We haven't walked the whole list both ways yet. So do that. */
	for (struct big_allocation *d = first_top; d; ++n_seen, prev = d, d = BIDX(d->next_sib))
	{
		if (prev) assert(-1 == bigalloc_compare_toplevel(prev, d));
	}
	assert(n_seen == n_toplevel_in_use);
	prev = NULL;
	n_seen = 0;
	for (struct big_allocation *d = last_top; d; ++n_seen, prev = d, d = BIDX(d->prev_sib))
	{
		if (prev) assert(1 == bigalloc_compare_toplevel(prev, d));
	}
	assert(n_seen == n_toplevel_in_use);
}

__attribute__((visibility("hidden")))
void sanity_check_bigalloc(struct big_allocation *b)
{
#ifndef NDEBUG
	if (BIGALLOC_IN_USE(b))
	{
		/* Must be non-zero-size. */
		assert(b->end != b->begin);
		/* The pageindex immediately before the beginning should not say
		 * that it's this bigalloc there. */
		assert(pageindex[PAGENUM(((char*)(b)->begin)-1)] != IDXB(b));
		assert(pageindex[PAGENUM((b)->end)] != IDXB(b));

		assert(!b->allocated_by
				|| !b->allocated_by->min_alignment
				|| 0 == (unsigned long) b->begin % b->allocated_by->min_alignment);

		/* Check that our depth is 1 + our parent's depth */
		if (BIDX(b->parent))
		{
			assert(bigalloc_depth(b) == 1 + bigalloc_depth(BIDX(b->parent)));
			/* Also check bounds w.r.t. parent. */
			assert(b->begin >= BIDX(b->parent)->begin);
			assert(b->end <= BIDX(b->parent)->end);
		}
		/* Check that old children all have the same depth as each other. */
		if (BIDX(b->first_child))
		{
			unsigned first_child_depth = bigalloc_depth(BIDX(b->first_child));
			for (struct big_allocation *child = BIDX(BIDX(b->first_child)->next_sib); child; child = BIDX(child->next_sib))
			{
				assert(bigalloc_depth(child) == first_child_depth);
				/* Also recursively sanity-check children. */
				sanity_check_bigalloc(child);
			}
		}
	}
#endif
}
void __liballocs_sanity_check_bigalloc(struct big_allocation *b) __attribute__((visibility("protected"),alias("sanity_check_bigalloc")));
#define SANITY_CHECK_BIGALLOC(b) sanity_check_bigalloc((b)) 

bigalloc_num_t *pageindex __attribute__((visibility("protected")));
extern bigalloc_num_t *__liballocs_pageindex __attribute__((alias("pageindex")));

static void memset_bigalloc(bigalloc_num_t *begin, bigalloc_num_t num, 
	bigalloc_num_t old_num, size_t n)
{
	if (unlikely(n > (BIGGEST_SANE_USER_ALLOC >> LOG_PAGE_SIZE)))
	{
		debug_printf(0,
			"asked to memset pageindex for an insanely large bigalloc (%ld pages, at %p)\n",
			(unsigned long) n, begin
		);
		abort();
	}
	/* NOTE: a lot of this function is debugging checks!
	 * It collapses to very little when NDEBUG is defined. */
	assert(1ull<<(8*sizeof(bigalloc_num_t)) >= NBIGALLOCS - 1);
	assert(sizeof (wchar_t) == 2 * sizeof (bigalloc_num_t));
#ifndef NDEBUG
	ptrdiff_t first_bad_n;
	bigalloc_num_t bad_value;
#define CHECK_LOC(loc, bad_n_expr) do { \
	if (!(old_num == (bigalloc_num_t) -1 || !(loc) || (loc) == old_num)) \
	{ first_bad_n = (bad_n_expr); bad_value = (loc); goto report_failure_and_abort; } \
} while (0)
#else
#define CHECK_LOC(loc, bad_n_expr)
#endif

	/* We use wmemset with special cases at the beginning and end */
	if (n > 0 && (uintptr_t) begin % sizeof (wchar_t) != 0)
	{
		CHECK_LOC(*begin, begin-pageindex);
		*begin++ = num;
		--n;
	}
	assert(n == 0 || (uintptr_t) begin % sizeof (wchar_t) == 0);
	
	// double up the value
	wchar_t wchar_val     = ((wchar_t) num)     << (8 * sizeof(bigalloc_num_t)) | num;
	wchar_t wchar_transition_val = ((wchar_t) num); // FIXME: assumes little-endianness
	wchar_t wchar_old_val = ((wchar_t) old_num) << (8 * sizeof(bigalloc_num_t)) | old_num;
	
	// check the relevant range of the pageindex is in the state we expect
	if (old_num != (bigalloc_num_t) -1 && old_num) // FIXME: also check when old_num is zero
	{
		bigalloc_num_t *pageindex_end = pageindex + PAGENUM(MAXIMUM_USER_ADDRESS + 1);
		// we should get zero or more of the old value
		// ... followed by zero or one of the transitional value
		// ... followed by zero or more of the null value
		// ... adding up to n/2 or more.
		// We used to use wcsspn directly, but this overruns
		// if we start it in the last two pages of user-accessible memory
		// when either of those is nonzero. Or in fact if there is a contiguous
		// nonempty sequence of pages at the end of user memory, and we start
		// within that part of the pageindex.
		// We could also open-code a wchar_t-based solution, but unlike wmemset (-ish!)
		// this breaks strict aliasing rules. So just do the slower thing... we're debug.
		bigalloc_num_t *p;
		// search forwards from p, checking we see zero or old_num
		for (p = begin; p < pageindex_end && (p - begin) < n; ++p)
		{
			// either *p is uninit'd or it equals the old_num we expect to see
			CHECK_LOC(*p, p-pageindex);
		}
		// assert we didn't terminate early
		assert(p - begin == n);
	}
	if (n != 0) wmemset((wchar_t *) begin, wchar_val, n / 2);
	
	// if we missed one off the end, do it now
	if (n % 2 == 1)
	{
		// if we have one left over, we should have done up to n-1
		CHECK_LOC(*(begin + (n-1)), (begin-pageindex)+n-1);
		*(begin + (n-1)) = num;
	}
	return;
#ifndef NDEBUG
report_failure_and_abort:
	debug_printf(0, "pageindex has bad value (%d; expected %d) at page 0x%lx\n",
		(int) bad_value, (int) old_num, (long) first_bad_n);
	abort();
#endif
}

const int the_signal = SIGBUS;
static struct sigaction oldaction; /* We will restore this... */

/* FIXME: we should really use some handler chaining, not
 * just clobbering whatever handler pre-exists. libcrunch
 * needs its own handler, and the guest program may too. */
static void handle_signal(int n, siginfo_t *info, void *ucontext)
{
	/* We must NOT trigger a nested SIGBUS here. In general, any memory allocation
	 * may do this, if it needs to grab more pages and therefore touch the pageindex.
	 * So be very conservative about library calls. We do not use debug_printf(). */
#define     PAGEINDEX_MAPPING_UNIT     COMMON_HUGEPAGE_SIZE
#define LOG_PAGEINDEX_MAPPING_UNIT LOG_COMMON_HUGEPAGE_SIZE
	/* If the fault falls within the pageindex area, we map something there.
	 * Otherwise, don't. */
	if ((uintptr_t) info->si_addr >= PAGEINDEX_ADDRESS &&
	    (uintptr_t) info->si_addr <  PAGEINDEX_ADDRESS + PAGEINDEX_SIZE_BYTES)
	{
		/* FIXME: check whether we have already mapped something here. */
		/* Do we want to keep a bitmap of which hugepages of pageindex are
		 * already mapped? If the pageindex is 2^37 bytes, and a hugepage
		 * is 2^21 bytes, then there are 2^16 bits in this bitmap, or 2^13
		 * bytes, which is very manageable for mapping locally. */
		/* NOTE that we use hugepages only as a convenient unit, i.e. a coarse-
		 * -grained division of memory -- nothing about our logic depends on matching
		 * the underlying architecture's hugepage size. */
		uintptr_t range_base = RELF_ROUND_DOWN_((uintptr_t) info->si_addr, PAGEINDEX_MAPPING_UNIT);
		uintptr_t range_idx = (range_base - PAGEINDEX_ADDRESS) >> LOG_PAGEINDEX_MAPPING_UNIT;
		void *ret = raw_mmap((void*) range_base, PAGEINDEX_MAPPING_UNIT,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
		if (ret != (void*) range_base)
		{
			write_string("failed to map lazily a piece of pageindex at ");
			write_string(fmt_hex_num((uintptr_t) range_base));
			write_string(" (ret ");
			write_string(fmt_hex_num((uintptr_t) ret));
			write_string(")\n");
			abort();
		}
		write_string("lazily mapped a piece of pageindex at ");
		write_string(fmt_hex_num((uintptr_t) ret));
		write_string(" (idx ");
		write_string(fmt_hex_num((unsigned long) range_idx));
		write_string(")\n");
		return; // we explicitly resume from the segfault
	}
	/* FIXME: be more compositional, w.r.t. other possible handlers (installed
	 * either before we install ours or after!).
	 * For now, we want to do whatever would happen if our handler was not installed...
	 * probably that's just exit. However, exiting has the side effect of disabling
	 * the core handling path. Instead we disable ourselves and then resume! FIXME: this
	 * is not foolproof, e.g. if there are concurrent threads futzing with the memory map. */
	write_string("Signal not handleable by lazy mapping of pageindex\n");
	//raw_exit(128 + the_signal);
	sigaction(the_signal, &oldaction, NULL);
}

/* We use SIGBUS here, as it is more rarely triggered than SIGSEGV and so is
 * less confusing/disruptive at debug time, while still achieving the intention
 * of not generating huge core files from the unused pageindex areas. We
 * memory-map a zero-length temporary file that we immediately unlink. */
static void install_lazy_pageindex_handler(void)
{
	struct sigaction action = {
		.sa_handler = (void*) &handle_signal,
		.sa_flags = SA_NODEFER | SA_SIGINFO
	};
	int ret = sigaction(the_signal, &action, &oldaction);
	if (ret != 0)
	{
		debug_printf(0, "failed to install signal handler for lazy pageindex mapping");
		abort();
	}
}

__attribute__((constructor(101),visibility("hidden")))
void __pageindex_init(void)
{
	if (!pageindex)
	{
		/* PROBLEM: we're running too early to search the environment.
		 * The libc's 'environ' has not been populated yet. And that
		 * means we can't get the auxv, at least not by the usual
		 * trick. For now, we use get_auxv_via_libc_stack_end(), which
		 * is glibc-specific. The only way to do this portably will be
		 * when we become our own ld.so, so we can snarf the auxv nice
		 * and early from the stack.
		 */
		char *debug_envvar = NULL;
		char **env = get_auxv_environ(get_auxv_via_libc_stack_end());
		debug_envvar = environ_getenv("LIBALLOCS_DEBUG_LEVEL", env);
		// HACK: should really do atoi here -- this is intolerant of leading space/zero
		_Bool print_debug_message = debug_envvar && debug_envvar[0] != '0';
		if (print_debug_message)
		{
			write_string("liballocs: process name ");
			raw_write(2, get_exe_command_basename(), strlen(get_exe_command_basename()));
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
		}
		/* Mmap our region. We map one 16-bit number for every page in the user address region. */
		/* HACK: always place at a known address (see pageindex.h, but it's 0x410000000000),
		 * to avoid problems with libcrunch shadow space. */
		if (getenv("LIBALLOCS_PAGEINDEX_NO_LAZY_MAPPING"))
		{
			pageindex = MEMTABLE_NEW_WITH_TYPE_AT_ADDR(bigalloc_num_t, PAGE_SIZE, (void*) 0,
				(void*) (MAXIMUM_USER_ADDRESS + 1), (const void *) PAGEINDEX_ADDRESS);
			if (pageindex == MAP_FAILED) abort();
			debug_printf(3, "pageindex at %p (mapped eagerly)\n", pageindex);
		}
		else
		{
			int fd = memfd_create("pageindex-lazy-region", 0);
			if (fd == -1) abort();
			pageindex = (bigalloc_num_t *) mmap((void*) PAGEINDEX_ADDRESS,
				sizeof (bigalloc_num_t) * ((uintptr_t)(MAXIMUM_USER_ADDRESS + 1) >> LOG_PAGE_SIZE),
				PROT_READ|PROT_WRITE,
				MAP_PRIVATE|MAP_FIXED|MAP_NORESERVE,
				fd, 0);
			if (pageindex == MAP_FAILED) { debug_printf(0, "Failed to map memfd fd %d (%s)\n", fd, strerror(errno)); abort(); }
			close(fd);
			install_lazy_pageindex_handler();
			debug_printf(3, "pageindex at %p (to be mapped lazily)\n", pageindex);
		}
		create_private_nommap_malloc_heap();
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

__attribute__((visibility("hidden")))
_Bool __pages_unused(void *begin, void *end)
{
	return is_unindexed(begin, end);
}


__attribute__((constructor))
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
	b->allocator_private = NULL;
	b->allocator_private_free = NULL;
}

static void add_child(struct big_allocation *child, struct big_allocation *parent)
{
	SANITY_CHECK_BIGALLOC(parent);
	assert(!BIDX(child->parent));
	child->parent = IDXB(parent);
	/* Hook it into the new list, at the head. FIXME: keep sorted? */
	struct big_allocation *previous_first_child = BIDX(parent->first_child);
	parent->first_child = IDXB(child);
	assert(!BIDX(child->next_sib));
	child->next_sib = IDXB(previous_first_child);
	assert(!previous_first_child || !BIDX(previous_first_child->prev_sib));
	if (previous_first_child) previous_first_child->prev_sib = IDXB(child);
	assert(!BIDX(child->prev_sib));
	SANITY_CHECK_BIGALLOC(child);
	SANITY_CHECK_BIGALLOC(parent);
}

static void unlink_child(struct big_allocation *child)
{
	struct big_allocation *parent = BIDX(child->parent);
	if (!parent) abort();
	SANITY_CHECK_BIGALLOC(child);
	SANITY_CHECK_BIGALLOC(parent);
	/* Unhook it from its current list. */
	if (child == BIDX(parent->first_child))
	{
		parent->first_child = child->next_sib;
		assert(!BIDX(child->prev_sib));
	}
	else
	{
		assert(BIDX(child->prev_sib));
	}
	if (BIDX(child->prev_sib)) BIDX(child->prev_sib)->next_sib = child->next_sib;
	if (BIDX(child->next_sib)) BIDX(child->next_sib)->prev_sib = child->prev_sib;
	child->prev_sib = 0;
	child->next_sib = 0;
	child->parent = 0;
	SANITY_CHECK_BIGALLOC(parent);
}
#define PAGE_DIST(first, second) \
( (PAGENUM((second)) > \
    PAGENUM((first))) ? \
	(PAGENUM((second)) - PAGENUM((first))) \
	: 0 )

static struct big_allocation *find_deepest_bigalloc(const void *addr);
static void add_toplevel(struct big_allocation *b);
static void unlink_toplevel(struct big_allocation *b);

static void bigalloc_del(struct big_allocation *b)
{
	SANITY_CHECK_BIGALLOC(b);
	
	/* Recursively delete all children. */
	struct big_allocation *child = BIDX(b->first_child);
	while (child)
	{
		struct big_allocation *next_child = BIDX(child->next_sib);
		bigalloc_del(child);
		child = next_child;
	}
	
	/* Delete the user metadata, if the user told us we need to. */
	if (b->allocator_private && b->allocator_private_free)
	{
		b->allocator_private_free(b->allocator_private);
	}
	if (b->suballocator_private_free) b->suballocator_private_free(b->suballocator_private);
	struct big_allocation *parent = BIDX(b->parent);
	if (parent) unlink_child(b);
	else unlink_toplevel(b);
	
	SANITY_CHECK_BIGALLOC(b);
	
	bigalloc_num_t parent_num = IDXB(parent);
	void *begin_to_clear = b->begin;
	void *end_to_clear = b->end;
	memset_bigalloc(
		pageindex + PAGENUM(ROUND_UP((unsigned long) begin_to_clear, PAGE_SIZE)),
		parent_num,
		/* If our recursive deletion worked,
		 * then surely in all these positions the pageindex
		 * should have our number? */
		IDXB(b),
		PAGE_DIST(ROUND_UP((unsigned long) begin_to_clear, PAGE_SIZE),
		          ROUND_DOWN((unsigned long) end_to_clear, PAGE_SIZE))
	);
	clear_bigalloc_nomemset(b);
	
	assert(!BIGALLOC_IN_USE(b));
}

__attribute__((visibility("protected")))
struct allocator *__liballocs_get_allocator_upper_bound(const void *obj)
{
	if (!pageindex) __pageindex_init();
	struct big_allocation *b = __liballocs_get_bigalloc_containing(obj);
	if (b) return b->allocated_by;
	else return NULL;
}
__attribute__((visibility("protected")))
struct allocator *__liballocs_ool_get_allocator(const void *obj)
{
	return __liballocs_leaf_allocator_for(obj, NULL);
}

__attribute__((visibility("protected")))
void __liballocs_print_l0_to_stream_err(void)
{
	int lock_ret;
	BIG_LOCK
	
	if (!pageindex) __pageindex_init();
	for (struct big_allocation *b = &big_allocations[1]; b < &big_allocations[NBIGALLOCS]; ++b)
	{
		if (BIGALLOC_IN_USE(b) && !BIDX(b->parent)) fprintf(get_stream_err(), "%p-%p %s %p\n",
				b->begin, b->end, b->allocated_by->name, 
				b->allocator_private
		);
	}
	
	BIG_UNLOCK
}

__attribute__((visibility("protected")))
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
		fprintf(get_stream_err(), "*** saw wild pointer %p\n", ptr);
		__liballocs_print_l0_to_stream_err();
	}
}

static struct big_allocation *get_common_parent_bigalloc(const void *ptr, const void *end);
static struct big_allocation *bigalloc_new(const void *ptr, size_t size, struct big_allocation *parent, 
	void *allocator_private, void (*allocator_private_free)(void*), struct allocator *allocated_by);

__attribute__((visibility("protected")))
struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size,
	void *allocator_private, void(*allocator_private_free)(void*), struct big_allocation *maybe_parent,
	struct allocator *allocated_by)
{
	/* We get called from generic_malloc_index when the malloc'd address is a multiple of the 
	 * page size, is big enough and fills (more-or-less) the alloc'd region. If so,  
	 * create a bigalloc record including the caller-supplied metadata. We will fish 
	 * it out in get_alloc_info. */
	if (!pageindex) __pageindex_init();
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
				write_string("\nStart deepest bigalloc num: ");
				write_ulong((unsigned long) pageindex[PAGENUM(ptr)]);
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
				write_string("\nEnd deepest bigalloc num: ");
				write_ulong((unsigned long) pageindex[PAGENUM(chunk_lastbyte)]);
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
	
	if (parent) SANITY_CHECK_BIGALLOC(parent);
	
	/* Grab a new bigalloc. */
	struct big_allocation *b = bigalloc_new(ptr, size, parent, allocator_private, allocator_private_free,
		allocated_by);
	SANITY_CHECK_BIGALLOC(b);
	
	BIG_UNLOCK
	return b;
}

static void bigalloc_init(struct big_allocation *b, const void *ptr, size_t size, struct big_allocation *parent, 
	void *allocator_private, void (*allocator_private_free)(void*), struct allocator *allocated_by, struct allocator *suballocator,
		void *suballocator_private, void(*suballocator_private_free)(void*));

static struct big_allocation *bigalloc_new(const void *ptr, size_t size, struct big_allocation *parent, 
	void *allocator_private, void (*allocator_private_free)(void*), struct allocator *allocated_by)
{
	struct big_allocation *b = find_free_bigalloc();
	if (!b) return b;
	bigalloc_init(b, ptr, size, parent, allocator_private, allocator_private_free,
		allocated_by, /* suballocator */ NULL, NULL, NULL);
	return b;
}

static void bigalloc_init_nomemset(struct big_allocation *b, const void *ptr, size_t size, struct big_allocation *parent, 
	void *allocator_private, void (*allocator_private_free)(void*),
	struct allocator *allocated_by, struct allocator *suballocator,
	void *suballocator_private, void (*suballocator_private_free)(void*))
{
	b->begin = (void*) ptr;
	b->end = (char*) ptr + size;
	b->allocator_private = allocator_private;
	b->allocator_private_free = allocator_private_free;
	b->allocated_by = allocated_by;
	b->suballocator = suballocator;
	b->suballocator_private = suballocator_private;
	b->suballocator_private_free = suballocator_private_free;
	b->first_child = b->next_sib = b->prev_sib = 0;
	/* How to populate the df fields?
	 * Maybe we don't need them after all. Instead we 'simply' use the
	 * next_sib and prev_sib fields in a different manner. There should
	 * be a position in the list where next_sib has 'begin' >= our end or null, and
	 *                                 prev_sib has 'end' <= our begin or null.
	 */
	/* Add it to the child list of the parent, if we have one. */
	if (parent)
	{
		add_child(b, parent);
		assert(b->parent);
		/* Check that the parent thinks that this allocator is its suballocator. 
		 * EXCEPTION: the executable's data segment also contains the sbrk area.
		 * EXCEPTION: the auxv allocator also "contains" (logically) the stack.
		 * Actually, only do this check if the child does not have any children
		 * of its own. Except initially, it won't do. Hmm. So just scrap the check. */
		// if (!parent->suballocator) parent->suballocator = allocated_by;
		// else if (parent->suballocator != allocated_by
		// 	&& !(parent == executable_data_segment_mapping_bigalloc
		// 		 && parent->suballocator == &__default_lib_malloc_allocator)
		// 	// && parent != auxv_bigalloc
		// ) abort();
	} else add_toplevel(b);
	
	SANITY_CHECK_BIGALLOC(b);
	if (!b->parent) sanity_check_bigallocs_toplevel();
}

static void bigalloc_init(struct big_allocation *b, const void *ptr, size_t size, struct big_allocation *parent, 
	void *allocator_private, void (*allocator_private_free)(void*), struct allocator *allocated_by, struct allocator *suballocator,
	void *suballocator_private, void (*suballocator_private_free)(void*))
{
	bigalloc_init_nomemset(b, ptr, size, parent, allocator_private, allocator_private_free,
		allocated_by, suballocator,
		suballocator_private, suballocator_private_free);

	bigalloc_num_t parent_num = IDXB(parent);
	/* For each page that this alloc newly spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) b->begin, PAGE_SIZE)),
		IDXB(b), parent_num,
			PAGE_DIST(ROUND_UP((unsigned long) b->begin, PAGE_SIZE),
				      ROUND_DOWN((unsigned long) b->end, PAGE_SIZE))
	);
	SANITY_CHECK_BIGALLOC(b);
}

#define START __liballocs_private_nommap_malloc_bigalloc
#define search_xwards_until_p(dir, p) \
    prev = NULL; \
	for (cur = START; \
			cur && !(p); \
			prev = cur, cur = BIDX(cur->dir ## _sib));
static uint16_t find_toplevel_lowest_ge(void *addr)
{
	/* To do this search, we start by searching forwards from our arbitrary start point,
	 * looking for something spanning an address >= addr       i.e. its 'end-1' >= addr
	 * If the result is not our start point, then we have our answer.
	 * If the result is our start point, we have found *something*
	 * but it might not be the lowest.
	 * So search backwards for the highest spanning any address < addr   i.e. its 'begin' is < addr
	 * and return its successor (possibly null). */
#define cond (((uintptr_t) cur->end-1) >= (uintptr_t) addr)
	struct big_allocation *cur, *prev = NULL;
	search_xwards_until_p(next, cond);
	if (cur && cur != START) return IDXB(cur);
	if (!cur) return 0; // nothing from START onwards is ge addr, so nothing is
	search_xwards_until_p(prev, !cond);
	assert(cur != START);
	assert(prev);
	return IDXB(prev); // might equal START
#undef cond
}
static uint16_t find_toplevel_highest_lt(void *addr)
{
#define cond (((uintptr_t) cur->begin) < (uintptr_t) addr)
	struct big_allocation *cur, *prev = NULL;
	search_xwards_until_p(prev, cond);
	if (cur && cur != START) return IDXB(cur);
	if (!cur) return 0; // nothing from START backwards is lt addr, so nothing is
	search_xwards_until_p(next, !cond);
	struct big_allocation *b;
	assert(cur != START);
	assert(prev);
	return IDXB(prev); // might equal START
#undef cond
}
static void add_toplevel(struct big_allocation *b)
{
	b->next_sib = find_toplevel_lowest_ge(b->end);
	/* Don't repeat the search if we don't need to. */
	b->prev_sib = b->next_sib ? BIDX(b->next_sib)->prev_sib : find_toplevel_highest_lt(b->begin);
	if (b->prev_sib) BIDX(b->prev_sib)->next_sib = IDXB(b);
	if (b->next_sib) BIDX(b->next_sib)->prev_sib = IDXB(b);
}
static void unlink_toplevel(struct big_allocation *b)
{
	if (b->prev_sib) BIDX(b->prev_sib)->next_sib = b->next_sib;
	if (b->next_sib) BIDX(b->next_sib)->prev_sib = b->prev_sib;
}
__attribute__((visibility("protected")))
struct big_allocation *__liballocs_find_mapping_at_or_above(void *addr)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	uint16_t found = find_toplevel_highest_lt(addr);
	// does the found bigalloc span the address?
	struct big_allocation *ret = NULL;
	if (!found) ret = NULL;
	else if ((uintptr_t) BIDX(found)->end <= (uintptr_t) addr) ret = BIDX(find_toplevel_lowest_ge(addr));
	else ret = BIDX(found);
	BIG_UNLOCK
	return ret;
}
__attribute__((visibility("protected")))
struct big_allocation *__liballocs_find_mapping_below(void *addr)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	uint16_t found = find_toplevel_highest_lt(addr);
	struct big_allocation *ret = NULL;
	// does the found bigalloc end below the query address?
	// if not, look for the highest lt its start address
	if (!found) ret = NULL;
	else if ((uintptr_t) BIDX(found)->end > (uintptr_t) addr) ret = BIDX(find_toplevel_highest_lt(BIDX(found)->begin));
	else ret = BIDX(found);
	BIG_UNLOCK
	return ret;
}
__attribute__((visibility("protected")))
_Bool __liballocs_extend_bigalloc(struct big_allocation *b, const void *new_end)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	const void *old_end = b->end;
	b->end = (void*) new_end;
	bigalloc_num_t parent_num = BIDX(b->parent) ? b->parent : 0;
	
	/* For each page that this alloc spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_DOWN((unsigned long) old_end, PAGE_SIZE)),
		IDXB(b), parent_num,
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
	if (maybe_lower_n == IDXB(b)) return 0;
	
	/* Search b's children for bigalloc number maybe_lower_n. Be breadth-first. */
	for (struct big_allocation *child = BIDX(b->first_child); child; child = BIDX(child->next_sib))
	{
		if (IDXB(child) == maybe_lower_n) return 1;
	}
	for (struct big_allocation *child = BIDX(b->first_child); child; child = BIDX(child->next_sib))
	{
		_Bool rec = is_one_or_more_levels_under(maybe_lower_n, child);
		if (rec) return 1;
	}
	return 0;
}

__attribute__((visibility("protected")))
_Bool __liballocs_pre_extend_bigalloc_recursive(struct big_allocation *b, const void *new_begin)
{
	_Bool ret;
	if (BIDX(b->parent)) ret = __liballocs_pre_extend_bigalloc_recursive(BIDX(b->parent),
		BIDX(b->parent)->allocated_by->min_alignment ?
			(ROUND_DOWN_PTR(new_begin, BIDX(b->parent)->allocated_by->min_alignment))
		: new_begin);
	else ret = 1;
	if (ret) ret = __liballocs_pre_extend_bigalloc(b, new_begin);
	return ret;
}

__attribute__((visibility("protected")))
_Bool __liballocs_pre_extend_bigalloc(struct big_allocation *b, const void *new_begin)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	SANITY_CHECK_BIGALLOC(b);
	const void *old_begin = b->begin;
	if ((char*) new_begin < (char*) old_begin)
	{
		b->begin = (void*) new_begin;
		bigalloc_num_t parent_num = b->parent;

		/* For each page that this alloc spans, memset it in the page index. */
		memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) new_begin, PAGE_SIZE)),
			IDXB(b), parent_num,
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
	}
	
	
	SANITY_CHECK_BIGALLOC(b);
	BIG_UNLOCK
	return 1;
}

/* This helper just takes a new end, which may be an expansion or contraction. 
 * Clients must fix up the allocator-specific metadata. */
__attribute__((visibility("hidden")))
void __adjust_bigalloc_end(struct big_allocation *b, void *new_end)
{
	char *old_end = b->end;
	
	if ((uintptr_t) new_end < (uintptr_t) old_end)
	{
		/* We're contracting. */
		__liballocs_truncate_bigalloc_at_end(b, new_end);
	}
	else if ((uintptr_t) new_end > (uintptr_t) old_end)
	{
		/* We're expanding. */
		__liballocs_extend_bigalloc(b, new_end);
	}
}

static _Bool bigalloc_truncate_at_end(struct big_allocation *b, const void *new_end)
{
	const void *old_end = b->end;
	b->end = (void*) new_end;
	bigalloc_num_t parent_num = b->parent;
	
	/* For each page that this alloc no longer spans, memset it back to the parent num. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_DOWN((unsigned long) new_end, PAGE_SIZE)),
		parent_num, IDXB(b),
			PAGE_DIST(ROUND_DOWN((unsigned long) new_end, PAGE_SIZE),
			          ROUND_DOWN((unsigned long) old_end, PAGE_SIZE))
	);
	
	SANITY_CHECK_BIGALLOC(b);
	
	return 1;
}

__attribute__((visibility("protected")))
_Bool __liballocs_truncate_bigalloc_at_end(struct big_allocation *b, const void *new_end)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	_Bool ret = bigalloc_truncate_at_end(b, new_end);
	SANITY_CHECK_BIGALLOC(b);
	BIG_UNLOCK
	return ret;
}

__attribute__((visibility("protected")))
_Bool __liballocs_truncate_bigalloc_at_beginning(struct big_allocation *b, const void *new_begin)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	const void *old_begin = b->begin;
	b->begin = (void*) new_begin;
	bigalloc_num_t parent_num = b->parent;
	
	/* For each page that this alloc no longer spans, memset it in the page index. */
	memset_bigalloc(pageindex + PAGENUM(ROUND_UP((unsigned long) old_begin, PAGE_SIZE)),
		parent_num, IDXB(b),
			PAGE_DIST(ROUND_UP((unsigned long) old_begin, PAGE_SIZE),
			          ROUND_UP((unsigned long) new_begin, PAGE_SIZE))
	);
	SANITY_CHECK_BIGALLOC(b);
	BIG_UNLOCK
	return 1;
}

__attribute__((visibility("protected")))
struct big_allocation *__liballocs_split_bigalloc_at_page_boundary(struct big_allocation *b, const void *split_addr)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	struct big_allocation tmp = *b;
	
	/* Partition the children between the two halves. It's an error
	 * if any child spans the boundary. */
	struct big_allocation *new_bigalloc = find_free_bigalloc();
	if (!new_bigalloc) abort();
	bigalloc_init_nomemset(new_bigalloc, 
		split_addr, (char*) tmp.end - (char*) split_addr, BIDX(tmp.parent),
		tmp.allocator_private, tmp.allocator_private_free, tmp.allocated_by,
		tmp.suballocator, tmp.suballocator_private, tmp.suballocator_private_free);
	/* Danger: the new bigalloc now have the *same* metadata as the old one. 
	 * Our caller sorts this out, since the metadata is opaque to us. */
	
	/* We avoid memset because the old (before-the-split) allocation's children 
	 * might have taken over this elements in the index. Deal with children now. */
	struct big_allocation *child = BIDX(b->first_child);
	while (child)
	{
		_Bool within_first_half = 
				(char*) child->begin >= (char*) b->begin
				&& (char*) child->end <= (char*) split_addr;
		_Bool within_second_half = 
				(char*) child->begin >= (char*) split_addr
				&& (char*) child->end <= (char*) b->end;
		assert(!(within_first_half && within_second_half));
		
		struct big_allocation *next_in_original_list = BIDX(child->next_sib);
		
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
		if (*pos == IDXB(b)) *pos = IDXB(new_bigalloc);
	}
	SANITY_CHECK_BIGALLOC(b);
	SANITY_CHECK_BIGALLOC(new_bigalloc);
	BIG_UNLOCK
	return new_bigalloc;
}

/* We recursively search through the bigallocs overlapping 'addr'. 
 * If 'match_suballocator', we return the first one whose suballocator equals 'a'.
 * Otherwise we return the first one whose *allocator* equals 'a'. */
static struct big_allocation *find_bigalloc_recursive(struct big_allocation *start,
	const void *addr, struct allocator *a, _Bool match_suballocator)
{
	/* If we don't have a start, start at top level. But
	 * we can't find anywhere in the chain of bigallocs spanning
	 * this address except via the pageindex. */
	if (!start)
	{
		bigalloc_num_t startnum = pageindex[PAGENUM(addr)];
		if (!startnum)
		{
			if (unlikely(!startnum && !__liballocs_systrap_is_initialized))
			{
				/* Early on, we might have just edged past the end of the brk bigalloc,
				 * so search backwards. You might think this logic should be in the wild
				 * address function, but that is only called on queries, not on bigalloc
				 * lookups. Probably there should be a common path. */
				if (big_allocations[2].begin) // HACK: bigalloc 1 is the private malloc heap
				{
		#define MAX_BRK_PAGES_TO_SEARCH 128
					unsigned long search_pagenum = PAGENUM(addr);
					while (search_pagenum > 0 && pageindex[search_pagenum] == 0)
					{
						if (search_pagenum - PAGENUM(addr) > MAX_BRK_PAGES_TO_SEARCH) break;
						--search_pagenum;
					}
					if (pageindex[search_pagenum])
					{
						// have we found the brk allocator? test the highest address on the page
						if (__lookup_bigalloc_from_root(
								(void*)((search_pagenum<<LOG_PAGE_SIZE) + ((1ul<<LOG_PAGE_SIZE)-1)),
								&__brk_allocator, NULL))
						{
							__brk_allocator_notify_brk(sbrk(0), __builtin_return_address(0));
						}
					}
				}
				else
				{
					// we have no bigallocs... nothing
					__mmap_allocator_init();
				}
				// try again
				startnum = pageindex[PAGENUM(addr)];
				if (!startnum) goto found_nothing;
			}
		}
		start = &big_allocations[startnum];
		while (BIDX(start->parent)) start = BIDX(start->parent);
	}

	/* Is it this one? */
	if ((match_suballocator ? start->suballocator : start->allocated_by) == a) return start;
	
	/* Okay, it's not this one. Is it one of the children? */
	for (struct big_allocation *child = BIDX(start->first_child);
			child;
			child = BIDX(child->next_sib))
	{
		if ((char*) child->begin <= (char*) addr && 
				child->end > addr)
		{
			/* okay, tail-recurse down here */
			return find_bigalloc_recursive(child, addr, a, match_suballocator);
		}
	}
	
	/* We didn't find an overlapping child, so we fail. */
found_nothing:
	return NULL;
}
static struct big_allocation *find_bigalloc_under_pageindex(const void *addr, struct allocator *a)
{
	bigalloc_num_t start_idx = pageindex[PAGENUM(addr)];
	if (start_idx == 0) return NULL;
	return find_bigalloc_recursive(&big_allocations[start_idx], addr, a, /* suballocator? */ 0);
}
static struct big_allocation *find_bigalloc_from_root(const void *addr, struct allocator *a)
{
	return find_bigalloc_recursive(NULL, addr, a, /* suballocator? */ 0);
}
static struct big_allocation *find_bigalloc_under_pageindex_nofail(const void *addr, struct allocator *a)
{
	bigalloc_num_t start_idx = pageindex[PAGENUM(addr)];
	/* We should always have something at level0 spanning the whole page. */
	if (start_idx == 0) abort();
	return find_bigalloc_recursive(&big_allocations[start_idx], addr, a, /* suballocator? */ 0);
}
static struct big_allocation *find_deepest_bigalloc_recursive(struct big_allocation *start, 
	const void *addr)
{
	/* Is it one of the children? */
	for (struct big_allocation *child = BIDX(start->first_child);
			child;
			child = BIDX(child->next_sib))
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

__attribute__((visibility("protected")))
_Bool __liballocs_delete_bigalloc_at(const void *begin, struct allocator *a)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	
	struct big_allocation *b = find_bigalloc_from_root(begin, a);
	if (!b) { BIG_UNLOCK; return 0; }
	
	bigalloc_del(b);
	BIG_UNLOCK;
	return 1;
}

__attribute__((visibility("hidden")))
_Bool __liballocs_delete_all_bigallocs_overlapping_range(const void *begin, const void *end)
{
	if (!pageindex) __pageindex_init();
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
		write_string("Deleted up to address ");
		write_ulong((unsigned long) deleted_up_to);
		write_string("\n");
		if ((char*) deleted_up_to >= (char*) end) break;
		
		/* Use the pageindex to find a bigalloc overlapping the range.
		 * By definition, it parent also overlaps the range, so it must go.
		 * And by definition, any children must go if their parents go.
		 * Luckily, bigalloc_del does recursive deletion. */
		bigalloc_num_t n = pageindex[PAGENUM(deleted_up_to)];
		write_string("Got bigalloc num: ");
		write_ulong((unsigned long) n);
		write_string("\n");
		if (n)
		{
			struct big_allocation *b = &big_allocations[n];
			assert(b->begin); if (!b->begin) abort(); if (!b->end) abort();
			while (BIDX(b->parent)) b = BIDX(b->parent);
			assert((char*) b->end > (char*) deleted_up_to); if (!((char*) b->end > (char*) deleted_up_to)) abort();
			const void *old_deleted_up_to = deleted_up_to;
			deleted_up_to = b->end;
			bigalloc_del(b);
			write_string("Pageindex now has bigalloc num: ");
			write_ulong((unsigned long) pageindex[PAGENUM(old_deleted_up_to)]);
			write_string("\n");
		} else { assert(0 && "should not have found a bigalloc here"); abort(); }
	}
	
	BIG_UNLOCK;
	return 1;
}

__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_under_pageindex(const void *mem, struct allocator *a, void **out_object_start)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	assert(a);
	struct big_allocation *b = find_bigalloc_under_pageindex(mem, a);
	BIG_UNLOCK;
	return b;
}

__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_under(const void *mem, struct allocator *a, struct big_allocation *start, void **out_object_start)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	assert(a);
	struct big_allocation *b = find_bigalloc_recursive(start, mem, a, /* suballocator? */ 0);
	BIG_UNLOCK;
	return b;
}
__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_under_by_suballocator(const void *mem, struct allocator *sub_a,
	struct big_allocation *start, void **out_object_start)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	assert(sub_a);
	struct big_allocation *b = find_bigalloc_recursive(start, mem, sub_a, /* suballocator? */ 1);
	BIG_UNLOCK;
	return b;
}

__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_from_root(const void *mem, struct allocator *a, void **out_object_start)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	assert(a);
	struct big_allocation *b = find_bigalloc_from_root(mem, a);
	BIG_UNLOCK;
	return b;
}

__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_from_root_by_suballocator(const void *mem, struct allocator *sub_a, void **out_object_start)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	assert(sub_a);
	struct big_allocation *b = find_bigalloc_recursive(NULL, mem, sub_a, /* suballocator? */ 1);
	BIG_UNLOCK;
	return b;
}
__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_top_level(const void *mem)
{
	if (!pageindex) __pageindex_init();
	int lock_ret;
	BIG_LOCK
	bigalloc_num_t n = pageindex[PAGENUM(mem)];
	struct big_allocation *b = NULL;
	if (n != 0)
	{
		b = &big_allocations[n];
	}
	BIG_UNLOCK
	while (b && BIDX(b->parent)) b = BIDX(b->parent);
	return b;
}

__attribute__((visibility("protected")))
struct big_allocation *__lookup_deepest_bigalloc(const void *mem)
{
	if (!pageindex) __pageindex_init();
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
		BIDX(b1->parent), depth1 - 1, b2, depth2 - 1);
	else return get_common_parent_bigalloc_recursive(
		b1, depth1, BIDX(b2->parent), depth2 - 1);
}

static struct big_allocation *get_common_parent_bigalloc(const void *ptr, const void *end)
{
	struct big_allocation *b1 = find_deepest_bigalloc(ptr);
	struct big_allocation *b2 = find_deepest_bigalloc(end);
	unsigned depth1 = bigalloc_depth(b1);
	unsigned depth2 = bigalloc_depth(b2);
	return get_common_parent_bigalloc_recursive(b1, depth1, b2, depth2);
}

__attribute__((visibility("hidden")))
struct big_allocation * __liballocs_find_common_parent_bigalloc(const void *ptr, const void *end)
{
	if (!pageindex) __pageindex_init();
	return get_common_parent_bigalloc(ptr, end);
}

void print_bigalloc_slice_for(void *addr)
{
#if 0
	/* We want to print something like this... */
	fprintf(stderr, "       0x7fffe1234567                   \n");
	fprintf(stderr, "0___________:_______________________UMAX\n");
	fprintf(stderr, "    |_______:_______| mmap   [NN]       \n");
	fprintf(stderr, "         |__:___|     malloc [MM]       \n");
	fprintf(stderr, "           |:_|                         \n");
	fprintf(stderr, "       0x7fffe1234567                   \n");
	/* We want to print something like this...
	 *   - size each intermediate rectangle by the log2 of its size
	 *   - pick the : position linearly along that
	 *       ... in effect this is sliding the rectangle around
	 *       since we have picked the top ':' position also linearly?
	 */
	struct big_allocation *b = BIDX(pageindex[PAGENUM(addr)]);
	while (b && b->parent) b = b->parent;
	for (struct big_allocation *child = BIDX(start->first_child);
			child;
			child = BIDX(child->next_sib))
	{
		if ((char*) child->begin <= (char*) addr && 
				child->end > addr)
		{
			/* Recurse down here */
			struct big_allocation *maybe_deeper = find_deepest_bigalloc_recursive(child, addr);
			if (maybe_deeper) return maybe_deeper;
		}
	}
#endif
}

_Bool __liballocs_notify_unindexed_address(const void *ptr)
{
	if (!pageindex) __pageindex_init();
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
