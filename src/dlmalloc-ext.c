#define _GNU_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include "liballocs_private.h"
#include "malloc-meta.h"
#include "pageindex.h"
#include "vas.h"

#ifdef TRACE_PRIVATE_MALLOC
#include "librunt.h"
#endif

/* We will compile two versions of this file.
 * One is the "nommap_" version and links against nommap_dl* symbols.
 * In turn, they are defined by a nommap-dlmalloc.o which uses a morecore()/sbrk() emulation
 * (defined in this file).
 * The other is the plain version which links against dl* symbols
 * defined in dlmalloc.o which uses mmap only, and has no morecore().
 * We need a way to generate the nommap_ symbol names or the plain ones. */
#ifdef NOMMAP
#define MKIDENT(prefix, suffix) prefix ## nommap_ ## suffix
#define INFIX_STRLIT "nommap_"
#else
#define MKIDENT(prefix, suffix) prefix ## suffix
#define INFIX_STRLIT ""
#endif

/* Here we lightly extend dlmalloc so that we can probe whether a chunk
 * belongs to it or not. We use liballocs's bigallocs to do this. */
void *MKIDENT(__real_, dlmalloc)(size_t size);
void *MKIDENT(__real_, dlcalloc)(size_t nmemb, size_t size);
void MKIDENT(__real_, dlfree)(void *ptr);
void *MKIDENT(__real_, dlrealloc)(void *ptr, size_t size);
void *MKIDENT(__real_, dlmemalign)(size_t boundary, size_t size);
int MKIDENT(__real_, dlposix_memalign)(void **memptr, size_t alignment, size_t size);
size_t MKIDENT(__real_, dlmalloc_usable_size)(void *userptr);

__attribute__((visibility("hidden")))
struct allocator MKIDENT(__private_, malloc_allocator) = (struct allocator) {
#ifdef NOMMAP
	.name = "liballocs private no-mmap malloc"
#else
	.name = "liballocs private malloc"
#endif
};

#ifdef NOMMAP
/* "nommap" means "servicing a malloc will never have to perform mmap". It
 * doesn't mean we don't rely on mmap at all... here we use it to create a
 * heap area at startup. We *could* eliminate it by creating a special
 * program header for it, or just making it a big array of char[] in the
 * liballocs_preload.so, i.e. getting the oader to do the mmap for us... but
 * that does not seem worth it right now. */
__attribute__((visibility("protected")))
struct big_allocation *__liballocs_private_nommap_malloc_bigalloc;
__attribute__((visibility("hidden")))
struct big_allocation *create_private_nommap_malloc_heap(void)
{
	/* A relatively small private heap for allocations that are O(nbigallocs)
	 * rather than O(usedmem). The theory is that only the nbigallocs one needs
	 * to have a 'no-mmap' property in order to avoid reentrancy. This can be kept
	 * quite small. It is still 32K * 4/3 * 416 (<-- current size of struct mapping_sequence)
	 * or approx 18MB, so is worth allocating MAP_NORESERVE. */
	size_t heapsz = ROUND_UP(NBIGALLOCS * 4 * sizeof (struct mapping_sequence) / 3, PAGE_SIZE);
	int prot = PROT_READ|PROT_WRITE;
	int flags = MAP_ANONYMOUS|MAP_NORESERVE|MAP_PRIVATE;
	__private_nommap_malloc_heap_base = mmap(NULL, heapsz, prot, flags, -1, 0);
mmap_return_site:
	if (MMAP_RETURN_IS_ERROR(__private_nommap_malloc_heap_base)) abort();
	__private_nommap_malloc_heap_limit = (void*)((uintptr_t) __private_nommap_malloc_heap_base
		+ heapsz);
	/* It's just a mapping sequence, init. */
	static struct mapping_sequence seq;
	seq = (struct mapping_sequence) {
		.begin = __private_nommap_malloc_heap_base,
		.end =  __private_nommap_malloc_heap_limit,
		.filename = NULL,
		.nused = 1,
		.mappings = { [0] = (struct mapping_entry) {
			.begin = __private_nommap_malloc_heap_base,
			.end = __private_nommap_malloc_heap_limit,
			.prot = prot,
			.flags = flags & ~MAP_NORESERVE,
			.offset = 0,
			.is_anon = 1,
			.caller = /* &&mmap_return_site */ 0
		} }
	};
	struct big_allocation *b = __liballocs_private_nommap_malloc_bigalloc =
		__add_mapping_sequence_bigalloc_nocopy(&seq);
	/* What about the bitmap? 1GB in 16B units needs 64M bits or 8Mbytes.
	 * We don't want to spend that much up-front. But we don't have to!
	 * We allocate the bitmap in our own heap, which is MAP_NORESERVE. */
	b->suballocator = &__private_nommap_malloc_allocator;
	size_t range_size_bytes = (uintptr_t) b->end - (uintptr_t) b->begin;
	size_t bitmap_alloc_size_bytes = DIVIDE_ROUNDING_UP(
		DIVIDE_ROUNDING_UP(range_size_bytes, PRIVATE_MALLOC_ALIGN),
		8) + sizeof (struct insert);
	/* FIXME: also want to create one of these?
	struct arena_bitmap_info
	{
		unsigned long nwords;
		bitmap_word_t *bitmap;
		void *bitmap_base_addr;
	};
	*/
	/* We use the real dlmalloc just this once, because we can't set the bit
	 * before the bitmap is created. Note that we are *not* in a nommap context
	 * right now. However... if the real dlmalloc does a mmap -- it didn't use to,
	 * but now in the nommap-vs-vanilla world, the vanilla dlmalloc may mmap --
	 * we need a bigalloc to be created if the vanilla dlmalloc creates a new
	 * memory mapping. Since it's an intra-DSO mmap, it is not trapped... we rely
	 * on the preload.c mmap override, which calls __mmap_allocator_notify_mmap().
	 * This should be enough to create the bigalloc for the underlying mapping.
	 */
	// FIXME: this is an interesting case of an unclassifiable allocation site,
	// by our current 'dumpallocs.ml' classifier. It is sized (syntactically)
	// in bytes but allocated (semantically) in bitmap_word_t units, and rests
	// on the assumption that when we scale down a whole number of pages,
	// we get some whole number of bitmap_word_ts, but we don't care about
	// the actual number... we care only that we have one bit per
	// PRIVATE_MALLOC_ALIGN bytes.
	void *__real_dlmalloc(size_t size); /* this is *not* the nommap version */
	b->suballocator_private = __real_nommap_dlmalloc(bitmap_alloc_size_bytes);
	/* Although this bitmap is technically fair game for the mmap-based dlmalloc,
	 * we use the same nommap allocator that we are currently initializing.
	 * it is not really an O(mem)-sized bitmap (it is O(heapsize) which is O(nbigalloc))
	 * and the assertions below are a useful sanity check which would not hold
	 * if we used the other private dlmalloc. */
dlmalloc_return_site:
	assert((uintptr_t) b->suballocator_private >= (uintptr_t) __private_nommap_malloc_heap_base);
	assert((uintptr_t) b->suballocator_private + bitmap_alloc_size_bytes
		< (uintptr_t) __private_nommap_malloc_heap_limit);
	__private_nommap_malloc_set_metadata(b->suballocator_private, bitmap_alloc_size_bytes,
		&&dlmalloc_return_site);

	return b;
}

static void set_metadata(void *ptr, size_t size, const void *allocsite)
{
	struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
	assert(b);
	assert(b->allocated_by == &__mmap_allocator);
	assert(0 == 
		((uintptr_t) ptr - (uintptr_t) b->begin) % PRIVATE_MALLOC_ALIGN
	);
	assert((uintptr_t) ptr >= (uintptr_t) b->begin);
	bitmap_set_b(
		(bitmap_word_t *) b->suballocator_private,
		((uintptr_t) ptr - (uintptr_t) b->begin) / PRIVATE_MALLOC_ALIGN
	);
	// FIXME: set the insert
	// FIXME: this is just index_insert. Make it so
}
// FIXME: for meta-completeness, our allocations should have an insert.

__attribute__((visibility("hidden")))
void __private_nommap_malloc_set_metadata(void *ptr, size_t size, const void *allocsite)
{
	set_metadata(ptr, size, allocsite);
}

static void clear_metadata(void *ptr)
{
	// we shouldn't be dlfreeing stuff so early
	// ... WHY NOT? we do this when plugging the ld.so hole, in static-file init
	//assert(__liballocs_systrap_is_initialized);
	struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
	assert(b && b->allocated_by == &__mmap_allocator);
	bitmap_clear_b(
		(bitmap_word_t *) b->suballocator_private,
		((uintptr_t) ptr - (uintptr_t) b->begin) / PRIVATE_MALLOC_ALIGN
	);
	// FIXME: this is just index_delete. Make it so.
}
#else /* we are not NOMMAP */
static void set_metadata(void *ptr, size_t size, const void *allocsite) {} // FIXME
static void clear_metadata(void *ptr) {}
#endif

void *MKIDENT(__wrap_, dlmalloc)(size_t size)
{
	void *ret = MKIDENT(__real_, dlmalloc)(size);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private " INFIX_STRLIT "dlmalloc(");
	write_ulong((unsigned long) size);
	write_string(") returned ");
	write_ulong((unsigned long) ret);
	write_string("\n");
#endif
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	return ret;
}
void *MKIDENT(__wrap_, dlcalloc)(size_t nmemb, size_t size)
{
	void *ret = MKIDENT(__real_, dlcalloc)(nmemb, size);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private " INFIX_STRLIT "dlcalloc(nmemb=");
	write_ulong((unsigned long) nmemb);
	write_string(",size=");
	write_ulong((unsigned long) size);
	write_string(") returned ");
	write_ulong((unsigned long) ret);
	write_string("\n");
#endif
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	return ret;
}
void MKIDENT(__wrap_, dlfree)(void *ptr)
{
	clear_metadata(ptr);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private " INFIX_STRLIT "dlfree(");
	write_ulong((unsigned long) ptr);
	write_string(") called\n");
#endif
	MKIDENT(__real_, dlfree)(ptr);
}
void *MKIDENT(__wrap_, dlrealloc)(void *ptr, size_t size)
{
	if (ptr) clear_metadata(ptr);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private " INFIX_STRLIT "dlrealloc(ptr=");
	write_ulong((unsigned long) ptr);
	write_string(",size=");
	write_ulong((unsigned long) size);
	write_string(") called...\n");
#endif
	// don't mess with the size-zero case, because it means free()
	if (!size) { MKIDENT(__real_, dlfree)(ptr); return NULL; }
	void *ret = MKIDENT(__real_, dlrealloc)(ptr, size + sizeof (struct insert)); // FIXME: aligned
	// FIXME: better to copy the old metadata, not set new?
	// FIXME: all this should be common to generic-malloc.c, extracted/macroised somehow
	if (ret && size > 0) set_metadata(ret, size, __builtin_return_address(0));
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private " INFIX_STRLIT "dlrealloc(ptr=");
	write_ulong((unsigned long) ptr);
	write_string(",size=");
	write_ulong((unsigned long) size);
	write_string(") ... returning new allocation ");
	write_ulong((unsigned long) ret);
	write_string("\n");
#endif
	return ret;
}
void *MKIDENT(__wrap_, dlmemalign)(size_t boundary, size_t size)
{
	void *ret = MKIDENT(__real_, dlmemalign)(boundary, size);
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	return ret;
}
int MKIDENT(__wrap_, dlposix_memalign)(void **memptr, size_t alignment, size_t size)
{
	int ret = MKIDENT(__real_, dlposix_memalign)(memptr, alignment, size);
	if (ret) set_metadata(*memptr, size, __builtin_return_address(0));
	return ret;
}

size_t MKIDENT(__wrap_, dlmalloc_usable_size)(void *userptr)
{
  size_t ret = MKIDENT(__real_, dlmalloc_usable_size)(userptr);
  return ret - sizeof (struct insert); /* FIXME: do we increment the size on malloc??!??! */
}

#ifdef NOMMAP
void *__private_nommap_malloc_heap_base __attribute__((visibility("hidden")));
void *__private_nommap_malloc_heap_limit __attribute__((visibility("hidden")));
static void *emulated_curbrk;
void *emulated_sbrk(intptr_t increment)
{
	if (!emulated_curbrk) emulated_curbrk = __private_nommap_malloc_heap_base;
	void *old_curbrk = emulated_curbrk;
	/* We always return an error if we can't satisfy the request,
	 * which includes overflow/underflow. */
	uintptr_t req_brk = (uintptr_t) emulated_curbrk + increment;
	_Bool flowed_over_or_under = (increment > 0 && req_brk < (uintptr_t) old_curbrk)
			|| (increment < 0 && req_brk > (uintptr_t) old_curbrk);
	if (flowed_over_or_under) goto err;
	/* Clip to our heap area. We only go ahead if it fits. */
	void *new_brk = (increment > 0)
		? (MINPTR(__private_nommap_malloc_heap_limit, (void*)req_brk))
		: (MAXPTR(__private_nommap_malloc_heap_base, (void*)req_brk));
	if (new_brk == (void*) req_brk)
	{
		emulated_curbrk = (void*) req_brk;
		return old_curbrk;
	}
err:
	errno = ENOMEM;
	return (void*) -1;
}
#endif
