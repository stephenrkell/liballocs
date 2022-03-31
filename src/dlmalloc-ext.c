#define _GNU_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include "liballocs_private.h"
#include "malloc-meta.h"
#include "pageindex.h"
#include "vas.h"

/* Here we lightly extend dlmalloc so that we can probe whether a chunk
 * belongs to it or not. We use liballocs's bigallocs to do this. */
void *__real_dlmalloc(size_t size);
void *__real_dlcalloc(size_t nmemb, size_t size);
void __real_dlfree(void *ptr);
void *__real_dlrealloc(void *ptr, size_t size);
void *__real_dlmemalign(size_t boundary, size_t size);
int __real_dlposix_memalign(void **memptr, size_t alignment, size_t size);
size_t __real_dlmalloc_usable_size(void *userptr);

__attribute__((visibility("hidden")))
struct allocator __private_malloc_allocator = (struct allocator) {
	.name = "liballocs private malloc"
};

/* Keeping metadata for the chunks we allocate ourselves is good for
 * our meta-completeness; we do it mostly like we would for an ordinary
 * malloc. This [will, once un-bitrotted] help with the nice node/v8+liballocs
 * demo, in which we do a dlopen() and can see the full link_map structure
 * (including ld.so-private fields) as its pointed-to return value.
 *
 * FIXME: Part of the problem there is that the ld.so's allocations are seen
 * as being made by us. I am not sure why that should be, in a deep sense...
 * we do checks like is_ldso_call()  but we probably shouldn't. */
#define MAX_EARLY_CHUNKS 256
static struct early_chunk_meta {
	unsigned long chunk_addr_shr:(ADDR_BITSIZE-LOG_PRIVATE_MALLOC_ALIGN);
	unsigned long chunk_size_bytes:(WORD_BITSIZE-(ADDR_BITSIZE-LOG_PRIVATE_MALLOC_ALIGN));
} early_chunks_meta[MAX_EARLY_CHUNKS],
  *p_first_free_early_chunk_meta = &early_chunks_meta[0];

static void set_metadata_inner(struct big_allocation *b,
	void *ptr, size_t size, const void *allocsite)
{
	assert(0 == 
		((uintptr_t) ptr - (uintptr_t) b->begin) % PRIVATE_MALLOC_ALIGN
	);
	assert((uintptr_t) ptr >= (uintptr_t) b->begin);
	bitmap_set_b(
		(bitmap_word_t *) b->suballocator_private,
		((uintptr_t) ptr - (uintptr_t) b->begin) / PRIVATE_MALLOC_ALIGN
	);
	// FIXME: set the insert
}
static void transfer_early_chunks(struct big_allocation *b)
{
	// transfer the early chunks into the bitmap we are using for their starts
	for (struct early_chunk_meta *p = &early_chunks_meta[0];
				p != p_first_free_early_chunk_meta;
				++p)
	{
		set_metadata_inner(b,
			(void*)(uintptr_t)(((uintptr_t) p->chunk_addr_shr) << LOG_PRIVATE_MALLOC_ALIGN),
			p->chunk_size_bytes, NULL);
	}
#ifndef NDEBUG
	bzero(early_chunks_meta, sizeof early_chunks_meta);
#else
	// just clear one
	bzero(early_chunks_meta, sizeof early_chunks_meta[0]);
#endif
}

static void set_metadata(void *ptr, size_t size, const void *allocsite)
{
	if (__liballocs_systrap_is_initialized)
	{
		struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
		if (b && b->allocated_by == &__mmap_allocator)
		{
			if (early_chunks_meta[0].chunk_addr_shr) transfer_early_chunks(b);
			set_metadata_inner(b, ptr, size, allocsite);
		}
		else if (!b)
		{
			/* Maybe systrap is done now, but it wasn't when we last called?
			 * HMM, if systrap is done then we'll have a mapping bigalloc.
			 */
			/* dlmalloc might have made a new arena mmap, which we didn't trap
			 * because... WHY? It should call our mmap wrapper in preload.c,
			 * which should record the mapping.
			 *
			 * In the malloc-in-exe test case we are actually getting a pointer
			 * into sbrk(). This shouldn't happen because our dlmalloc does
			 * not use sbrk.
			 *
			 * Well, it might not be sbrk. AH, it isn't!
			 * It is after our *auxiliary* mappings of the executable.
			 *
			 * It's confusing because there are two copies of dlmalloc
			 * in this test case.
			 *
			 * What's happening is that the mmap happened when systrapping
			 * was not enabled. But we missed it wen we were walking the
			 * mappings because *we were walking the mappings when it happened!*. */
			abort();
		}
		else /* this is the really wacky case: top-level is not mmap */
		{
			abort();
		}
	}
	else
	{
		/* we first use private_malloc super-early, when we're still yet to
		 * scan /proc/self/maps, hence the bigallocs aren't set up yet. */
		if (p_first_free_early_chunk_meta == &early_chunks_meta[MAX_EARLY_CHUNKS]) abort();
		*p_first_free_early_chunk_meta++ = (struct early_chunk_meta) {
			.chunk_addr_shr = ((uintptr_t) ptr) >> LOG_PRIVATE_MALLOC_ALIGN,
			.chunk_size_bytes = size
		};
	}
}
static _Bool is_early_chunk_start(void *ptr)
{
	for (struct early_chunk_meta *p = &early_chunks_meta[0];
				p != p_first_free_early_chunk_meta;
				++p)
	{
		if (p->chunk_addr_shr == (((uintptr_t) ptr) >> LOG_PRIVATE_MALLOC_ALIGN))
		{
			return 1;
		}
	}
	return 0;
}
static void clear_metadata(void *ptr)
{
	// we shouldn't be dlfreeing stuff so early
	assert(__liballocs_systrap_is_initialized);
	struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
	assert(b && b->allocated_by == &__mmap_allocator);
	bitmap_clear_b(
		(bitmap_word_t *) b->suballocator_private,
		((uintptr_t) ptr - (uintptr_t) b->begin) / PRIVATE_MALLOC_ALIGN
	);
}

_Bool __thread __private_malloc_active __attribute__((visibility("hidden")));
void *__wrap_dlmalloc(size_t size)
{
	__private_malloc_active = 1;
	void *ret = __real_dlmalloc(size);
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	__private_malloc_active = 0;
	return ret;
}
_Bool __thread __private_calloc_active __attribute__((visibility("hidden")));
void *__wrap_dlcalloc(size_t nmemb, size_t size)
{
	__private_calloc_active = 1;
	void *ret = __real_dlcalloc(nmemb, size);
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	__private_calloc_active = 0;
	return ret;
}
_Bool __thread __private_free_active __attribute__((visibility("hidden")));
void __wrap_dlfree(void *ptr)
{
	__private_free_active = 1;
	clear_metadata(ptr);
	__real_dlfree(ptr);
	__private_free_active = 0;
}
_Bool __thread __private_realloc_active __attribute__((visibility("hidden")));
void *__wrap_dlrealloc(void *ptr, size_t size)
{
	__private_realloc_active = 1;
	if (ptr) clear_metadata(ptr);
	// don't mess with the size-zero case, because it means free()
	if (!size) { __wrap_dlfree(ptr); return NULL; }
	void *ret = __real_dlrealloc(ptr, size + sizeof (struct insert)); // FIXME: aligned
	// FIXME: better to copy the old metadata, not set new?
	// FIXME: all this should be common to generic-malloc.c, extracted/macroised somehow
	if (ret && size > 0) set_metadata(ret, size, __builtin_return_address(0));
	__private_realloc_active = 0;
	return ret;
}
_Bool __thread __private_memalign_active __attribute__((visibility("hidden")));
void *__wrap_dlmemalign(size_t boundary, size_t size)
{
	__private_memalign_active = 1;
	void *ret = __real_dlmemalign(boundary, size);
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	__private_memalign_active = 0;
	return ret;
}
_Bool __thread __private_posix_memalign_active __attribute__((visibility("hidden")));
int __wrap_dlposix_memalign(void **memptr, size_t alignment, size_t size)
{
	__private_posix_memalign_active = 1;
	int ret = __real_dlposix_memalign(memptr, alignment, size);
	if (ret) set_metadata(*memptr, size, __builtin_return_address(0));
	__private_posix_memalign_active = 0;
	return ret;
}

_Bool __thread __private_malloc_usable_size_active __attribute__((visibility("hidden")));
size_t __wrap_dlmalloc_usable_size(void *userptr)
{
  __private_malloc_usable_size_active = 1;
  size_t ret = __real_dlmalloc_usable_size(userptr);
  __private_malloc_usable_size_active = 0;
  return ret - sizeof (struct insert);
}

/* This is used by libmallochooks. That is a giant HACK. */
_Bool __private_malloc_is_chunk_start(void *ptr) __attribute__((visibility("hidden")));
_Bool __private_malloc_is_chunk_start(void *ptr)
{
	if (early_chunks_meta[0].chunk_addr_shr)
	{
		// we have at least one early chunk => haven't transferred them yet
		return is_early_chunk_start(ptr);
	}
	struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
	if (b && b->allocated_by == &__mmap_allocator
	      && b->suballocator == &__private_malloc_allocator) return 1;
	// FIXME: actually check the chunk-start thing, duh
	return 0;
}

void *__private_malloc_heap_base __attribute__((visibility("hidden")));
void *__private_malloc_heap_limit __attribute__((visibility("hidden")));
static void *emulated_curbrk;
void *emulated_sbrk(intptr_t increment)
{
	if (!emulated_curbrk) emulated_curbrk = __private_malloc_heap_base;
	if (increment > 0)
	{
		// we only return an error if we can't allocate any more at all
		// FIXME: is this correct? matches my memory of glibc's logic...
		if (emulated_curbrk == __private_malloc_heap_limit)
		{
			errno = ENOMEM;
			return (void*) -1;
		}
		emulated_curbrk = MINPTR(
			__private_malloc_heap_limit,
			(void*)((uintptr_t) emulated_curbrk + increment)
		);
	}
	else if (increment < 0)
	{
		emulated_curbrk = MAXPTR(
			__private_malloc_heap_base,
			(void*)((uintptr_t) emulated_curbrk + increment)
		);
	}
	return emulated_curbrk;
}
