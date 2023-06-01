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

#ifdef TRACE_PRIVATE_MALLOC
#include "raw-syscalls-defs.h"
#endif

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
void __private_malloc_set_metadata(void *ptr, size_t size, const void *allocsite)
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

void *__wrap_dlmalloc(size_t size)
{
	void *ret = __real_dlmalloc(size);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private dlmalloc(");
	write_ulong((unsigned long) size);
	write_string(") returned ");
	write_ulong((unsigned long) ret);
	write_string("\n");
#endif
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	return ret;
}
void *__wrap_dlcalloc(size_t nmemb, size_t size)
{
	void *ret = __real_dlcalloc(nmemb, size);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private dlcalloc(nmemb=");
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
void __wrap_dlfree(void *ptr)
{
	clear_metadata(ptr);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private dlfree(");
	write_ulong((unsigned long) ptr);
	write_string(") called\n");
#endif
	__real_dlfree(ptr);
}
void *__wrap_dlrealloc(void *ptr, size_t size)
{
	if (ptr) clear_metadata(ptr);
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private dlrealloc(ptr=");
	write_ulong((unsigned long) ptr);
	write_string(",size=");
	write_ulong((unsigned long) size);
	write_string(") called...\n");
#endif
	// don't mess with the size-zero case, because it means free()
	if (!size) { __real_dlfree(ptr); return NULL; }
	void *ret = __real_dlrealloc(ptr, size + sizeof (struct insert)); // FIXME: aligned
	// FIXME: better to copy the old metadata, not set new?
	// FIXME: all this should be common to generic-malloc.c, extracted/macroised somehow
	if (ret && size > 0) set_metadata(ret, size, __builtin_return_address(0));
#ifdef TRACE_PRIVATE_MALLOC
	write_string("private dlrealloc(ptr=");
	write_ulong((unsigned long) ptr);
	write_string(",size=");
	write_ulong((unsigned long) size);
	write_string(") ... returning new allocation ");
	write_ulong((unsigned long) ret);
	write_string("\n");
#endif
	return ret;
}
void *__wrap_dlmemalign(size_t boundary, size_t size)
{
	void *ret = __real_dlmemalign(boundary, size);
	if (ret) set_metadata(ret, size, __builtin_return_address(0));
	return ret;
}
int __wrap_dlposix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret = __real_dlposix_memalign(memptr, alignment, size);
	if (ret) set_metadata(*memptr, size, __builtin_return_address(0));
	return ret;
}

size_t __wrap_dlmalloc_usable_size(void *userptr)
{
  size_t ret = __real_dlmalloc_usable_size(userptr);
  return ret - sizeof (struct insert);
}

/* This is used by libmallochooks. That is a giant HACK. */
_Bool __private_malloc_is_chunk_start(void *ptr) __attribute__((visibility("hidden")));
_Bool __private_malloc_is_chunk_start(void *ptr)
{
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
