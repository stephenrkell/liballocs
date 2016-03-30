#define _GNU_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include "liballocs_private.h"
#include "pageindex.h"

/* Here we lightly extend dlmalloc so that we can probe whether a chunk
 * belongs to it or not. We use liballocs's bigallocs to do this. */
void *__real_dlmalloc(size_t size);
void *__real_dlcalloc(size_t nmemb, size_t size);
void __real_dlfree(void *ptr);
void *__real_dlrealloc(void *ptr, size_t size);
void *__real_dlmemalign(size_t boundary, size_t size);
int __real_dlposix_memalign(void **memptr, size_t alignment, size_t size);
size_t __real_dlmalloc_usable_size(void *userptr);

static char *lowest_early_seen = (char*) -1;
static char *highest_early_seen;

static void fix_mapping_metadata(void *ptr)
{
	if (__liballocs_systrap_is_initialized)
	{
		struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
		if (b && b->allocated_by == &__mmap_allocator)
		{
			b->meta.un.opaque_data.data_ptr = NULL;
		} else abort();
	}
	else
	{
		/* we first use private_malloc super-early, when we're still yet to
		 * scan /proc/self/maps, hence the bigallocs aren't set up yet. 
		 * Hopefully we won't use more than one memory mapping during that
		 * time. */
		if ((char*) ptr < lowest_early_seen) lowest_early_seen = (char*) ptr;
		if ((char*) ptr > highest_early_seen) highest_early_seen = (char*) ptr;
	}
}
_Bool __thread __private_malloc_active __attribute__((visibility("hidden")));
void *__wrap_dlmalloc(size_t size)
{
	__private_malloc_active = 1;
	void *ret = __real_dlmalloc(size);
	if (ret) fix_mapping_metadata(ret);
	__private_malloc_active = 0;
	return ret;
}
_Bool __thread __private_calloc_active __attribute__((visibility("hidden")));
void *__wrap_dlcalloc(size_t nmemb, size_t size)
{
	__private_calloc_active = 1;
	void *ret = __real_dlcalloc(nmemb, size);
	if (ret) fix_mapping_metadata(ret);
	__private_calloc_active = 0;
	return ret;
}
_Bool __thread __private_free_active __attribute__((visibility("hidden")));
void __wrap_dlfree(void *ptr)
{
	__private_free_active = 1;
	__real_dlfree(ptr);
	__private_free_active = 0;
}
_Bool __thread __private_realloc_active __attribute__((visibility("hidden")));
void *__wrap_dlrealloc(void *ptr, size_t size)
{
	__private_realloc_active = 1;
	void *ret = __real_dlrealloc(ptr, size);
	if (ret) fix_mapping_metadata(ret);
	__private_realloc_active = 0;
	return ret;
}
_Bool __thread __private_memalign_active __attribute__((visibility("hidden")));
void *__wrap_dlmemalign(size_t boundary, size_t size)
{
	__private_memalign_active = 1;
	void *ret = __real_dlmemalign(boundary, size);
	if (ret) fix_mapping_metadata(ret);
	__private_memalign_active = 0;
	return ret;
}
_Bool __thread __private_posix_memalign_active __attribute__((visibility("hidden")));
int __wrap_dlposix_memalign(void **memptr, size_t alignment, size_t size)
{
	__private_posix_memalign_active = 1;
	int ret = __real_dlposix_memalign(memptr, alignment, size);
	if (ret) fix_mapping_metadata(*memptr);
	__private_posix_memalign_active = 0;
	return ret;
	
}

/* Since our malloc hooks don't touch __private_malloc_usable_size, 
 * this doesn't get pulled in, and we end up with the __real_ reference
 * being dangling. FIXME: the right thing is probably to have malloc
 * hooks also hook malloc_usable_size. I haven't thought that through
 * yet, so just get rid of this function for now.  */
//_Bool __thread __private_malloc_usable_size_active __attribute__((visibility("hidden")));
//size_t __wrap_dlmalloc_usable_size(void *userptr)
//{
//	__private_malloc_usable_size_active = 1;
//	size_t ret = __real_dlmalloc_usable_size(userptr);
//	__private_malloc_usable_size_active = 0;
//	return ret;
//}
_Bool __private_malloc_is_chunk_start(void *ptr) __attribute__((visibility("hidden")));
_Bool __private_malloc_is_chunk_start(void *ptr)
{
	if ((char*) ptr >= lowest_early_seen && (char*) ptr <= highest_early_seen) return 1;
	
	struct big_allocation *b = __lookup_bigalloc_top_level(ptr);
	if (b && b->allocated_by == &__mmap_allocator && !b->meta.un.opaque_data.data_ptr) return 1;
	// HACK: here we are recognising our own mappings by their lack of metadata.
	// Better would be to use the allocation site thingy, or some other robust thing.
	return 0;
}
