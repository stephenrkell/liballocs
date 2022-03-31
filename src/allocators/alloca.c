#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "relf.h"
#include "liballocs_private.h"
#include "pageindex.h"
#include "generic_malloc_index.h"

// this is a bug-finding hack to detect bogus/corrupt chunk pointers... can remove
#define BIGGEST_SANE_ALLOCA 33554431ul /* 32MB - 1byte */

extern struct allocator __alloca_allocator;
struct big_allocation *alloca_arena_for_userptr(void *userptr, struct big_allocation *b)
{
	assert(malloc_usable_size(userptr) <= BIGGEST_SANE_ALLOCA);
	if (b)
	{
		return (b->allocated_by == &__stackframe_allocator) ? b :
				(b->allocated_by == &__alloca_allocator) ? b->parent :
				(abort(), NULL); // it's a problem
	}
	b = __lookup_bigalloc_from_root_by_suballocator(userptr, &__alloca_allocator, NULL);
	// what if we get no b? probably means we're not initialized
	assert(b);
	return b;
}

liballocs_err_t __alloca_get_info(void *obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_alloca_case;
	struct insert *heap_info = NULL;
	void *base;
	size_t caller_usable_size;
	size_t alloc_usable_chunksize = 0;
	assert(b);
	struct arena_bitmap_info *info = b->suballocator_private;
	// if we haven't allocated a bitmap, there's nothing there
	assert(info);
	if (!info || NULL == (heap_info = lookup_object_info(alloca_arena_for_userptr(obj, b),
		obj, &base, &alloc_usable_chunksize, NULL)))
	{
		/* For an unindexed chunk, we don't know the base, so we don't know anything. */
		++__liballocs_aborted_unindexed_alloca;
		return &__liballocs_err_unindexed_alloca_object;
	}
	assert(base);
	caller_usable_size = caller_usable_size_for_chunk_and_malloc_usable_size(base,
		alloc_usable_chunksize);
	assert(heap_info);
	if (out_base) *out_base = base;
	if (out_size) *out_size = caller_usable_size;
	if (out_type || out_site) return extract_and_output_alloc_site_and_type(
		heap_info, out_type, (void**) out_site);
	// no error
	return NULL;
}

struct allocator __alloca_allocator = {
	.name = "alloca",
	.is_cacheable = 1,   // HMM: am I sure that we're cacheable?
	.get_info = __alloca_get_info
};
static void ensure_arena_covers_addr(struct big_allocation *arena, void *addr);

void __liballocs_unindex_stack_objects_counted_by(unsigned long *bytes_counter, void *frame_addr)
{
	struct big_allocation *b = __lookup_bigalloc_under_pageindex(bytes_counter,
		&__stackframe_allocator, NULL);
	if (*bytes_counter == 0) goto out;
	if (!b) abort();
	
	/* Starting at the stack pointer, we look for indexed chunks and 
	 * keep unindexing until we have unindexed exactly *bytes_counter bytes. */
	void *sp;
	#ifdef UNW_TARGET_X86
		__asm__ ("movl %%esp, %0\n" :"=r"(sp));
	#else // assume X86_64 for now
		__asm__("movq %%rsp, %0\n" : "=r"(sp));
	#endif
	ensure_arena_covers_addr(b, sp);

	struct arena_bitmap_info *info = b->suballocator_private;
	unsigned long total_to_unindex = *bytes_counter;
	unsigned long total_unindexed = 0;
	unsigned chunks_unindexed = 0;
	assert(!info->bitmap_base_addr || info->bitmap_base_addr == ROUND_DOWN_PTR(b->begin, ALLOCA_ALIGN*BITMAP_WORD_NBITS));
	// pretend we're currently on 'one before the initial search start pos'
	unsigned long cur_bit_idx = (((uintptr_t) sp - (uintptr_t) info->bitmap_base_addr)
			/ ALLOCA_ALIGN) - 1;
	
	/* Iterate forward over bits */
	while ((unsigned long)-1 != (cur_bit_idx = bitmap_find_first_set1_geq_l(
			info->bitmap, info->bitmap + info->nwords,
			cur_bit_idx + 1, NULL)))
	{
		void *cur_userchunk = (void*)((uintptr_t) info->bitmap_base_addr
			+ (cur_bit_idx * ALLOCA_ALIGN));
		debug_printf(0, "Walking an alloca chunk at %p (bitmap base: %p) idx %d\n", cur_userchunk,
			(void*) info->bitmap_base_addr, (int) cur_bit_idx);
		struct insert *cur_insert = insert_for_chunk(cur_userchunk);

		unsigned long bytes_to_unindex = malloc_usable_size(cur_userchunk);
		assert(ALLOCA_ALIGN == MALLOC_ALIGN);
		// equal alignments so we can just abuse the generic malloc functions
		__generic_malloc_bitmap_delete(b, cur_userchunk);
		assert(bytes_to_unindex < BIGGEST_SANE_ALLOCA);
		total_unindexed += bytes_to_unindex;
		if (total_unindexed >= total_to_unindex)
		{
			if (total_unindexed > total_to_unindex)
			{
				fprintf(stderr, 
					"Warning: unindexed too many bytes "
					"(requested %lu from %p; got %lu)\n",
					total_to_unindex, frame_addr, total_unindexed);
			}
			goto out;
		}
	}
out:
	/* FIXME: be more discriminating in what cache we zap -- only ours or children */
	__liballocs_uncache_all(frame_addr, total_to_unindex);
	if (b) __liballocs_delete_bigalloc_at(bytes_counter, &__stackframe_allocator);
}

static void realloc_bitmap_prepend(struct arena_bitmap_info *info,
	unsigned long new_min_nwords, uintptr_t new_bitmap_base_addr)
{
	if (info->nwords < new_min_nwords)
	{
		// we have to realloc
		void *old_bitmap = info->bitmap;
		unsigned long old_nwords = info->nwords;
		debug_printf(0, "Adding %d words to bitmap (coverage %ld bytes)\n",
			(int)(new_min_nwords - old_nwords),
			(long)((new_min_nwords - old_nwords) * ALLOCA_ALIGN * BITMAP_WORD_NBITS));
		info->bitmap = __private_realloc(info->bitmap, new_min_nwords * sizeof (bitmap_word_t));
		if (!info->bitmap) abort();
		// now we've post-extended the bitmap, but that's not the right thing...
		// we need to move it so that it's pre-extended
		info->nwords = new_min_nwords;
		long nwords_added = info->nwords - old_nwords;
		assert(nwords_added > 0);
		if (!info->bitmap_base_addr)
		{
			info->bitmap_base_addr = (void*)new_bitmap_base_addr;
		}
		else
		{
			info->bitmap_base_addr -= nwords_added * BITMAP_WORD_NBITS * ALLOCA_ALIGN;
			assert(info->bitmap_base_addr == (void*) new_bitmap_base_addr);
		}
		// memmove the old bits rightwards, assuming there are old bits
		if (old_bitmap)
		{
			memmove(info->bitmap + nwords_added, info->bitmap,
				sizeof (bitmap_word_t) * old_nwords);
		}
		// zero the fresh bits, which are at the beginning
		bzero(info->bitmap, sizeof (bitmap_word_t) * nwords_added);
	}
}
static void *first_chunk_addr(struct big_allocation *arena, long *out_bit_idx)
{
	struct arena_bitmap_info *info = arena->suballocator_private;
	unsigned long first_bit_set = bitmap_find_first_set1_geq_l(
		info->bitmap, info->bitmap + info->nwords,
		0, NULL);
	assert(!info->bitmap_base_addr || (uintptr_t) info->bitmap_base_addr == ROUND_DOWN((uintptr_t) arena->begin, ALLOCA_ALIGN*BITMAP_WORD_NBITS));
	if (out_bit_idx) *out_bit_idx = first_bit_set;
	if (first_bit_set == (unsigned long) -1) return NULL;
	return (void*)(info->bitmap_base_addr + first_bit_set * ALLOCA_ALIGN);
}
static void ensure_arena_covers_addr(struct big_allocation *arena,
	void *addr)
{
	/* Extend the frame bigalloc to include this alloca. Note that we're *prepending*
	 * to the allocation. */
	struct arena_bitmap_info *info = arena->suballocator_private;
#ifndef NDEBUG
	long old_first_bit_idx;
	void *old_first_chunk_addr = first_chunk_addr(arena, &old_first_bit_idx);
	void *old_bitmap_base_addr = info->bitmap_base_addr;
	assert(!old_bitmap_base_addr || (uintptr_t) old_bitmap_base_addr == ROUND_DOWN((uintptr_t) arena->begin, ALLOCA_ALIGN*BITMAP_WORD_NBITS));
#endif
	void *old_start = arena->begin;
	if (info->bitmap && (uintptr_t) old_start <= (uintptr_t) addr) return;
	if ((uintptr_t) old_start > (uintptr_t) addr)
	{
		__liballocs_pre_extend_bigalloc_recursive(arena, /*sp_at_caller*/ addr);
	}
	assert((uintptr_t) arena->begin <= (uintptr_t) addr);
	uintptr_t new_bitmap_base_addr = ROUND_DOWN((uintptr_t) arena->begin, ALLOCA_ALIGN*BITMAP_WORD_NBITS);
	// we may not have allocated the bitmap yet, so always call this
	uintptr_t new_bitmap_limit_addr = ROUND_UP((uintptr_t) arena->end, ALLOCA_ALIGN*BITMAP_WORD_NBITS);
	unsigned long new_coverage_nbytes = new_bitmap_limit_addr - new_bitmap_base_addr;
	assert(new_coverage_nbytes % ALLOCA_ALIGN == 0);
	unsigned long new_coverage_naligns = new_coverage_nbytes / ALLOCA_ALIGN;
	realloc_bitmap_prepend(info, /* new min nwords */
		DIVIDE_ROUNDING_UP(
			new_coverage_naligns,
			BITMAP_WORD_NBITS
		),
		new_bitmap_base_addr
	);
	assert((uintptr_t) info->bitmap_base_addr == new_bitmap_base_addr);
#ifndef NDEBUG
	long first_bit_idx;
	void *first_chunk = first_chunk_addr(arena, &first_bit_idx);
	debug_printf(0, "Bitmap base addr moved from %p to %p; first chunk at %p (was: %p) idx %d (was %d)\n",
		(void*) old_bitmap_base_addr, (void*)new_bitmap_base_addr,
		first_chunk, old_first_chunk_addr, (int) first_bit_idx, (int) old_first_bit_idx);
#endif

	// assert that our first chunk position hasn't changed
	assert(old_first_chunk_addr == first_chunk_addr(arena, NULL));
}

/* We have a special connection here. */
struct big_allocation *__stackframe_allocator_find_or_create_bigalloc(
		unsigned long *frame_counter, const void *caller, const void *frame_sp_at_caller, 
		const void *frame_bp_at_caller);

void __alloca_allocator_notify(void *new_userchunkaddr,
		unsigned long requested_size, unsigned long *frame_counter,
		const void *caller, const void *sp_at_caller, const void *bp_at_caller)
{
	assert(malloc_usable_size(new_userchunkaddr) <= BIGGEST_SANE_ALLOCA);
	/* 1. We need to register the current frame as a "big" allocation, or
	 *    if it already is "big", to extend that to cover the current extent.
	 *    NOTE also that the "cracks" case suddenly becomes important: 
	 *    without crack handling, other locals in the frame will suddenly
	 *    become invisible to get_info calls.
	 *    (One quick fix might be to have the frame's first alloca call
	 *    pad the stack to a page boundary, and pad the amount to something
	 *    page-aligned, so that the pageindex always gives an exact hit.)
	 */
	// XXX: sp as passed by caller is unreliable -- can come out much higher
	// than the actual post-alloca rsp. Not sure why. But can use the chunk addr
	// as our stack lower bound.
	//assert((char*) new_userchunkaddr >= (char*) sp_at_caller);
	struct big_allocation *b = __stackframe_allocator_find_or_create_bigalloc(
		frame_counter, caller, /*sp_at_caller*/ new_userchunkaddr, bp_at_caller);
	assert(b);
	if (!b->suballocator) b->suballocator = &__alloca_allocator;
	else if (b->suballocator != &__alloca_allocator) abort();
	if (!b->suballocator_private)
	{
		b->suballocator_private = __private_malloc(sizeof (struct arena_bitmap_info));
		bzero(b->suballocator_private, sizeof (struct arena_bitmap_info));
		b->suballocator_private_free = __free_arena_bitmap_and_info;
		// we leave allocating the actual bitmap to the realloc step, below
	}

	ensure_arena_covers_addr(b, new_userchunkaddr);
	/* index it */
	__generic_malloc_bitmap_insert(b, new_userchunkaddr, requested_size, caller);
	
#undef __liballocs_get_alloc_base /* inlcache HACKaround */
	assert(__liballocs_get_alloc_base(new_userchunkaddr));
	assert(((void*(*)(void*))(__liballocs_get_alloc_base))(new_userchunkaddr) == new_userchunkaddr);
}

