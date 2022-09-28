#define _GNU_SOURCE

#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include "liballocs.h"
#include "liballocs_private.h"
#include "allocsites.h"
#include "relf.h"
/* This alias needs to go before generic_malloc_index.h because of
 * the aliasing HACK in that file, which will #define __liballocs_free_arena_bitmap_and_info. */
void __liballocs_free_arena_bitmap_and_info(void *info)
__attribute__((alias("__free_arena_bitmap_and_info")));

#include "generic_malloc_index.h" /* FIXME: want to remove this */

/* These definitions need to go somewhere. But they are used mostly by our
 * hooks, not by the allocsites routines in the rest of this file. */
#ifndef NO_TLS
__thread void *__current_allocsite;
__thread void *__current_allocfn;
__thread size_t __current_allocsz;
__thread int __currently_freeing;
__thread int __currently_allocating;
#else
void *__current_allocsite;
void *__current_allocfn;
size_t __current_allocsz;
int __currently_freeing;
int __currently_allocating;
#endif
// ditto this!
#include "allocmeta.h"
__attribute__((visibility("hidden")))
void __free_arena_bitmap_and_info(void *info /* really struct arena_bitmap_info * */)
{
	struct arena_bitmap_info *the_info = info;
	if (the_info && the_info->bitmap) __private_free(the_info->bitmap);
	if (the_info) __private_free(the_info);
}

/* Each allocsite is logically assigned a contiguous
 * ID, defined as the sum of its index in the allocsite array
 * and its file's "base ID" (or start_id). The lookup
 * allocsites_vectors_by_base_id
 * is a "spine" for these per-DSO arrays, sorted by "start_id". */
struct allocsites_vectors_by_base_id_entry
allocsites_vectors_by_base_id[ALLOCSITES_INDEX_SIZE];

/* Positions in the id array are issued sequentially */
allocsite_id_t allocsites_id_entry_slot_next_free  __attribute__((visibility("hidden")));

void init_allocsites_info(struct allocs_file_metadata *file)
{
	if (!file->meta_obj_handle) return;
	ElfW(Sym) *found = gnu_hash_lookup(
			get_gnu_hash(file->meta_obj_handle),
			get_dynsym(file->meta_obj_handle),
			get_dynstr(file->meta_obj_handle),
			"allocsites");
	if (found)
	{
		struct allocsite_entry *first_entry = sym_to_addr(found);
		/* We maintain a linear spine of allocation site lists, so that
		 * every allocation site in any loaded object has a smallish
		 * integer index that is issued sequentially. */
		unsigned slot_pos = allocsites_id_entry_slot_next_free++;
		if (slot_pos > ALLOCSITES_INDEX_SIZE) abort();
		file->allocsites_info = &allocsites_vectors_by_base_id[slot_pos];
		allocsite_id_t start_id;
		if (slot_pos == 0) start_id = 0;
		else
		{
			start_id = allocsites_vectors_by_base_id[slot_pos - 1].start_id
				+ allocsites_vectors_by_base_id[slot_pos - 1].count;
			if (start_id < allocsites_vectors_by_base_id[slot_pos - 1].start_id)
			{ /* We've overflowed. */ abort(); }
		}
		allocsites_vectors_by_base_id[slot_pos]
		 = (struct allocsites_vectors_by_base_id_entry) {
			.start_id = start_id,
			.count = found->st_size / sizeof (struct allocsite_entry),
			.file_base_addr = file->m.l->l_addr,
			.ptr = first_entry 
		};
		file->allocsites_info = &allocsites_vectors_by_base_id[slot_pos];
	}
}

static struct allocs_file_metadata *get_file(const void *allocsite)
{
	struct big_allocation *file_bigalloc = __lookup_bigalloc_from_root(allocsite,
		&__static_file_allocator, NULL);
	assert(file_bigalloc && "file bigallocs have not been initialized");
	struct allocs_file_metadata *file = file_bigalloc->allocator_private;
	return file;
}

struct allocsite_entry *__liballocs_find_allocsite_entry_at(
	const void *allocsite)
{
	struct allocs_file_metadata *file = get_file(allocsite);
	uintptr_t allocsite_vaddr = (uintptr_t) allocsite - file->m.l->l_addr;
	if (!file->allocsites_info) return NULL;
	struct allocsite_entry *start = file->allocsites_info->ptr;
	/* Now we do a binary search inside the allocsites array. */
#define proj(p) ((p)->allocsite_vaddr)
	struct allocsite_entry *found
	= bsearch_leq_generic(struct allocsite_entry,
		/* target */ allocsite_vaddr,
		file->allocsites_info->ptr,
		/* n */ file->allocsites_info->count,
		proj);
#undef proj
	return found;
}

allocsite_id_t __liballocs_allocsite_id(const void *allocsite)
{
	struct allocs_file_metadata *file = get_file(allocsite);
	struct allocsite_entry *found_entry
	 = __liballocs_find_allocsite_entry_at(allocsite);
	if (!found_entry) return (allocsite_id_t) -1;
	return file->allocsites_info->start_id + (found_entry - file->allocsites_info->ptr);
}

struct allocsite_entry *__liballocs_allocsite_entry_by_id(allocsite_id_t id,
	uintptr_t *out_file_base_addr)
{
#define proj(p) (p)->start_id
	struct allocsites_vectors_by_base_id_entry *found_id_entry
	 = bsearch_leq_generic(struct allocsites_vectors_by_base_id_entry,
		id,
		allocsites_vectors_by_base_id,
		allocsites_id_entry_slot_next_free,
		proj);
#undef proj
	if (!found_id_entry) return NULL;
	if (out_file_base_addr) *out_file_base_addr = found_id_entry->file_base_addr;
	assert(found_id_entry->start_id <= id);
	return found_id_entry->ptr + (id - found_id_entry->start_id);
}
const void *__liballocs_allocsite_by_id(allocsite_id_t id)
{
	uintptr_t file_base_addr;
	struct allocsite_entry *entry = __liballocs_allocsite_entry_by_id(id, &file_base_addr);
	if (!entry) return NULL;
	return (void*)(file_base_addr + entry->allocsite_vaddr);
}
