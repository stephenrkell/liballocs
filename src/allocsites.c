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

/* Each allocsite is logically assigned a contiguous
 * ID, defined as the sum of its index in the allocsite array and its file's "start ID".
 * The two lookups allocsites_by_id and allocsites_by_object_base_address_entry
 * are "spines" for these per-DSO arrays, sorted by "start_id" and base address.
 * FIXME: get rid of the by_object_base_address one, and just use the bigalloc
 * looking (pageindex) to get to the per-file metadata. */

/* The two arrays for indexing allocation sites */
struct allocsites_by_id_entry allocsites_by_id[ALLOCSITES_INDEX_SIZE] __attribute__((visibility("hidden")));
struct allocsites_by_object_base_address_entry
	allocsites_by_object_base_address[ALLOCSITES_INDEX_SIZE] __attribute__((visibility("hidden")));
/* Positions in the id array are issued sequentially */
static unsigned short allocsites_id_entry_slot_next_free = 0;

static _Bool by_address_entry_is_unused(const struct allocsites_by_object_base_address_entry *e)
{
	return !e->object_base_address && !e->start_id_plus_one;
}
static _Bool by_id_entry_is_unused(const struct allocsites_by_id_entry *e)
{
	return !e->start_id && !e->count && !e->ptr;
}

static int compare_index_entry(const void *p_k, const void *p_ent)
{
	const struct allocsites_by_object_base_address_entry *e_k = p_k;
	const struct allocsites_by_object_base_address_entry *e_ent = p_ent;
	
	/* We "should return an integer
	   less than, equal to, or greater than zero if the key object is found, respectively, to be
	   less than, to match, or be greater than the array member." */
	
	/* Exception: we treat unused entries as infinitely big,
	 * so that they bunch up at the end. */
	if (by_address_entry_is_unused(e_k) && by_address_entry_is_unused(e_ent)) return 0;
	else if (by_address_entry_is_unused(e_k)) /* it's bigger than e_ent */ return 1;
	else if (by_address_entry_is_unused(e_ent)) return -1;
	
	/* Don't use subtraction, because of risk of overflow. */
	if ((intptr_t) e_k->object_base_address < (intptr_t) e_ent->object_base_address) return -1;
	if ((intptr_t) e_k->object_base_address > (intptr_t) e_ent->object_base_address) return 1;
	return 0;
}
static int compare_allocsite_entry(const void *p_k, const void *p_ent)
{
	const struct allocsite_entry *e_k = p_k;
	const struct allocsite_entry *e_ent = p_ent;
	
	/* We "should return an integer
	   less than, equal to, or greater than zero if the key object is found, respectively, to be
	   less than, to match, or be greater than the array member." */
	
	/* Don't use subtraction, because of risk of overflow. */
	if ((uintptr_t) e_k->allocsite < (uintptr_t) e_ent->allocsite) return -1;
	if ((uintptr_t) e_k->allocsite > (uintptr_t) e_ent->allocsite) return 1;
	return 0;
}
static int search_compare_by_address_entry(const void *p_k, const void *p_ent)
{
	/* This one is a bit different. We return EQUAL if the key is >= the entry
	 * and < the next entry. */
	const struct allocsites_by_object_base_address_entry *e_k = p_k;
	const struct allocsites_by_object_base_address_entry *e_ent = p_ent;

	/* If the entry is unused, the key is LESS than it. */
	assert(!by_address_entry_is_unused(e_k));
	if (by_address_entry_is_unused(e_ent)) return -1;
	
	/* Don't use subtraction, because of risk of overflow. */
	uintptr_t key_address = (uintptr_t) e_k->object_base_address;
	/* Do we have a next entry? */
	_Bool entry_is_last = ((e_ent - &allocsites_by_object_base_address[0]) == ALLOCSITES_INDEX_SIZE)
		|| by_address_entry_is_unused(e_ent + 1);
	if (
		(entry_is_last && key_address >= (uintptr_t) e_ent->object_base_address)
	|| (!entry_is_last && key_address >= (uintptr_t) e_ent->object_base_address
							&& key_address < (uintptr_t) (e_ent + 1)->object_base_address)
		) return 0;
				
	if (key_address < (uintptr_t) e_ent->object_base_address) return -1;
	if (key_address > (uintptr_t) e_ent->object_base_address) return 1;
	
	assert(0 && "unreachable");
	return 0;
}
static int search_compare_by_id_entry(const void *p_k, const void *p_ent)
{
	const struct allocsites_by_id_entry *e_k = p_k;
	const struct allocsites_by_id_entry *e_ent = p_ent;

	/* If the key is unused, the key is LESS than it. */
	assert(!by_id_entry_is_unused(e_k));
	if (by_id_entry_is_unused(e_ent)) return -1;
	
	/* Don't use subtraction, because of risk of overflow. */
	unsigned short key_id = e_k->start_id;
	/* Do we have a next entry? */
	_Bool entry_is_last = ((e_ent - &allocsites_by_id[0]) == ALLOCSITES_INDEX_SIZE)
		|| by_id_entry_is_unused(e_ent + 1);
	if (
		(entry_is_last && key_id >= e_ent->start_id)
	|| (!entry_is_last && key_id >= e_ent->start_id
							&& key_id < (e_ent + 1)->start_id)
		) return 0;
				
	if (key_id < e_ent->start_id) return -1;
	if (key_id > e_ent->start_id) return 1;
	
	assert(0 && "unreachable");
	return 0;
}
unsigned issue_allocsites_ids(unsigned count, struct allocsite_entry *first_entry,
	const void *object_base_address)
{
	/* We maintain a linear spine of allocation site lists, so that
	 * every allocation site in any loaded object has a smallish
	 * integer index that is issued sequentially. */
	unsigned slot_pos = allocsites_id_entry_slot_next_free++;
	if (slot_pos > ALLOCSITES_INDEX_SIZE) abort();
	unsigned short start_id;
	if (slot_pos == 0) start_id = 0;
	else
	{
		start_id = allocsites_by_id[slot_pos - 1].start_id
			+ allocsites_by_id[slot_pos - 1].count;
		if (start_id < allocsites_by_id[slot_pos - 1].start_id)
		{ /* We've overflowed. */ abort(); }
	}
	allocsites_by_id[slot_pos]
	 = (struct allocsites_by_id_entry) { .start_id = start_id, .count = count,
		.ptr = first_entry };
	/* for the by-address look-up, just plonk it in an unused position
	 * and then qsort. */
	assert(by_address_entry_is_unused(&allocsites_by_object_base_address[slot_pos]));
	allocsites_by_object_base_address[slot_pos]
	 = (struct allocsites_by_object_base_address_entry) {
		.object_base_address = object_base_address,
		.start_id_plus_one = start_id + 1,
		.by_id = &allocsites_by_id[slot_pos]
	};
	qsort(allocsites_by_object_base_address,
		ALLOCSITES_INDEX_SIZE,
		sizeof allocsites_by_object_base_address[0],
		compare_index_entry
	);
	return start_id;
}
struct allocsites_by_object_base_address_entry *__liballocs_find_allocsite_lookup_entry(
	const void *allocsite)
{
	struct allocsites_by_object_base_address_entry fake_entry_as_key =
	{ .object_base_address = allocsite };
	
	void *found = bsearch(&fake_entry_as_key,
		allocsites_by_object_base_address,
		ALLOCSITES_INDEX_SIZE,
		sizeof allocsites_by_object_base_address[0],
		search_compare_by_address_entry
	);
	
	if (found) return found;
	return NULL;
}

struct allocsite_entry *__liballocs_find_allocsite_entry_in_object(
	const void *allocsite, struct allocsites_by_object_base_address_entry *obj_base_entry)
{
	struct allocsite_entry fake_allocsite = {
		.allocsite = (void*) allocsite
	};
	struct allocsite_entry *start = obj_base_entry->by_id->ptr;
	/* Now we do a second binary search inside the allocsites array. */
	void *found = bsearch(&fake_allocsite,
		start,
		obj_base_entry->by_id->count,
		sizeof (struct allocsite_entry),
		compare_allocsite_entry
	);
	if (found) return found;
	return NULL;
}
struct allocsite_entry *__liballocs_find_allocsite_entry(
	const void *allocsite)
{
	struct allocsites_by_object_base_address_entry *found_object_entry
	 = __liballocs_find_allocsite_lookup_entry(allocsite);
	if (!found_object_entry) return NULL;
	return __liballocs_find_allocsite_entry_in_object(
		allocsite, found_object_entry);
}

unsigned short __liballocs_allocsite_id(const void *allocsite)
{
	struct allocsites_by_object_base_address_entry *found_object_entry
	 = __liballocs_find_allocsite_lookup_entry(allocsite);
	if (!found_object_entry) goto fail;
	
	struct allocsite_entry *found_entry = __liballocs_find_allocsite_entry_in_object(allocsite,
		found_object_entry);
	if (!found_entry) goto fail;
	
	return found_object_entry->by_id->start_id + (found_entry - found_object_entry->by_id->ptr);
fail:
	return (unsigned short) -1;
}

struct allocsite_entry *__liballocs_allocsite_entry_by_id(unsigned short id)
{
	struct allocsites_by_id_entry fake_entry_as_key =
	{ .start_id = id };
	
	struct allocsites_by_id_entry *found_id_entry
	 = bsearch(&fake_entry_as_key,
		allocsites_by_id,
		ALLOCSITES_INDEX_SIZE,
		sizeof allocsites_by_id[0],
		search_compare_by_id_entry
	);
	
	if (!found_id_entry) return NULL;
	assert(found_id_entry->start_id <= id);
	return found_id_entry->ptr + (id - found_id_entry->start_id);
}
const void *__liballocs_allocsite_by_id(unsigned short id)
{
	struct allocsite_entry *entry = __liballocs_allocsite_entry_by_id(id);
	if (!entry) return NULL;
	return entry->allocsite;
}
