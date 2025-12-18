#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "liballocs.h"
#include "allocmeta.h"
#include "pageindex.h"


static int n = 0;
static int saw_string_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_containment_ctxt *cont, void *arg)
{
	// printf("Saw a string at %p (%06d): %s\n", obj, n, (char*)obj);
	++n;
	return 0;
}

int main(void)
{
	// let's malloc a thing and then declare it (somehow)
	// a packed sequence, by promoting it and then
	// - clearing its type info (?)
	// - setting it as suballocated by the relevant packed seq
	void *chunk = calloc(1, 131072);
	assert(__liballocs_pageindex[PAGENUM(chunk)]);

	struct big_allocation *seq_b = __lookup_bigalloc_from_root(chunk,
		&__default_lib_malloc_allocator, NULL);
	assert(seq_b->allocated_by == &__default_lib_malloc_allocator);

	seq_b->suballocator = &__packed_seq_allocator;
	seq_b->suballocator_private = malloc(sizeof (struct packed_sequence));
	seq_b->suballocator_private_free = __packed_seq_free;
	// FIXME: clear type info? do we need to?
	__default_lib_malloc_allocator.set_type(seq_b, chunk, NULL);
	if (!seq_b->suballocator_private) abort();
	*(struct packed_sequence *) seq_b->suballocator_private = (struct packed_sequence) {
		.fam = &__string8_nulterm_packed_sequence,
		.enumerate_fn_arg = NULL,
		.name_fn_arg = NULL,
		.un = { .metavector_any = NULL },
		.metavector_nused = 0,
		.metavector_size = 0,
		.starts_bitmap = NULL,
		.starts_bitmap_nwords = 0,
		.offset_cached_up_to = 0
	};
	struct alloc_tree_pos pos = {
		.base = chunk,
		.bigalloc_or_uniqtype = (uintptr_t) seq_b
	};
	__packed_seq_allocator.walk_allocations(&pos, saw_string_cb, NULL, NULL, NULL);
	assert(n == 131072);
	n = 0;
	alloc_walk_allocations(&pos, saw_string_cb, NULL, NULL, NULL);
	assert(n == 131072);
	n = 0;
	__liballocs_walk_allocations_df(&pos, saw_string_cb, NULL);
	// HMM. This is visiting each string twice. And that's correct!
	// After visiting the array, we also visit the individual char that it
	// contains, because we're depth-first.
	assert(n == 262144);
	return 0;
}
