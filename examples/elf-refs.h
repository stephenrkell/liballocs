#ifndef ELF_REFS_H_
#define ELF_REFS_H_

#include <stdint.h>
#include "allocmeta.h"

struct elf_walk_refs_state
{
	struct walk_refs_state ref;
	struct big_allocation *file_bigalloc;
	struct elf_reference *buf; // don't copy this; we need to realloc it
	unsigned buf_capacity;
	unsigned buf_used;
};

struct elf_reference
{
	unsigned long source_file_offset;
	struct uniqtype *reference_type;
	unsigned long target_file_offset; // may be -1, in theory (shouldn't be, for us)
	const char *target_alloc_name;
	unsigned target_offset_from_alloc_start;
	struct uniqtype *referenced_type;
	intptr_t interp_how;
	// HMM: more here
};

intptr_t can_interp_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t,
	struct alloc_tree_link *link);

void *do_interp_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link, intptr_t how);

_Bool may_contain_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link);

uintptr_t is_environ_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link);

int seen_elf_reference_or_pointer_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link_to_here,
	void *elf_walk_refs_state_as_void);

int seen_elf_environ_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link_to_here,
	void *environ_elt_cb_arg_as_void);

#endif
