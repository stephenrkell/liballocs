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
#include <limits.h>
#include <link.h>
#include "relf.h"
#include "liballocs_private.h"
#include "pageindex.h"
#include "raw-syscalls.h"
#include "allocmeta.h"

static _Bool trying_to_initialize;
static _Bool initialized;

void __static_section_allocator_init(void) __attribute__((constructor(102)));
void __static_section_allocator_init(void)
{
	/* Sections are created by the static file allocator,
	 * so there is nothing to do.  */
}
struct section_metadata
{
	const Elf64_Shdr *shdr; /* should *not* be null; we don't create dummy sections */
};

struct big_allocation *__static_section_allocator_ensure_big(
			const void *addr_spanned_by_section,
			ElfW(Shdr) *shdr
		)
{
	struct big_allocation *section_already = __lookup_bigalloc(
		addr_spanned_by_section, &__static_section_allocator, NULL);
	if (section_already) return section_already;
	struct big_allocation *containing_segment = __lookup_bigalloc(
		addr_spanned_by_section, &__static_segment_allocator, NULL);
	if (!containing_segment) abort();

	void *section_start_addr = (char*) containing_segment->parent->begin
			+ shdr->sh_addr;
	struct big_allocation *b = __liballocs_new_bigalloc(
		section_start_addr,
		shdr->sh_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = NULL,
					.free_func = NULL
				}
			}
		},
		containing_segment,
		&__static_section_allocator
	);
	b->suballocator = &__static_symbol_allocator;
	return b;
}

void __static_section_allocator_notify_define_section(
	struct file_metadata *meta,
	const ElfW(Shdr) *shdr
)
{
	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) section_start_addr,
		section_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = (void*) m,
					.free_func = &free_section_metadata
				}
			}
		},
		containing_segment,
		&__static_segment_allocator
	);

	/* We're finished. Adding symbol metadata might make sections
	 * into bigallocs. The file allocator takes care of this.
	 * This is because we want to compute
	 * the list of sorted symbols only once for the whole file.
	 * Similarly, bitmaps are maintained per-segment not per-section,
	 * since not all static alloc (symbols, reloc targets) need be
	 * contained within a section. */
}

static liballocs_err_t get_info(void * obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* FIXME: sections are not alwyas bigallocs,but here we assume they are.
	 * but they needn't be. We can simply use the shdrs mapped
	 * by the file allocator -- they are our metadata vector,
	 * though we need to make them indexed (queryable). */
	if (maybe_bigalloc)
	{
		void *object_start = maybe_bigalloc->begin;
		if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;;
		if (out_base) *out_base = object_start;
		if (out_site) *out_site =
			((struct file_metadata *) (maybe_bigalloc->parent->parent->meta.un.opaque_data.data_ptr))
					->load_site;
		if (out_size) *out_size = /*shdr->sh_size*/
			(char*) maybe_bigalloc->end - (char*) maybe_bigalloc->begin;
		return NULL;
	}
	else
	{
		// FIXME
		return NULL;
	}
	assert(0);
}

DEFAULT_GET_TYPE

struct allocator __static_section_allocator = {
	.name = "static-section",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
