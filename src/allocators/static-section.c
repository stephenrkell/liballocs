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
			const ElfW(Shdr) *shdr
		)
{
	if (shdr->sh_size == 0) return NULL;
	
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
					.data_ptr = (ElfW(Shdr) *) shdr,
					.free_func = NULL
				}
			}
		},
		containing_segment,
		&__static_section_allocator /* parent */
	);
	b->suballocator = &__static_symbol_allocator; // HMM: symbols are never(?) big, so....
	return b;
}

void __static_section_allocator_notify_define_section(
	struct file_metadata *meta,
	const ElfW(Shdr) *shdr
)
{
	/* We simply create a bigalloc from the off, if we're nonzero-sized.
	 * That might be a bit extravagant. But actually it's necessary!
	 * The data segment's suballocator needs to be a malloc allocator.
	 * By contrast, we (the section allocator) don't need to be marked
	 * as the suballocator of the segment allocator if our allocs are
	 * bigallocs. */
	if (shdr->sh_size > 0)
	{
		__static_section_allocator_ensure_big((char*) meta->l->l_addr + shdr->sh_addr,
			shdr);
	}
}

static liballocs_err_t get_info(void *obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* We may or may not be a bigalloc. Either way, we simply use the shdrs
	 * mapped by the file allocator to answer the query. */
	if (b->allocated_by == &__static_section_allocator)
	{
		void *object_start = b->begin;
		if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;;
		if (out_base) *out_base = object_start;
		if (out_site) *out_site =
			((struct file_metadata *) (b->parent->parent->meta.un.opaque_data.data_ptr))
					->load_site;
		if (out_size) *out_size = /*shdr->sh_size*/
			(char*) b->end - (char*) b->begin;
		return NULL;
	}
	// else we have the containing bigalloc... might be a segment, but we want the file
	while (b->allocated_by != &__static_file_allocator) b = b->parent;
	struct file_metadata *fm = (struct file_metadata *) b->meta.un.opaque_data.data_ptr;
	/* Querying by section is pretty rare. And there are not that many
	 * sections. It doesn't seem worth maintaining a separate sorted
	 * vector per segment or per file. So we just linear-search the
	 * whole shdr vector and return the first match. It must:
	 * 
	 * - fall within our parent bigalloc (segment);
	 * - have SHF_ALLOC.
	 */
	for (unsigned i = 0; i < fm->ehdr->e_shnum; ++i)
	{
		ElfW(Shdr) *shdr = &fm->shdrs[i];
		if ((shdr->sh_flags & SHF_ALLOC)
				&& ((uintptr_t) obj >= fm->l->l_addr + shdr->sh_addr
				&&  (uintptr_t) obj <  fm->l->l_addr + shdr->sh_addr + shdr->sh_size))
		{
			// hit!
			if (out_type) *out_type = NULL;
			if (out_base) *out_base = (void*) fm->l->l_addr + shdr->sh_addr;
			if (out_size) *out_size = shdr->sh_size;
			if (out_site) *out_site = fm->load_site;
			return NULL;
		}
	}
	return &__liballocs_err_unrecognised_static_object;
}

DEFAULT_GET_TYPE

struct allocator __static_section_allocator = {
	.name = "static-section",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
