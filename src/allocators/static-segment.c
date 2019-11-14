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

static _Bool trying_to_initialize;
static _Bool initialized;

void __static_segment_allocator_init(void) __attribute__((constructor(102)));
void __static_segment_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__static_file_allocator_init();
		/* We have nothing to init ourselves. */
		initialized = 1;
		trying_to_initialize = 0;
	}
}
/* In the most natural/direct model, children of the segment
 * may be sections or symbols, i.e. some symbols are not in
 * any section, and some ELF files do not have any section
 * headers at all. How common is this? How can we regularise
 * this? Rather than create dummy sections, we have only one
 * bitmap per segment. */

void __static_segment_allocator_notify_define_segment(
	struct file_metadata *file,
	unsigned phndx,
	unsigned loadndx
)
{
	if (!initialized) __static_segment_allocator_init();
	assert(initialized || trying_to_initialize);
	ElfW(Phdr) *phdr = &file->phdrs[phndx];
	const void *segment_start_addr = (char*) file->l->l_addr + phdr->p_vaddr;
	size_t segment_size = phdr->p_memsz;
	struct big_allocation *containing_file = __lookup_bigalloc_from_root(
		segment_start_addr, &__static_file_allocator, NULL);
	if (!containing_file) abort();

	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) segment_start_addr,
		segment_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = &file->segments[loadndx],
					.free_func = NULL
				}
			}
		},
		containing_file,
		&__static_segment_allocator /* allocated_by */
	);
	/* What's the suballocator? For the executable's data segment,
	 * a malloc will be the suballocator. But sections will be
	 * child bigallocs so that is OK -- we still only have one true
	 * suballocator. FIXME: what if we have syms directly underneath?
	 * Syms may or may not be part of a section... the not-part case
	 * may be tricky with this arrangement. */
	if ((uintptr_t) segment_start_addr == executable_data_segment_start_addr)
	{
		/* Here we rely on both sections and segments always being bigallocs,
		 * so the only suballocator of the data segment is the generic malloc.
		 * Of course the sections may themselves have suballocators (the symbol
		 * allocator). This may be a problem when we start to hang the bitmaps
		 * on places, because we want the bitmaps to be per-segment not
		 * per-section. It might be better to invert this: create a brk bigalloc,
		 * and the malloc becomes the suballocator under there while the
		 * segment is suballocated by the symbols (?). */
		executable_data_segment_bigalloc = b;
		// the data segment always extends as far as the file+mapping do (should be the same)
		assert(b->parent);
		assert(b->parent->parent);
		assert(b->parent->parent->end == b->parent->end);
		__adjust_bigalloc_end(b, b->parent->end);
		b->suballocator = &__generic_malloc_allocator;
	}
	/* Fill in the per-segment info that is stored in the file metadata. */
	union sym_or_reloc_rec *metavector = NULL;
	size_t metavector_size = 0;
	if (file->meta_obj_handle)
	{
#define METAVEC_SYM_PREFIX "metavec_0x"
		char buf[sizeof METAVEC_SYM_PREFIX+8]; // 8 bytes + NUL
		snprintf(buf, sizeof buf, METAVEC_SYM_PREFIX "%x", (unsigned) phdr->p_vaddr);
#undef METAVEC_SYM_PREFIX
		void *found = fake_dlsym(file->meta_obj_handle, buf);
		if (found && found != (void*) -1)
		{
			metavector = found;
			// what about the size?
			ElfW(Sym) *found_sym = gnu_hash_lookup(
				get_gnu_hash(file->meta_obj_handle),
				get_dynsym(file->meta_obj_handle),
				get_dynstr(file->meta_obj_handle),
				buf);
			assert(found_sym);
			metavector_size = found_sym->st_size;
		}
	}
	file->segments[loadndx] = (struct segment_metadata) {
		.phdr_idx = phndx,
		.metavector = metavector,
		.metavector_size = metavector_size
				/*,
		.starts_bitmap = */
	};
}
_Bool __static_segment_allocator_notify_brk(void *new_curbrk)
{
	if (!initialized) return 0; // not ready yet
	if (!__static_file_allocator_notify_brk(new_curbrk)) return 0; // not ready yet
	__adjust_bigalloc_end(executable_data_segment_bigalloc, new_curbrk);
	return 1;
}

void __static_segment_allocator_notify_destroy_segment(
	ElfW(Phdr) *phdr
)
{
	/* I think we don't have to do anything -- the usual bigalloc
	 * teardown also tears down children and frees their metadata. */
}

static liballocs_err_t get_info(void *obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* The only allocation we have is the bigalloc, so it's easy. */
	assert(b);
	if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;
	if (out_base) *out_base = b->begin;
	if (out_site) *out_site =
			((struct file_metadata *) (b->parent->meta.un.opaque_data.data_ptr))
				->load_site;
	if (out_size) *out_size = (char*) b->end - (char*) b->begin;
	return NULL;
}

DEFAULT_GET_TYPE

struct allocator __static_segment_allocator = {
	.name = "static-segment",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
