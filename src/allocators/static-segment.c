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
		/*dl_iterate_phdr(add_all_loaded_segments, NULL);*/
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
struct segment_metadata
{
	const Elf64_Phdr *phdr; /* we assume the ld.so keeps these (or a copy) in memory */
	unsigned long *bits;
	unsigned long *bits_limit;
	unsigned short *alloc_idx_scaled_vec;   /* one entry per NN bytes, recording
	                                         * the sorted_vec idx of the last-starting
	                                         * vec entry *prior* to that range in memory.
	                                         * (why prior?)
	                                         * The scaled vec is per-segment. BUT
	                                         * the sorted vec itself is maintained per-file!
	                                         * Why? surely per-segment is better?
	                                         * NO; remember it's not a bitmap! We maintain
	                                         * it from per-file structures (meta-objs,
	                                         * symtabs, etc.) so it's better to do it filewise. */
};

static void free_segment_metadata(void *sm)
{
	struct segment_metadata *s = (struct segment_metadata *) sm;
	__wrap_dlfree(sm);
}

void __static_segment_allocator_notify_define_segment(
	struct file_metadata *file,
	int i
)
{
	if (!initialized && !trying_to_initialize) __static_segment_allocator_init();
	ElfW(Phdr) *phdr = &file->phdrs[i];
	const void *segment_start_addr = (char*) file->l->l_addr + phdr->p_vaddr;
	size_t segment_size = phdr->p_memsz;
	struct big_allocation *containing_file = __lookup_bigalloc(
		segment_start_addr, &__static_file_allocator, NULL);
	if (!containing_file) abort();
	struct segment_metadata *m = __wrap_dlmalloc(sizeof (struct segment_metadata));
	*m = (struct segment_metadata) {
		.phdr = phdr,
		.bits = &(*file->starts_bitmaps)[i],
		.bits_limit = &(*file->starts_bitmaps)[i] + STARTS_BITMAP_NWORDS_FOR_PHDR(phdr),
		.alloc_idx_scaled_vec = NULL /* FIXME: implement this */
	};

	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) segment_start_addr,
		segment_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = (void*) m,
					.free_func = &free_segment_metadata
				}
			}
		},
		containing_file,
		&__static_segment_allocator
	);
	b->suballocator = &__static_section_allocator; // HMM: what if we have syms directly underneath?
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
