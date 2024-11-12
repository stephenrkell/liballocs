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
#include "raw-syscalls-defs.h"

/* static */ _Bool __static_segment_allocator_trying_to_initialize __attribute__((visibility("hidden")));
#define trying_to_initialize __static_segment_allocator_trying_to_initialize
static _Bool initialized;

void ( __attribute__((constructor(102))) __static_segment_allocator_init)(void)
{
	if (!initialized && !trying_to_initialize)
	{
		/* Initialize what we depend on. This might do nothing if we
		 * are already in the middle of doing this init. How do we
		 * ensure that we always come back here to do *our* init?
		 * Firstly, the static file allocator calls *us* when it's done.
		 * Secondly, we don't set our "trying" flag until *it's* inited,
		 * so that call will not give up saying "doing it". */
		__static_file_allocator_init();
		trying_to_initialize = 1;
		/* That's all. */
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
void __static_segment_setup_metavector(
		struct allocs_file_metadata *afile,
		unsigned phndx,
		unsigned loadndx
	)
{
	ElfW(Phdr) *phdr = &afile->m.phdrs[phndx];
	union sym_or_reloc_rec *metavector = NULL;
	size_t metavector_size = 0;
	if (afile->meta_obj_handle)
	{
#define METAVEC_SYM_PREFIX "metavec_0x"
		char buf[sizeof METAVEC_SYM_PREFIX+8]; // 8 bytes + NUL
		snprintf(buf, sizeof buf, METAVEC_SYM_PREFIX "%x", (unsigned) phdr->p_vaddr);
#undef METAVEC_SYM_PREFIX
		void *found = fake_dlsym(afile->meta_obj_handle, buf);
		if (found && found != (void*) -1)
		{
			metavector = found;
			// what about the size?
			ElfW(Sym) *found_sym = gnu_hash_lookup(
				get_gnu_hash(afile->meta_obj_handle),
				get_dynsym(afile->meta_obj_handle),
				get_dynstr(afile->meta_obj_handle),
				buf);
			assert(found_sym);
			metavector_size = found_sym->st_size;
		}
	}
	else
	{
		debug_printf(5, "no meta object loaded for %s\n", afile->m.l->l_name);
	}
	assert(afile->m.segments[loadndx].phdr_idx == phndx); // librunt has already done it
	afile->m.segments[loadndx].metavector = metavector;
	afile->m.segments[loadndx].metavector_size = metavector_size;
}

void __real___runt_segments_notify_define_segment(struct file_metadata *file, unsigned phndx, unsigned loadndx);
void __static_segment_allocator_notify_define_segment(
	struct file_metadata *file_,
	unsigned phndx,
	unsigned loadndx
)
{
	/* To avoid confusion, don't use "file" in this function
	 * (that's why I called it "file_"). */
	struct allocs_file_metadata *afile = CONTAINER_OF(file_, struct allocs_file_metadata, m);
	/* DON'T check for liballocs's global initializedness here.
	 * Because the only thing we need to initialize is the data segment
	 * bigalloc end, we can only become fully initialized once our
	 * depended-on allocators (static file, mmap) are fully initialized.
	 * But the file allocator calls *us* during *its* initialization.
	 * So this function has to work even if we're not fully initialized yet. */
	ElfW(Phdr) *phdr = &afile->m.phdrs[phndx];
	const void *segment_start_addr = (char*) afile->m.l->l_addr + phdr->p_vaddr;
	size_t segment_size = phdr->p_memsz;

	/* librunt does the outcalls to set up segments, so for us to run,
	 * we  need to be a wrapper of the librunt call. We call its __real_
	 * one to do the basics. */
	__real___runt_segments_notify_define_segment(&afile->m, phndx, loadndx);
	/* Now librunt has set up a dummy segment_metadata for us; we mostly
	 * just have to do the bigalloc stuff and fill it in the metavector. */

	struct big_allocation *containing_file = __lookup_bigalloc_from_root(
		segment_start_addr, &__static_file_allocator, NULL);
	if (!containing_file) abort();

	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) segment_start_addr,
		segment_size,
		&afile->m.segments[loadndx], /* allocator_private */
					/* HMM. This will often "overflow" the 1-element array. So we
					 * are really trusting the compiler not to know that. */
		NULL /* allocator_private_free */,
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
		assert(BIDX(b->parent)); // the segment's parent is the file
		assert(BIDX(BIDX(b->parent)->parent)); // the parent's parent is the mapping, which includes brk area
		// with the brk area included, we may extend further than the segment
		assert((uintptr_t) BIDX(BIDX(b->parent)->parent)->end >= (uintptr_t) BIDX(b->parent)->end);
		// the end of the segment is the end of the file
		__adjust_bigalloc_end(b, BIDX(b->parent)->end);
		b->suballocator = &__static_symbol_allocator;
	}
	/* Fill in the per-segment info that is stored in the file metadata. */
	__static_segment_setup_metavector(afile, phndx, loadndx);
}
void __wrap___runt_segments_notify_define_segment(struct file_metadata *file, unsigned phndx, unsigned loadndx) __attribute__((alias("__static_segment_allocator_notify_define_segment")));

void __real___runt_segments_notify_destroy_segment(ElfW(Phdr) *phdr);
void __static_segment_allocator_notify_destroy_segment(ElfW(Phdr) *phdr)
{
	/* I think we don't have to do anything -- the usual bigalloc
	 * teardown also tears down children and frees their metadata.
	 * But call the runt version for good measure. */
	__real___runt_segments_notify_destroy_segment(phdr);
}
void __wrap___runt_segments_notify_destroy_segment(ElfW(Phdr) *phdr) __attribute__((alias("__static_segment_allocator_notify_destroy_segment")));

static liballocs_err_t get_info(void *obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* The only allocation we have is the bigalloc, so it's easy. */
	assert(b);
	if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;
	if (out_base) *out_base = b->begin;
	if (out_site) *out_site =
			((struct file_metadata *) (BIDX(b->parent)->allocator_private))
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
