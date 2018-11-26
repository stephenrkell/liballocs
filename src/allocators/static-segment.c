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
 * bitmap per segment,s */
struct segment_metadata
{
	const Elf64_Phdr *phdr; /* we assume the ld.so keeps these (or a copy) in memory */
	unsigned long *bits;
	unsigned long *bits_limit;
	unsigned short *alloc_idx_scaled_vec;   /* one entry per NN bytes, recording
	                                         * the sorted_vec idx of the last-starting
	                                         * vec entry *prior* to that range in memory.
	                                         * The sorted vec itself is maintained per-file. */
};

static void free_segment_metadata(void *sm)
{
	struct segment_metadata *s = (struct segment_metadata *) sm;
	__wrap_dlfree(sm);
}

static void initialize_segment_bitmap_symbol_starts(struct file_metadata *meta,
	struct segment_metadata *seg)
{
	/* Scan the shdrs for any REL or RELA sections that
	 * apply to sections falling within this segment. We will use
	 * them to mark additional object starts in the bitmap.
	 * Note that it's the *target* section of the *reloc*
	 * that we care about, i.e. whatever section the symtab
	 * entry points to. The relocated section is not
	 * interesting to us. */
	for (unsigned i_sec = 0; i_sec < meta->ehdr->e_shnum; ++i_sec)
	{
		if ((meta->shdrs[i_sec].sh_type == SHT_REL
				|| meta->shdrs[i_sec].sh_type == SHT_RELA)
			&& meta->shdrs[i_sec].sh_info != 0 /* ignores .rela.dyn */
			&& 0 != (meta->shdrs[meta->shdrs[i_sec].sh_info].sh_flags & SHF_ALLOC)
				/* ignore relocs for non-allocated sections */
		   )
		{
			_Bool is_rela = (meta->shdrs[i_sec].sh_type == SHT_RELA);
			/* Scan the relocs and find whether their target section
			 * is within this section. */
			unsigned symtab_scn = meta->shdrs[i_sec].sh_link;
			ElfW(Sym) *symtab = (ElfW(Sym) *)(
				(char*) file_mapping + meta->shdrs[symtab_scn].sh_offset);
			unsigned nrel = meta->shdrs[i_sec].sh_size / 
				(is_rela ? sizeof (ElfW(Rela)) : sizeof (ElfW(Rel)));
			void *tbl_base = (char*) file_mapping + meta->shdrs[i_sec].sh_offset;
			ElfW(Rela) *rela_base = is_rela ? (ElfW(Rela) *) tbl_base : NULL;
			ElfW(Rel) *rel_base = is_rela ? NULL : (ElfW(Rel) *) tbl_base;
			for (unsigned i = 0; i < nrel; ++i)
			{
				/* Is this relocation referencing a section symbol?
				 * FIXME: this is ELF64-specific. */
				Elf64_Xword info = is_rela ? rela_base[i].r_info : rel_base[i].r_info;
				unsigned symind = ELF64_R_SYM(info);
				if (symind
						&& ELF64_ST_TYPE(symtab[symind].st_info) == STT_SECTION)
				{
					/* NOTE that the *referenced vaddr* is *not*
					 * the r_offset i.e. the relocation site.
					 * It's the vaddr of the referenced section symbol,
					 * i.e. of the referenced section,
					 * plus the addend if any. */
					unsigned shndx = symtab[symind].st_shndx;
					Elf64_Sword referenced_vaddr
						= meta->shdrs[shndx].sh_addr + 
							(is_rela ? rela_base[i].r_addend : 0);
					if (referenced_vaddr >= segment_base_vaddr
						&& referenced_vaddr < segment_limit_vaddr)
					{
						/* The referenced in-section location 
						 * is contained in this segment. Consider it
						 * an object start IFF no symbol overlaps it. */
						Elf64_Addr addr = referenced_vaddr;
						void *found = bsearch(&addr,
							file->all_syms_sorted, n_dynsym + n_symtab, sizeof (ElfW(Sym)),
							sym_addr_size_search);
						if (!found
							|| ((ElfW(Sym) *)found)->st_value > addr
							|| ((ElfW(Sym) *)found)->st_value
								+ ((ElfW(Sym) *)found)->st_size <= addr)
						{
							off_t offset_from_segment_base = referenced_vaddr
								- segment_base_vaddr;
							bitmap_set((unsigned long *) seg->bits,
								offset_from_segment_base);
						}
					}
				}
			}
		}
	}
}

static void initialize_segment_bitmap(struct file_metadata *meta,
	struct segment_metadata *seg)
{
	// linear scan of dynsym, using the sorted array
	// looking for symbols falling within this segment
	// FIXME: don't do linear scan; search for segment start address
	if (meta->all_syms_sorted)
	{
		for (unsigned i = 0; i < n_dynsym + n_symtab; ++i) // FIXME: do even if !dynsym
		{
			if (all_syms_sorted[i].st_size > 0) // only add range symbols
			{
				unsigned long sym_vaddr = all_syms_sorted[i].st_value;
				if (sym_vaddr >= segment_base_vaddr
						&& sym_vaddr < segment_limit_vaddr)
				{
					off_t offset_from_segment_base = sym_vaddr - segment_base_vaddr;
					bitmap_set((unsigned long *) seg->bits,
						offset_from_segment_base);
				}
			}
		}
	}
	assert(meta->shdrs);
	initialize_segment_bitmap_symbol_starts(meta, seg);
}

void __static_segment_allocator_notify_define_segment(
	struct file_metadata *meta,
	const ElfW(Phdr) *phdr
)
{
	if (!initialized && !trying_to_initialize) __static_segment_allocator_init();
	const void *segment_start_addr = (char*) load_addr + phdr->p_vaddr;
	size_t segment_size = phdr->p_memsz;
	struct big_allocation *containing_file = __lookup_bigalloc(
		segment_start_addr, &__static_file_allocator, NULL);
	if (!containing_file) abort();
	size_t bitmap_size_bytes = (7 + info->dlpi_phdr[i].p_memsz) / 8;
	size_t prefix_size = ROUND_UP(sizeof (struct segment_metadata), sizeof (unsigned long));
	size_t alloc_size = prefix_size + bitmap_size_bytes;
	struct segment_metadata *m = __wrap_dlmalloc(sizeof (struct segment_metadata));
	*m = (struct segment_metadata) {
		.phdr = phdr,
		.bits = (unsigned long *) ((char*) m + prefix_size),
		.bits_limit = (unsigned long *) ((char*) m + prefix_size + bitmap_size_bytes),
		.alloc_idx_scaled_vec = 
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
	b->suballocator = &__static_section_allocator;

	/* Now define sections for all the allocated sections in the shdrs
	 * which overlap this phdr. */
	for (ElfW(Shdr) *shdr = shdrs; shdr != shdrs + shnum; ++shdr)
	{
		if ((shdr->sh_flags & SHF_ALLOC) &&
				shdr->sh_addr >= phdr->p_vaddr &&
				shdr->sh_addr + shdr->sh_size < phdr->p_vaddr + phdr->p_memsz)
		{
			__static_section_allocator_notify_define_section(meta, shdr);
		}
	}
	
	/* Now do the symbols (and reloc-pointed-to rodata). */
	initialize_segment_bitmap(meta, m);
}

void __static_segment_allocator_notify_destroy_segment(
	ElfW(Phdr) *phdr
)
{
	/* I think we don't have to do anything -- the usual bigalloc
	 * teardown also tears down children and frees their metadata. */
}

static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* The only allocation we have is the bigalloc, so it's easy. */
	assert(maybe_bigalloc);
	if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;
	if (out_base) *out_base = maybe_bigalloc->begin;
	if (out_site) *out_site =
			((struct file_metadata *) (maybe_bigalloc->parent->meta.un.opaque_data.data_ptr))
				->load_site;
	if (out_size) *out_size = (char*) maybe_bigalloc->end - (char*) maybe_bigalloc->begin;
	return NULL;
}

DEFAULT_GET_TYPE

struct allocator __static_segment_allocator = {
	.name = "static-segment",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
