#include "uniqtype-defs.h"
#include "allocmeta.h"
#include "metavec.h"

/* Try to write this so that the logic might run *both* in liballocs
 * *and* in a standalone tool. */

void set_bit(struct segment_metadata *seg, ElfW(Addr) start_vaddr_in_file, void *segment_metadata_arg)
{
	
}
static void initialize_segment_bitmap_symbol_starts(struct file_metadata *meta,
	struct segment_metadata *seg)
{
	enumerate_starts(meta, set_bit, seg);
}
static void enumerate_reloc_starts_from_section(struct file_metadata *meta, void *file_temp_mapping,
	ElfW(Half) relscnidx, ElfW(Half) relscntype)
{
	_Bool is_rela = (relscntype == SHT_RELA);
	/* Scan the relocs and find whether their target section
	 * is within this section. */
	unsigned symtab_scn = meta->shdrs[relscnidx].sh_link;
	/* We need to get hold of the symtab content. */
	ElfW(Sym) *symtab = __static_file_allocator_get_symtab_by_idx(meta, symtab_scn);
	unsigned nrel = meta->shdrs[relscnidx].sh_size / 
		(is_rela ? sizeof (ElfW(Rela)) : sizeof (ElfW(Rel)));
	void *tbl_base = (char*) file_mapping + meta->shdrs[relscnidx].sh_offset;
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

static void enumerate_starts(struct file_metadata *file, void *file_temp_mapping,
	void (*action)(struct segment_metadata *seg, ElfW(Addr) start_vaddr_in_file, void *segment_metadata_arg),
	void *arg)
{
	/* Scan the shdrs for any REL or RELA sections that
	 * apply to sections falling within this segment. We will use
	 * them to mark additional object starts in the bitmap.
	 * Note that it's the *target* section of the *reloc*
	 * that we care about, i.e. whatever section the symtab
	 * entry points to. The relocated section is not
	 * interesting to us. */
	for (unsigned i_sec = 0; i_sec < file->shnum; ++i_sec)
	{
		if ((file->shdrs[i_sec].sh_type == SHT_REL
				|| file->shdrs[i_sec].sh_type == SHT_RELA)
			&& file->shdrs[i_sec].sh_info != 0 /* ignores .rela.dyn */
			&& 0 != (file->shdrs[meta->shdrs[i_sec].sh_info].sh_flags & SHF_ALLOC)
				/* ignore relocs for non-allocated sections */
		   )
		{
			enumerate_reloc_starts_from_section(file, file_temp_mapping, i_sec,
				file->shdrs[i_sec].sh_type);
		}
	}
	for (unsigned i_statsym = 0; i_statdym < file->; ++i_statsym)
	{
	}
	for (unsigned i_dynsym = 0; i_dynsym < file->; ++i_dynsym)
	{
	}
	for (unsigned i_extrasym = 0; i_extrasym < file->; ++i_extrasym)
	{
	}
	// also enumerate statsym, dynsym and extrasym starts
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


/* We sort symbols based on address and size.
 * The idea is that if I search for the next lower symbol, given an address,
 * will get the symbol that overlaps that address.
 * So when we break ties, if we put the symbols in order of size,
 * with bigger sizes later, we get the property we want. */
static int sym_addr_size_compare(const void *arg1, const void *arg2)
{
	ElfW(Sym) *sym1 = ((ElfW(Sym) *)arg1;
	ElfW(Sym) *sym2 = ((ElfW(Sym) *)arg2;
	
	ElfW(Addr) addr1 = sym1->st_value;
	ElfW(Addr) addr2 = sym2->st_value;
	ElfW(Word) size1 = sym1->st_size;
	ElfW(Word) size2 = sym2->st_size;

	if (addr1 < addr2) return -1;
	if (addr2 > addr1) return 1;
	// else the addresses are equal; what about sizes? bigger sizes sort higher
	if (size1 < size2) return -1;
	if (size1 > size2) return 1;
	return 0;
}
static int sym_addr_size_search(const void *key, const void *arr_obj)
{
	ElfW(Addr) search_addr = *(ElfW(Addr)*) key;
	ElfW(Sym) *obj = (ElfW(Sym) *) arr_obj;
	/* We match a key, i.e. return 0,
	 * if the symbol (arr_obj) overlaps it. */
	if (obj->st_value <= search_addr
		&& obj->st_value + obj->st_size > search_addr) return 0;
	/* "Key is less" means the object falls on the *bigger* side of the key. */
	if (obj->st_value > search_addr) return -1;
	if (obj->st_value + obj->st_size <= search_addr) return 1;
	assert(0);
	abort();
}

/* Map the file's segments, but don't run any of its code (omit PF_X just in case).
 * This lets us run relf.h routines on an arbitrary file on disk, without the
 * risk that malicious objects will run nasty stuff in their constructors. */
int map_file_as_if_loaded(const char *filename, struct link_map *out_lm)
{
	return 0; // FIXME
}

void output_meta_vec(ElfW(Ehdr) *ehdr, ElfW(Shdr) *shdr, ElfW(Half) shnum, struct link_map *l)
{
	/* We have created the segments. But they do not have sections or symbols
	 * defined yet.
	 * We delay creating the symbols because they might be defined by extrasyms,
	 * and we want section structure to be down so that systrap.c can use it
	 * to trap our syscalls, *before* meta-objects are loaded.
	 * In total, symbols might be defined by
	 * 
	 * - dynsyms
	 * - staticsyms
	 * - extrasyms
	 * - reloc targets   (no metadata! just the existence of a reloc target address)
	 *
	 * Let's consider static-symbol.
	 * We have a bitmap, one bit per byte, with one set bit per start.
	 * Starts are symbols with length (spans).
	 * We discard symbols that are not spans.
	 * If we see multiple spans covering the same address, we discard one
	 * of them heuristically.
	 * This gives us a list of spans, in address order, with distinct starts.
	 * We allocator a vector with one pointer per span.
	 * For spans that are in dynsym, it points to their dynsym entry (16 bits probably enough? HMM).
	 * Three other cases: 
	 * (1) not-in-dynsym symbols that are in an available .symtab ("staticsyms")
	 * (2) not-in-dynsym symbols that are only as static alloc recs ("extrasyms")
	 * (3) rodata covers address ranges but is not marked by any symbol.
	 * For (1), we map .symtab if we can and use that.
	 * For (2), make static alloc recs look like symtabs, with types on the side
	 * For (3), we fall back to the section allocator.
		Rodata is probably best modelled as uninterpreted bytes, for now.
		-- Doing better: look for references to it from code, and correlate with code's DWARF.
	 *  HMM. If we really model all sections, then each section that contains
	 *  symbols will have to become a bigalloc. Too many?
		 NO, in a finally linked binary there are not that many sections.
		 And this structure is useful for tools, e.g. trap-syscalls. Do it!

	 * So we have a vector of symbol entries in address order.
	 * And we have a scaled index of the bitmap, one entry per
		 smallish interval, holding the index# at that interval start.
		 Aligned 64-byte intervals seem good. One two-byte index entry per such interval.
		 Maximum 64K symbols per segment -- is that okay? Could make it a 4-byte entry even.
	 * So we can count set bits in the word, back to the interval start, and add to the index#.

	 * To add type information to syms, we need a uniqtype pointer.
	 * We could use a parallel vector. Or save space by combining vectors somehow perhaps.
	 *   Probably we should borrow the low-order zero bits of the uniqtype pointer,
	 *   giving us three extra bits, i.e. 44 bits for the uniqtype, 20 for the rest.
	 * The static alloc table then becomes this vector + the bitmap.
	 * No more need for prev/next.
	 * (Also get rid of heap allocsite table's prev/next? MEASURE performance change.)

	 * To make the bitmap-based lookup fast, we keep a vector of the initial
	 * span index value for the Nth [B-byte-sized] chunk of the bitmap.
	 * Then we only have to scan back to a B-byte boundary, count the # of set bits,
	 * and add that to the vector's value.
	 * So if the bitmap is 1MB say (covering an 8MB segment),
	 * and our span index a 16-bit number
	 * and we have a max scan of 8 bitmap words (512 bits)
	 * then we need 2 bytes of index vector per 512 bytes of segment.
	 * Even a single-word scan would give us 2 per 64, which is fine
	 *.
	 * Since some symbols are not in any section, and some ELF files
	 * do not have any section headers at all, the bitmap lives with the
	 * file metadata, not the section metadata. */

	unsigned long n_dynsym = 0;
	unsigned long n_symtab = 0;
	unsigned long n_reloc = 0;
	ElfW(Shdr) *symtab_ent = NULL;
	for (unsigned i = 0; i < ehdr->e_shnum; ++i)
	{
		if (shdrs[i].sh_type == SHT_SYMTAB) // FIXME: is this sufficient?
		{
			symtab_ent = &shdrs[i];
			n_symtab = symtab_ent->sh_size / sizeof (ElfW(Sym));
			break;
		}
	}
	if (dynsym) n_dynsym = dynamic_symbol_count(/*dynamic*/ l->l_ld, l);

	// copy and sort the symtabs' content into the vector
	long sorted_meta_vec_mapped_len = ROUND_UP((n_dynsym + n_symtab) * sizeof (ElfW(Sym)), PAGE_SIZE);
	if (meta->all_syms_sorted_mapped_len > 0)
	{
		meta->all_syms_sorted = mmap(NULL, meta->all_syms_sorted_mapped_len,
			PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		if (meta->all_syms_sorted == MAP_FAILED)
		{
			meta->all_syms_sorted = NULL;
			meta->all_syms_sorted_mapped_len = 0;
		}
		else
		{
			/* FIXME: don't memcpy */
			if (n_dynsym > 0) memcpy(meta->all_syms_sorted, dynsym, n_dynsym * sizeof (ElfW(Sym)));
			if (n_symtab > 0) memcpy((ElfW(Sym) *) meta->all_syms_sorted + n_dynsym,
					symtab, n_symtab * sizeof (ElfW(Sym)));
			}
			// FIXME: extrasyms
			// FIXME: relocs
			/* PROBLEM: qsort wants to malloc, which we don't want it
			 * to do. We solve this by providing our own qsort() override. */
			qsort(meta->all_syms_sorted, n_dynsym + n_symtab, sizeof (ElfW(Sym)),
				sym_addr_size_compare);
		}
	}
}
