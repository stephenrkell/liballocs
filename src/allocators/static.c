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

int add_all_loaded_segments(struct dl_phdr_info *info, size_t size, void *data)
	__attribute__((visibility("hidden")));

void __static_allocator_init(void) __attribute__((constructor(102)));
void __static_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__mmap_allocator_init();
		dl_iterate_phdr(add_all_loaded_segments, /* any link map ent */ NULL);
		initialized = 1;
		trying_to_initialize = 0;
	}
}

void __static_allocator_notify_load(void *handle)
{
	if (initialized)
	{
		int dlpi_ret = dl_iterate_phdr(add_all_loaded_segments, 
			(struct link_map *) handle);
		assert(dlpi_ret != 0);
	}
}

struct segment_metadata
{
	const char *filename;
	const Elf64_Phdr *phdr;
};

static void free_segment_metadata(void *sm)
{
	struct segment_metadata *s = (struct segment_metadata *) sm;
	__wrap_dlfree((void*) s->filename);
	__wrap_dlfree(sm);
}

void __static_allocator_notify_unload(const char *copied_filename)
{
	if (initialized)
	{
		assert(copied_filename);
		/* For all big allocations, if we're the allocator and the filename matches, 
		 * delete them. */
		for (struct big_allocation *b = &big_allocations[0]; b != &big_allocations[NBIGALLOCS]; ++b)
		{
			if (BIGALLOC_IN_USE(b) && b->allocated_by == &__static_allocator)
			{
				if (0 == strcmp(copied_filename, 
					((struct segment_metadata *) b->meta.un.opaque_data.data_ptr)->filename))
				{
					/* It's a match, so delete. */
					__liballocs_delete_bigalloc_at(b->begin, &__static_allocator);
				}
			}
		}
	}
}

/* FIXME: invalidate cache entries on dlclose(). */
#ifndef DLADDR_CACHE_SIZE
#define DLADDR_CACHE_SIZE 16
#endif
struct dladdr_cache_rec { const void *addr; Dl_info info; };
static struct dladdr_cache_rec dladdr_cache[DLADDR_CACHE_SIZE];
static unsigned dladdr_cache_next_free;

Dl_info dladdr_with_cache(const void *addr); // __attribute__((visibility("protected")));
Dl_info dladdr_with_cache(const void *addr)
{
	
	for (unsigned i = 0; i < DLADDR_CACHE_SIZE; ++i)
	{
		if (dladdr_cache[i].addr)
		{
			if (dladdr_cache[i].addr == addr)
			{
				/* This entry is useful, so maximise #misses before we recycle it. */
				dladdr_cache_next_free = (i + 1) % DLADDR_CACHE_SIZE;
				return dladdr_cache[i].info;
			}
		}
	}
	
	Dl_info info;
	int ret = dladdr(addr, &info);
	assert(ret != 0);

	/* always cache the dladdr result */
	dladdr_cache[dladdr_cache_next_free++] = (struct dladdr_cache_rec) { addr, info };
	if (dladdr_cache_next_free == DLADDR_CACHE_SIZE)
	{
		debug_printf(5, "dladdr cache wrapped around\n");
		dladdr_cache_next_free = 0;
	}
	
	return info;
}

struct symbols_bitmap
{
	unsigned long *bits;
	unsigned long *bits_limit;
	ElfW(Sym) *dynsym;
};

/* We sort symbols based on address and size.
 * The idea is that if I search for the next lower symbol, given an address,
 * will get the symbol that overlaps that address.
 * So when we break ties, if we put the symbols in order of size,
 * with bigger sizes later, we get the property we want. */
static int sym_addr_size_compare(const void *arg1, const void *arg2)
{
	if (((ElfW(Sym) *)arg1)->st_value < ((ElfW(Sym) *) arg2)->st_value) return -1;
	if (((ElfW(Sym) *)arg1)->st_value > ((ElfW(Sym) *) arg2)->st_value) return 1;
	// else the addresses are equal; what about sizes? bigger sizes sort higher
	if (((ElfW(Sym) *)arg1)->st_size < ((ElfW(Sym) *) arg2)->st_size) return -1;
	if (((ElfW(Sym) *)arg1)->st_size > ((ElfW(Sym) *) arg2)->st_size) return 1;
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
}

int add_all_loaded_segments(struct dl_phdr_info *info, size_t size, void *maybe_lment)
{
	static _Bool running;
	/* HACK: if we have an instance already running, quit early. */
	if (running) /* return 1; */ abort(); // i.e. debug this
	running = 1;
	if (!info) abort();
	// write_string("Blah9000\n");
	struct link_map *found_l = maybe_lment;
	if (!maybe_lment)
	{
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			if (l->l_addr == info->dlpi_addr) { found_l = l; break; }
		}
	}
	struct link_map *l = found_l;
	assert(l);
	const char *filename = l->l_name;
	if (!maybe_lment || l->l_addr == info->dlpi_addr)
	{
		// write_string("Blah9001\n");
		assert(!filename || 0 == strcmp(filename, info->dlpi_name));
		const char *dynobj_name = dynobj_name_from_dlpi_name(info->dlpi_name, 
			(void*) info->dlpi_addr);
		if (!dynobj_name) dynobj_name = "(unknown)";
		// write_string("Blah9002\n");

		// this is the file we care about, so iterate over its phdrs
		ElfW(Sym) *dynsym = NULL;
		ElfW(Sym) *all_syms_sorted = NULL;
		size_t all_syms_sorted_mapping_size = 0;
		unsigned n_dynsym = 0;
		unsigned n_symtab = 0;
		/* Iterate looking for its dynsym. */
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD
			if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
			{
				dynsym = get_dynsym(l);
				//ElfW(Dyn) *dynamic = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
				//ElfW(Sym) *tmp_symtab = (ElfW(Sym) *) dynamic_xlookup(dynamic DT_SYMTAB)->d_un.d_ptr;
				//if ((intptr_t) tmp_symtab < 0) break; // HACK: x86-64 vdso workaround
				//if (tmp_symtab && (uintptr_t) tmp_symtab < info->dlpi_addr) break; // HACK: x86-64 vdso workaround
				//symtab = tmp_symtab;
				break;
			}
		}
		/* Try to map the file's sht, so we can pilfer its relocs. */
		void *file_mapping = MAP_FAILED;
		ElfW(Shdr) *shdr = NULL;
		ElfW(Ehdr) *ehdr = NULL;
		size_t file_mapping_sz;
		int raw_fd = -1;
		if (filename)
		{
			raw_fd = raw_open(dynobj_name, O_RDONLY);
			struct stat s;
			int ret = (raw_fd == -1) ? -1 : raw_fstat(raw_fd, &s);
			if (raw_fd >= 0 && ret == 0)
			{
				file_mapping_sz = ROUND_UP(s.st_size, PAGE_SIZE);
				file_mapping = raw_mmap(NULL, file_mapping_sz, PROT_READ, MAP_PRIVATE, raw_fd, 0);
				if (file_mapping != MAP_FAILED)
				{
					ehdr = file_mapping;
					shdr = (ElfW(Shdr) *)(((unsigned char *) file_mapping) + ehdr->e_shoff);
				}
			}
			if (raw_fd != -1) close(raw_fd);
		}
		if (dynsym)
		{
			/* Copy the contents of dynsym and sort them. */
			n_dynsym = dynamic_symbol_count(/*dynamic*/ l->l_ld, l);
			/* Also copy in symtab if we can find it. FIXME: do this even if !dynsym */
			ElfW(Shdr) *symtab_ent = NULL;
			for (unsigned i = 0; i < ehdr->e_shnum; ++i)
			{
				if (shdr[i].sh_type == SHT_SYMTAB)
				{
					symtab_ent = &shdr[i];
					break;
				}
			}
			if (symtab_ent)
			{
				n_symtab = symtab_ent->sh_size / sizeof (ElfW(Sym));
			}
			
			all_syms_sorted_mapping_size = ROUND_UP((n_dynsym + n_symtab) * sizeof (ElfW(Sym)), PAGE_SIZE);
			all_syms_sorted = raw_mmap(NULL, all_syms_sorted_mapping_size,
					PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
			if (all_syms_sorted == MAP_FAILED)
			{
				all_syms_sorted = NULL;
				all_syms_sorted_mapping_size = 0;
			}
			else
			{
				memcpy(all_syms_sorted, dynsym, n_dynsym * sizeof (ElfW(Sym)));
				if (symtab_ent)
				{
					ElfW(Sym) *symtab = (ElfW(Sym) *)((unsigned char *) file_mapping
						+ symtab_ent->sh_offset);
					memcpy((unsigned char *) all_syms_sorted  + n_dynsym * sizeof (ElfW(Sym)),
						symtab,
						n_symtab * sizeof (ElfW(Sym)));
				}
				/* PROBLEM: qsort wants to malloc, which we don't want it
				 * to do. */
				qsort(all_syms_sorted, n_dynsym + n_symtab, sizeof (ElfW(Sym)),
					sym_addr_size_compare);
			}
		}
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				const void *segment_start_addr = (char*) info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
				size_t segment_size = info->dlpi_phdr[i].p_memsz;
				struct big_allocation *containing_mapping = __lookup_bigalloc(
					segment_start_addr, &__mmap_allocator, NULL);
				if (!containing_mapping) abort();
				// write_string("Blah9003\n");
				/* FIXME: get rid of this dlmalloc to avoid reentrancy issues. */
				struct segment_metadata *m = __wrap_dlmalloc(sizeof (struct segment_metadata));
				// write_string("Blah9004\n");
				*m = (struct segment_metadata) {
					/* We strdup once per segment, even though the filename could be 
					 * shared, in order to simplify the cleanup logic. */
					.filename = __liballocs_private_strdup(dynobj_name),
					.phdr = &info->dlpi_phdr[i]
				};
				// write_string("Blah9005\n");
				
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
					containing_mapping,
					&__static_allocator
				);
				/* FIXME: free this somewhere */
				size_t bitmap_size_bytes = (7 + info->dlpi_phdr[i].p_memsz) / 8;
				size_t prefix_size = ROUND_UP(sizeof (struct symbols_bitmap), sizeof (unsigned long));
				size_t alloc_size = prefix_size + bitmap_size_bytes;
				unsigned char *mapping = raw_mmap(NULL, alloc_size,
					PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
				if (mapping == MAP_FAILED) abort();
				b->suballocator_meta = (struct symbols_bitmap *) mapping;
				struct symbols_bitmap *bm = b->suballocator_meta;
				bm->bits = (unsigned long *) (mapping + prefix_size);
				bm->bits_limit = bm->bits + (bitmap_size_bytes / sizeof (unsigned long));
				// write_string("Blah9006\n");
				/* Look for dynsyms in this address range. */
				unsigned long segment_base_vaddr = info->dlpi_phdr[i].p_vaddr;
				unsigned long segment_limit_vaddr = info->dlpi_phdr[i].p_vaddr
						+ info->dlpi_phdr[i].p_memsz;
				// linear scan of dynsym
				// do we really only want to add dynsyms? NO! add any syms?
				if (dynsym)
				{
					bm->dynsym = dynsym;
					// scan *all* symbols, using the sorted array
					for (unsigned i = 0; i < n_dynsym + n_symtab; ++i) // FIXME: do even if !dynsym
					{
						if (all_syms_sorted[i].st_size > 0) // only add range symbols
						{
							unsigned long sym_vaddr = all_syms_sorted[i].st_value;
							if (sym_vaddr >= segment_base_vaddr
									&& sym_vaddr < segment_limit_vaddr)
							{
								off_t offset_from_segment_base = sym_vaddr - segment_base_vaddr;
								bitmap_set((unsigned long *) bm->bits,
									offset_from_segment_base);
							}
						}
					}
				} // end if dynsym
				if (shdr)
				{
					/* Scan the shdrs for any REL or RELA sections that
					 * apply to sections within this segment. We will use
					 * them to mark additional object starts in the bitmap.
					 * Note that it's the *target* section of the reloc
					 * that we care about, i.e. whatever section the symtab
					 * entry points to. The relocated section is not
					 * interesting to us. */
					for (unsigned i_sec = 0; i_sec < ehdr->e_shnum; ++i_sec)
					{
						if ((shdr[i_sec].sh_type == SHT_REL
								|| shdr[i_sec].sh_type == SHT_RELA)
							&& shdr[i_sec].sh_info != 0 /* ignores .rela.dyn */
							&& 0 != (shdr[shdr[i_sec].sh_info].sh_flags & SHF_ALLOC)
								/* ignore relocs for non-allocated sections */
						   )
						{
							_Bool is_rela = (shdr[i_sec].sh_type == SHT_RELA);
							/* Scan the relocs and find whether their target section
							 * is within this segment. */
							unsigned symtab_scn = shdr[i_sec].sh_link;
							ElfW(Sym) *symtab = (ElfW(Sym) *)(
								(char*) file_mapping + shdr[symtab_scn].sh_offset);
							unsigned nrel = shdr[i_sec].sh_size / 
								(is_rela ? sizeof (ElfW(Rela)) : sizeof (ElfW(Rel)));
							void *tbl_base = (char*) file_mapping + shdr[i_sec].sh_offset;
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
										= shdr[shndx].sh_addr + 
											(is_rela ? rela_base[i].r_addend : 0);
									if (referenced_vaddr >= segment_base_vaddr
										&& referenced_vaddr < segment_limit_vaddr)
									{
										/* The referenced in-section location 
										 * is contained in this segment. Consider it
										 * an object start IFF no symbol overlaps it. */
										
										Elf64_Addr addr = referenced_vaddr;
										void *found = bsearch(&addr,
											all_syms_sorted, n_dynsym + n_symtab, sizeof (ElfW(Sym)),
											sym_addr_size_search);
										if (!found
											|| ((ElfW(Sym) *)found)->st_value > addr
											|| ((ElfW(Sym) *)found)->st_value
												+ ((ElfW(Sym) *)found)->st_size <= addr)
										{
											off_t offset_from_segment_base = referenced_vaddr
												- segment_base_vaddr;
											bitmap_set((unsigned long *) bm->bits,
												offset_from_segment_base);
										}
									}
								}
							}
						}
					}
				}
				
				
			} // end if it's a load
		} // end for each phdr
		
		if (all_syms_sorted) raw_munmap(all_syms_sorted, all_syms_sorted_mapping_size);
		if (file_mapping != MAP_FAILED)
		{
			raw_munmap(file_mapping, file_mapping_sz);
		}
		// if we were looking for a single file, and got here, then we found it; can stop now
		if (maybe_lment != NULL) { running = 0; return 1; }
	}
	// write_string("Blah9050\n");

	running = 0;
	
	// keep going
	return 0;
}

/* Doing better: what we want.
   Split static into static-segment, static-section, static-symbol.
   Let's consider static-symbol.
   We have a bitmap, one bit per byte, with one set bit per start.
   Starts are symbols with length (spans).
   We discard symbols that are not spans.
   If we see multiple spans covering the same address, we discard one
   of them heuristically.
   This gives us a list of spans, in address order, with distinct starts.
   We allocator a vector with one pointer per span.
   For spans that are in dynsym, it points to their dynsym entry (16 bits probably enough? HMM).
   Three other cases: 
   (1) not-in-dynsym symbols that are in an available .symtab ("statsyms")
   (2) not-in-dynsym symbols that are only as static alloc recs ("extrasyms")
   (3) rodata covers address ranges but is not marked by any symbol.
   For (1), we map .symtab if we can and use that.
   For (2), make static alloc recs look like symtabs, with types on the side
   For (3), we fall back to the section allocator.
        Rodata is probably best modelled as uninterpreted bytes, for now.
        -- Doing better: look for references to it from code, and correlate with code's DWARF.
     HMM. If we really model all sections, then each section that contains
     symbols will have to become a bigalloc. Too many?
         NO, in a finally linked binary there are not that many sections.
         And this structure is useful for tools, e.g. trap-syscalls. Do it!

   So we have a vector of symbol entries in address order.
   And we have a scaled index of the bitmap, one entry per
         smallish interval, holding the index# at that interval start.
         Aligned 64-byte intervals seem good. One two-byte index entry per such interval.
         Maximum 64K symbols per segment -- is that okay? Could make it a 4-byte entry even.
   So we can count set bits in the word, back to the interval start, and add to the index#.

   To add type information to syms, we need a uniqtype pointer.
   We could use a parallel vector. Or save space by combining vectors somehow perhaps.
      Probably we should borrow the low-order zero bits of the uniqtype pointer,
      giving us three extra bits, i.e. 44 bits for the uniqtype, 20 for the rest.
   The static alloc table then becomes this vector + the bitmap.
   No more need for prev/next.
   (Also get rid of heap allocsite table's prev/next? MEASURE performance change.)
   
   To make the bitmap-based lookup fast, we keep a vector of the initial
   span index value for the Nth [B-byte-sized] chunk of the bitmap.
   Then we only have to scan back to a B-byte boundary, count the # of set bits,
   and add that to the vector's value.
   So if the bitmap is 1MB say (covering an 8MB segment),
   and our span index a 16-bit number
   and we have a max scan of 8 bitmap words (512 bits)
   then we need 2 bytes of index vector per 512 bytes of segment.
   Even a single-word scan would give us 2 per 64, which is fine.

 */

#define maximum_static_obj_size (256*1024) // HACK
struct uniqtype *
static_addr_to_uniqtype(const void *static_addr, void **out_object_start)
{
	assert(__liballocs_allocsmt != NULL);
	if (!static_addr) return NULL;
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)static_addr | (0x800000000000ul<<1)));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= static_addr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > static_addr)) 
			{
				/* This is the next-lower record, but does it span the address?
				 * Note that subprograms have length 0, i.e. known length. */
				if (p->uniqtype && UNIQTYPE_HAS_KNOWN_LENGTH(p->uniqtype) &&
						p->uniqtype->pos_maxoff >= ((char*) static_addr - (char*) p->allocsite))
				{
					if (out_object_start) *out_object_start = p->allocsite;
					return p->uniqtype;
				} else return NULL;
			}
			might_start_in_lower_bucket &= (p->allocsite > static_addr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_static_obj_size);
	return NULL;
}
#undef maximum_vaddr_range_size




static liballocs_err_t get_info(void * obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_static_case;
//			/* We use a blacklist to rule out static addrs that map to things like 
//			 * mmap()'d regions (which we never have typeinfo for)
//			 * or uninstrumented libraries (which we happen not to have typeinfo for). */
//			_Bool blacklisted = check_blacklist(obj);
//			if (blacklisted)
//			{
//				// FIXME: record blacklist hits separately
//				err = &__liballocs_err_unrecognised_static_object;
//				++__liballocs_aborted_static;
//				goto abort;
//			}
	void *object_start;
	struct uniqtype *alloc_uniqtype = static_addr_to_uniqtype(obj, &object_start);
	if (out_type) *out_type = alloc_uniqtype;
	if (!alloc_uniqtype)
	{
		++__liballocs_aborted_static;
		void *segment_base;
		struct big_allocation *segment_bigalloc = __lookup_bigalloc(obj,
			&__static_allocator, &segment_base);
		assert(segment_bigalloc);
		size_t segment_size_bytes = (char*) segment_bigalloc->end - (char*) segment_bigalloc->begin;
		struct symbols_bitmap *bm = segment_bigalloc->suballocator_meta;
		unsigned long found = bitmap_rfind_first_set(
			bm->bits,
			bm->bits_limit,
			(char*) obj - (char*) segment_bigalloc->begin,
			NULL);
		if (found != (unsigned long) -1)
		{
			/* To know the limit, we need the ELF symbol.
			 * To know the ELF symbol, we have to find it.
			 * PROBLEM: ELF dynsyms are not necessarily sorted!
			 * HACK: for now, scan forward to the next set bit
			 * and imagine that the object goes up to there.
			 * BE CAREFUL of the end case. */
			unsigned long found_end_idx = bitmap_find_first_set1(
				bm->bits,
				bm->bits_limit,
				1 + ((char*) obj - (char*) segment_bigalloc->begin),
				NULL);
			if (found_end_idx == (unsigned long) -1)
			{
				found_end_idx = segment_size_bytes;
			}
			object_start = (char*) segment_bigalloc->begin + found;
			void *object_end_upper_bound = (char*) segment_bigalloc->begin + found_end_idx;
			if (out_base) *out_base = object_start;
			if (out_site) *out_site = object_start;
			if (out_size) *out_size = (char*) object_end_upper_bound - (char*) object_start;
			return NULL;
		}
//				consider_blacklisting(obj);
		/* Look for a dynsym spanning this symbol. */
		//unsigned long idx = bitmap_find_first_set(
		//	unsigned long *p_bitmap, unsigned long *p_limit, unsigned long *out_test_bit);
		
		
		
		return &__liballocs_err_unrecognised_static_object;
	}

	// else we can go ahead
	if (out_base) *out_base = object_start;
	if (out_site) *out_site = object_start;
	if (out_size) *out_size = alloc_uniqtype->pos_maxoff;
	return NULL;
}

// nasty hack
_Bool __lookup_static_allocation_by_name(struct link_map *l, const char *name,
	void **out_addr, size_t *out_len)
{
	for (struct link_map *inner_l = _r_debug.r_map; inner_l; inner_l = inner_l->l_next)
	{
		if (is_meta_object_for_lib(inner_l, l)) /* HACK: we shouldn't need this... or should we? */
		{
			ElfW(Sym) *statics_sym = symbol_lookup_in_object(inner_l, "statics");
			if (!statics_sym) abort();
			struct static_allocsite_entry *statics = sym_to_addr(statics_sym);
			for (struct static_allocsite_entry *cur_ent = statics;
					!STATIC_ALLOCSITE_IS_NULL(cur_ent);
					cur_ent++)
			{
				if (cur_ent->name && 0 == strcmp(cur_ent->name, name))
				{
					// found it! it'd better not be the last in the table...
					if (!(cur_ent + 1)->entry.allocsite) abort();
					void *this_static = cur_ent->entry.allocsite;
					void *next_static = (char*) (cur_ent + 1)->entry.allocsite;
					*out_addr = this_static;
					*out_len = (char*) next_static - (char*) this_static;
					return 1;
				}
			}

			// didn't find the symbol we were looking for -- oh well
			return 0;
		}
	}
	
	return 0;
}

DEFAULT_GET_TYPE

struct allocator __static_allocator = {
	.name = "static",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
