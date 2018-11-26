#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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
int fstat(int fd, struct stat *buf);

/* This file's logic really belongs in the dynamic linker.
 * It is responding to load and unload events.
 * Also, it'd be great if we could keep a file descriptor on
 * all the files we loaded -- rather than having to look them up again
 * by name.
 * We also want phdr, ehdr and shdr access. */

/* Since November 2018 we have split static metadata
   into static-file, static-segment, static-section, static-symbol.
   This file implements only static-file, but here is an overview of how
   the whole thing works.

   It is segments' being pre-packed that allows us to precompute their
   allocated object metadata and represent it as packed arrays.
   If we ever get around to supporting dynamic re-layouting of segments,
   the flip side will be expensive recomputation of all this precomputed stuff.

   The basic idea is to use vectors, bitmaps and cumulative offset counts
   to provide fast, dense lookups into all this statically packed metadata.
   This can be precomputed and stored in a -cached-meta-obj,
   or computed on demand. HMM. This -cached-meta seems ugly.
   Do we want to get into on-demand generation of these ELF files?
   Maybe this should all be in an ahead-of-time tool? But it is easier
   to do it right here in execution. (Same reason that ldd works by actually
   doing the load, despite security problems with that.)
 */

static _Bool trying_to_initialize;
static _Bool initialized;

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info, size_t size, void *file_metadata);

void __static_file_allocator_notify_load(void *handle, const void *load_site);

void __static_file_allocator_init(void) __attribute__((constructor(102)));
void __static_file_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__mmap_allocator_init();
		__auxv_allocator_init();
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			__static_file_allocator_notify_load(l, __auxv_get_program_entry_point());
		}
		initialized = 1;
		trying_to_initialize = 0;
	}
}

static void free_file_metadata(void *fm)
{
	struct file_metadata *f = (struct file_metadata *) fm;
	__wrap_dlfree((void*) f->filename);
	if (f->shdrs_mapped_len > 0) munmap(ROUND_DOWN_PTR(f->shdrs, PAGE_SIZE), f->shdrs_mapped_len);
	if (f->symtab_mapped_len > 0) munmap(ROUND_DOWN_PTR(f->symtab, PAGE_SIZE), f->symtab_mapped_len);
	if (f->strtab_mapped_len > 0) munmap(ROUND_DOWN_PTR(f->strtab, PAGE_SIZE), f->strtab_mapped_len);
	if (f->sorted_meta_vec_mapped_len > 0) munmap(ROUND_DOWN_PTR(f->sorted_meta_vec, PAGE_SIZE), f->sorted_meta_vec_mapped_len);
	__wrap_dlfree(fm);
}

static void *map_file_range(void *addr, size_t length, int prot, int flags, int fd,
			off_t offset)
{
	off_t rounded_offset = ROUND_DOWN(offset, PAGE_SIZE);
	length += offset - rounded_offset;
	length = ROUND_UP(length, PAGE_SIZE);
	void *ret = mmap(addr, length, prot, flags, fd, offset);
	if (ret != MAP_FAILED) return (char*) ret + (offset - rounded_offset);
	return MAP_FAILED;
}

// GAH: with the move to entries, we need a side table to get
// the address represented by any given entry.
// PERHAPS the right thing is to sort in groups,
// then do a merge?
// PERHAPS the right thing is to avoid extrasyms?
// ALSO the uniqtype pointers won't be statically representable.
// REMEMBER that we want to statically generate 
// - extrasyms
// - types for included-in-{dynsym,symtab} syms
// - i.e. most/all this processing should be done statically
// - what should our output look like?
/*
	Statically, we should compute the sorted vector.
	And the types vector.
	And the extrasyms vector.
	At run time, we can point to these directly.
	Ideal feature: for extrasyms, the user can ask to generate extrasyms
	   for symtab, if they know that is going to be stripped. This
	   affects the contents of the sorted vector.
	We implement this by sorting each kind separately,
	   then doing a 4-way merge which we hand-code.
	BUT perhaps don't bother storing the sorted vector in the meta obj?
	We can reconstruct it at run time.
	But why should we?
	It is just a bunch of discriminants and offsets.
	At run time, we simply build the bitmap.
	Actually, why do that at runtime? We can also build that statically. We output
	- extrasyms
	- extrarelocs (for syscall trap site caching... HMM)
	- sorted_vec (16-bit entries: 14 bits for idx in symtab/dynsym/extrasym)
	- types_vec
	- starts_bitmap
	- cumulative_vec_offsets
	Do syscalls really belong in extrarelocs?
	If we have an mmap'ing binary with no metadata attached,
	   we still want to be able to trap its syscalls.
	   But that is still supported via the libsystrap API; it's just our use of that API
	      that we're varying.
	Each word is commented in the .c output with the (up to 64) entities whose starts it records.
	Is 16K entries enough? Can use 16-bit vec entries if so (2 bits reserved)
	I think this should be enough because
	(1) only defined symbols are of interest,
	(2) only relocs pointing to addresses not spanned by symbols are of interest, and
	(3) elements should not be counted twice,
	(i.e. elements in dynsym should be skipped when processing symtab).
 */
// PERHAPS we should have a parallel vector for the uniqtypes

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

void __static_file_allocator_notify_load(void *handle, const void *load_site)
{
   struct link_map *l = (struct link_map *) handle;

	/* Load the separate meta-object for this object. */
	void *meta_handle = NULL;
	int ret_meta = dl_for_one_object_phdrs(handle,
		load_and_init_all_metadata_for_one_object, &meta_handle);
	if (ret_meta == 0) assert(meta_handle);

	void *file_start_addr = (void*) l->l_addr;
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) file_start_addr;
	const char (__attribute__((unused)) magic)[] = { '\177', 'E', 'L', 'F' };
	assert(0 == memcmp(ehdr, magic, sizeof magic));
	struct big_allocation *containing_mapping_bigalloc = __lookup_bigalloc(
		file_start_addr,
		&__mmap_allocator, NULL);
	if (!containing_mapping_bigalloc) abort();
	size_t file_size = (char*) containing_mapping_bigalloc->end
		- (char*) containing_mapping_bigalloc->begin;
	const char *dynobj_name = dynobj_name_from_dlpi_name(l->l_name,
		(void*) l->l_addr);
	struct file_metadata *meta = __wrap_dlmalloc(sizeof (struct file_metadata));

	{ // to avoid letting these locals stay in scope
		ElfW(Shdr) *shdrs = NULL;
		size_t shdrs_mapped_len = 0;
		ElfW(Sym) *symtab = NULL;
		size_t symtab_mapped_len = 0;
		unsigned char *strtab = NULL;
		size_t strtab_mapped_len = 0;
		/* FIXME: we'd much rather not use l->l_name (race condition) --
		 * if we had the original fd, that would be great. */
		int fd = raw_open(l->l_name, O_RDONLY);
		if (fd != -1)
		{
			size_t shdrs_sz = ehdr->e_shnum * ehdr->e_shentsize;
			shdrs = map_file_range(NULL, shdrs_sz, PROT_READ, MAP_PRIVATE,
					fd, ROUND_DOWN(ehdr->e_shoff, PAGE_SIZE));
			shdrs_mapped_len = ROUND_UP(shdrs_sz + (((unsigned long) shdrs) & (PAGE_SIZE - 1)), PAGE_SIZE);

			for (unsigned i = 0; i < ehdr->e_shnum; ++i)
			{
				if (shdrs[i].sh_type == SHT_SYMTAB)
				{
					symtab = map_file_range(NULL, shdrs[i].sh_size, PROT_READ, MAP_PRIVATE,
							fd, shdrs[i].sh_offset);
					if (symtab != MAP_FAILED) symtab_mapped_len = ROUND_UP(shdrs[i].sh_size + (((unsigned long) symtab) & (PAGE_SIZE - 1)),
						PAGE_SIZE);
					strtab = map_file_range(NULL, shdrs[shdrs[i].sh_link].sh_size, PROT_READ, MAP_PRIVATE,
							fd, shdrs[shdrs[i].sh_link].sh_offset);
					if (strtab != MAP_FAILED) strtab_mapped_len = ROUND_UP(shdrs[shdrs[i].sh_link].sh_size
								+ (((unsigned long) strtab) & (PAGE_SIZE - 1)), PAGE_SIZE);
					break;
				}
			}
			close(fd);
		}

		*meta = (struct file_metadata) {
			.load_site = load_site,
			.filename = __liballocs_private_strdup(dynobj_name),
			.l = l,
			.shdrs = shdrs,
			.shdrs_mapped_len = shdrs_mapped_len, /* FIXME: re-use if within a segment */
			.symtab = symtab,
			.symtab_mapped_len = symtab_mapped_len,
			.strtab = strtab,
			.strtab_mapped_len = strtab_mapped_len, /* 0 if within a segment; >0 if mapped by us */
			.dynsym = get_dynsym(l), /* always mapped by ld.so */
			.dynstr = get_dynstr(l), /* always mapped by ld.so */
			.phdrs = NULL, /* for now... filled in by add_all_loaded_segments_for_one_file_only_cb */
			.phnum = -1, /* ditto */
			.meta_obj_handle = meta_handle,
			.extrasym = NULL,
			.sorted_meta_vec = NULL,
			.sorted_meta_vec_mapped_len = 0
		};
	} // use only meta-> from now on
	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) file_start_addr,
		file_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = (void*) m,
					.free_func = &free_file_metadata
				}
			}
		},
		containing_mapping_bigalloc,
		&__static_file_allocator
	);
	b->suballocator = &__static_segment_allocator;

	/* The only semi-portable way to get phdrs is to iterate over
	 * *all* the phdrs. But we only want to process a single file's
	 * phdrs now. Our callback must do the test. */
	int dlpi_ret = dl_iterate_phdr(add_all_loaded_segments_for_one_file_only_cb,
		(void*) l->l_addr);
	assert(dlpi_ret != 0);
	/* Now we have complete file metadata. */
	assert(meta->phdrs);

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

	meta->sorted_meta_vec_mapped_len = ROUND_UP((n_dynsym + n_symtab) * sizeof (ElfW(Sym)), PAGE_SIZE);
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

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info, size_t size, void *file_metadata)
{
	static _Bool running;
	/* HACK: if we have an activation already running, quit early. */
	int retval = 0;
	if (running) /* return 1; */ abort(); // i.e. debug this
	running = 1;
	
	/* Produce the sorted symbols vector for this file. 
	 * We do this here because dynsym is shared across the whole file. */

	struct file_metadata *meta = (struct file_metadata *) file_metadata;
	/* Is this the file we're doing right now? */
	if (l->l_addr == info->dlpi_addr)
	{
		// this is the file we care about, so iterate over its phdrs
		// -- but first, copy its phdr pointer and phnum value
		if (!meta->phdrs)
		{
			meta->phdrs = info->dlpi_phdr;
			meta->phnum = info->dlpi_phnum;
		}
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				__static_segment_allocator_notify_define_segment(
						meta,
						&info->dlpi_phdr[i]
					);
			}
		}
		retval = 1;
		goto out;
	}
out:
	running = 0;
	return retval;
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
			if (BIGALLOC_IN_USE(b) && b->allocated_by == &__static_file_allocator)
			{
				struct file_metadata *meta = (struct file_metadata *) b->meta.un.opaque_data.data_ptr;
				if (0 == strcmp(copied_filename, meta->filename))
				{
					/* unload meta-object */
					dlclose(meta->meta_obj_handle);
					/* It's a match, so delete. FIXME: don't match by name (fragile);
					 * load addr is better */
					__liballocs_delete_bigalloc_at(b->begin, &__static_file_allocator);
				}
			}
		}
	}
}


static liballocs_err_t get_info(void * obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_static_case;
	/* Until we've revamped the symbol metadata... */
	return __static_symbol_allocator_get_info(obj, NULL, out_type, out_base, out_size, out_site);
	// FIXME: re-eanble the below
	/* The only allocation we have is the bigalloc, so it's easy. */
	assert(maybe_bigalloc);
	if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;
	if (out_base) *out_base = maybe_bigalloc->begin;
	if (out_site) *out_site =
		((struct file_metadata *) (maybe_bigalloc->parent->meta.un.opaque_data.data_ptr))
			->load_site;
	if (out_size) *out_size = (char*) maybe_bigalloc->end - (char*) maybe_bigalloc->begin;
}

DEFAULT_GET_TYPE

struct allocator __static_file_allocator = {
	.name = "static-file",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
