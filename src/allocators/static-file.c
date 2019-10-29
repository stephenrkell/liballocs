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
int raw_open(const char *pathname, int flags); // avoid raw-syscalls.h

/* This file's logic really belongs in the dynamic linker.
 * It is responding to load and unload events.
 * Also, it'd be great if we could keep a file descriptor on
 * all the files we loaded -- rather than having to look them up again
 * by name.
 * We also want phdr, ehdr and shdr access. */

/* We now split static metadata into static-file, static-segment,
   static-section and static-symbol. This file implements only static-file,
   but here is an overview of how the whole thing works.

   The basic idea is to use vectors, bitmaps and cumulative offset counts
   to provide fast, dense lookups into all this statically packed metadata.
   The vector (metavector) is address-sorted, and has one entry per leaf-level
   static alloc (symbol, DWARF-defined object or reloc target). For compactness,
   this does not actually store the address; it simply stores an index into 
   whatever table (symtab, dynsym, extrasym, .rela?.*) already describes it.
   
   All this is precomputed and stored in the meta-DSO. It could be computed
   on demand, but that is slow.

   It is segments' being pre-packed that allows us to precompute their
   allocated object metadata and represent it as packed arrays.
   If we ever get around to supporting dynamic re-layouting of segments,
   the flip side will be expensive recomputation of all this precomputed stuff.
 */

static _Bool trying_to_initialize;
static _Bool initialized;

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info, size_t size, void *file_metadata);
struct segments
{
	const ElfW(Phdr) *phdrs;
	ElfW(Half) phnum;
	unsigned nload;
};
static int discover_segments_cb(struct dl_phdr_info *info, size_t size, void *segments_as_void);

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
		/* FIXME: arguably, for dynamically linked programs, the allocation
		 * site of these is somewhere inside the dynamic linker. E.g.
		 * if the linker was run by the kernel's loader (and not by directly
		 * running the linker on the command line, e.g.
		 * /path/to/ld.so /path/to/executable) it should be _dl_start, else
		 * it should be wherever in the dynamic linker did the load. We can
		 * distinguish all these cases, and should do.... */
		const void *program_entry_point = __auxv_get_program_entry_point();
		/* We probably don't need to iterate over all DSOs -- those that have been
		 * dlopened by us since execution started (e.g. the dlbind lib)
		 * were already notified/added earlier. So we only iterate
		 * over those we snapshotted. But if we *haven't* run dlopen
		 * at all yet, just iterate over everything. */
		if (early_lib_handles[0])
		{
			for (unsigned i = 0; i < MAX_EARLY_LIBS; ++i)
			{
				if (!early_lib_handles[i]) break;
				__static_file_allocator_notify_load(early_lib_handles[i],
					program_entry_point);
			}
		}
		else
		{
			for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
			{
				__static_file_allocator_notify_load(l, program_entry_point);
			}
		}
		initialized = 1;
		trying_to_initialize = 0;
	}
}

// we define this a bit closer to the allocating code, but declare it now
static void free_file_metadata(void *fm);

static void *get_or_map_file_range(struct file_metadata *file,
	size_t length, int fd, off_t offset)
{
	/* Check whether we already have this range, either in a LOAD phdr or
	 * in an extra mapping we made earlier. */
	for (unsigned i = 0; i < file->phnum; ++i)
	{
		ElfW(Phdr) *phdr = &file->phdrs[i];
		if (phdr->p_type == PT_LOAD)
		{
			if (phdr->p_offset <= offset &&
					phdr->p_offset + phdr->p_filesz >= offset + length)
			{
				// we can just return the address within that phdr
				return (char*) file->l->l_addr + phdr->p_vaddr +
					(offset - phdr->p_offset);
			}
		}
	}
	unsigned midx = 0;
	for (; midx < MAPPING_MAX; ++midx)
	{
		struct extra_mapping *m = &file->extra_mappings[midx];
		if (!m->mapping_pagealigned)
		{
			// this is a free slot. we fill from index 0 upwards, so no more
			break;
		}
		if (m->mapping_pagealigned
			&& m->fileoff_pagealigned <= offset
			&& m->fileoff_pagealigned + m->size >= offset + length)
		{
			return m->mapping_pagealigned + (offset - m->fileoff_pagealigned);
		}
	}
	/* OK. We need to create a new extra mapping, unless there's no room... */
	if (midx == MAPPING_MAX) return NULL;
	// tweak our offset/length
	off_t rounded_offset = ROUND_DOWN(offset, PAGE_SIZE);
	length += offset - rounded_offset;
	length = ROUND_UP(length, PAGE_SIZE);
	// FIXME: racy
	void *ret = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, rounded_offset);
	if (!MMAP_RETURN_IS_ERROR(ret))
	{
		file->extra_mappings[midx] = (struct extra_mapping) {
			.mapping_pagealigned = ret,
			.fileoff_pagealigned = rounded_offset,
			.size = length
		};
		return (char*) ret + (offset - rounded_offset);
	}
	return NULL;
}

// GAH: with the move to entries, we need a side table to get
// the address represented by any given entry.
// PERHAPS the right thing is to sort in groups,
// then do a merge?
// PERHAPS the right thing is to avoid extrasyms?
// ALSO the uniqtype pointers won't be statically representable.
// REMEMBER that we want to statically generate 
// - extrasyms
// - types for included-in-{dynsym,symtab} syms, since extrasyms should not duplicate them
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

struct dso_vaddr_bounds
{
	uintptr_t lowest_mapped_vaddr;
	uintptr_t limit_vaddr;
};
static int vaddr_bounds_cb(struct dl_phdr_info *info, size_t size, void *bounds_as_void)
{
	struct dso_vaddr_bounds *bounds = (struct dso_vaddr_bounds *) bounds_as_void;
	*bounds = (struct dso_vaddr_bounds) {
		.lowest_mapped_vaddr = (uintptr_t) -1,
		.limit_vaddr = 0
	};

	for (int i = 0; i < info->dlpi_phnum; ++i)
	{
		if (info->dlpi_phdr[i].p_type == PT_LOAD)
		{
			/* We can round down to int because vaddrs *within* an object 
			 * will not be more than 2^31 from the object base. */
			uintptr_t max_plus_one = info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
			if (max_plus_one > bounds->limit_vaddr) bounds->limit_vaddr = max_plus_one;
			if (info->dlpi_phdr[i].p_vaddr < bounds->lowest_mapped_vaddr)
			{
				bounds->lowest_mapped_vaddr = info->dlpi_phdr[i].p_vaddr;
			}
		}
	}
	return 1;
}

static struct dso_vaddr_bounds get_dso_vaddr_bounds(void *handle)
{
	struct dso_vaddr_bounds bounds;
	int ret = dl_for_one_object_phdrs(handle, vaddr_bounds_cb, &bounds);
	return bounds;
}
void __static_file_allocator_notify_brk(void *new_curbrk)
{
	if (!initialized) return;
	__adjust_bigalloc_end(executable_file_bigalloc, new_curbrk);
}

void __static_file_allocator_notify_load(void *handle, const void *load_site)
{
	struct link_map *l = (struct link_map *) handle;
	debug_printf(1, "notified of load of object at %s\n", l->l_name);
	/* Load the separate meta-object for this object. */
	void *meta_handle = NULL;
	int ret_meta = dl_for_one_object_phdrs(handle,
		load_and_init_all_metadata_for_one_object, &meta_handle);
	// meta_handle may be null -- we continue either way
	/* Look up the mapping sequence for this file. Note that
	 * although a file is notionally sparse, modern glibc's ld.so
	 * does ensure that it is spanned by a contiguous sequence of
	 * memory mappings, by first mapping a no-permissions chunk
	 * and then mprotecting various bits. FIXME: what about other
	 * ld.sos which may not do it this way? It would be bad if
	 * files could interleave with one another... we should
	 * probably just not support that case.
	 * SUBTLETY: this contiguous sequence does not start at the
	 * load address -- it starts at the first LOAD's base vaddr.
	 * See the hack in mmap.c. */
	struct dso_vaddr_bounds bounds = get_dso_vaddr_bounds(handle);
	assert(bounds.lowest_mapped_vaddr != (uintptr_t) -1);
	struct big_allocation *lowest_containing_mapping_bigalloc = NULL;
	struct mapping_entry *m = __liballocs_get_memory_mapping(
		(void*) (l->l_addr + bounds.lowest_mapped_vaddr),
		&lowest_containing_mapping_bigalloc);
	struct big_allocation *highest_containing_mapping_bigalloc = NULL;
	m = __liballocs_get_memory_mapping(
		(void*) (l->l_addr + bounds.limit_vaddr - 1),
		&highest_containing_mapping_bigalloc);
	/* We should have seen the mmap that created the bigalloc. If we haven't,
	 * it probably means that we haven't turned on systrapping yet. That's
	 * a logic error in liballocs; we should have done that by now. */
	if (!lowest_containing_mapping_bigalloc) abort();
	if (!highest_containing_mapping_bigalloc) abort();
	if (highest_containing_mapping_bigalloc != lowest_containing_mapping_bigalloc) abort();
	struct big_allocation *containing_mapping_bigalloc = lowest_containing_mapping_bigalloc;
	size_t file_size = (char*) highest_containing_mapping_bigalloc->end
		- (char*) lowest_containing_mapping_bigalloc->begin;
	const char *dynobj_name = dynobj_name_from_dlpi_name(l->l_name,
		(void*) l->l_addr);
	struct segments sinfo = (struct segments) { .nload = 0 };
	dl_for_one_object_phdrs(l, discover_segments_cb, &sinfo);
	assert(sinfo.nload != 0);
	size_t meta_sz = offsetof(struct file_metadata, segments)
		+ sinfo.nload * sizeof (struct segment_metadata);
	struct file_metadata *meta = __private_malloc(meta_sz);
	if (!meta) abort();
	bzero(meta, meta_sz);
	meta->load_site = load_site;
	meta->filename = __liballocs_private_strdup(dynobj_name);
	meta->l = l;
	meta->meta_obj_handle = meta_handle;
	meta->extrasym = (meta_handle ? dlsym(meta_handle, "extrasym") : NULL);
	meta->phdrs = sinfo.phdrs;
	meta->phnum = sinfo.phnum;
	/* We still haven't filled in everything... */
	/* We want to create a single "big allocation" for the whole file. 
	 * However, that's a problem ta least in the case of executables
	 * mapped by the kernel: there isn't a single mapping sequence. We
	 * fixed that in allocators/mmap.c: if we detect a hole, we map
	 * it PROT_NONE, and ensure the rules on extending mapping_sequences
	 * will swallow this into the same sequence. */
	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) lowest_containing_mapping_bigalloc->begin,
		file_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = (void*) meta,
					.free_func = &free_file_metadata
				}
			}
		},
		containing_mapping_bigalloc,
		&__static_file_allocator
	);
	b->suballocator = &__static_segment_allocator;
	char dummy;
	ElfW(auxv_t) *auxv = get_auxv(environ, &dummy);
	assert(auxv);
	ElfW(auxv_t) *ph_auxv = auxv_lookup(auxv, AT_PHDR);
	if (FILE_META_DESCRIBES_EXECUTABLE(meta))
	{
		assert(!executable_file_bigalloc);
		executable_file_bigalloc = b;
	}
	/* The only semi-portable way to get phdrs is to iterate over
	 * *all* the phdrs. But we only want to process a single file's
	 * phdrs now. Our callback must do the test. */
	int dlpi_ret = dl_for_one_object_phdrs(l, add_all_loaded_segments_for_one_file_only_cb, meta);
	assert(dlpi_ret != 0);
	assert(meta->phdrs);
	assert(meta->phnum && meta->phnum != -1);
	/* Now fill in the PT_DYNAMIC stuff. */
	meta->dynsym = (ElfW(Sym) *) dynamic_lookup(meta->l->l_ld, DT_SYMTAB)->d_un.d_ptr; /* always mapped by ld.so */
	meta->dynstr = (unsigned char *) dynamic_lookup(meta->l->l_ld, DT_STRTAB)->d_un.d_ptr; /* always mapped by ld.so */
	meta->dynstr_end = meta->dynstr + dynamic_lookup(meta->l->l_ld, DT_STRSZ)->d_un.d_val; /* always mapped by ld.so */
	/* Now we have the most file metadata we can get without re-mapping extra
	 * parts of the file. */
	/* FIXME: we'd much rather not do open() on l->l_name (race condition) --
	 * if we had the original fd that was exec'd, that would be great. */
	int fd = raw_open(l->l_name, O_RDONLY);
	if (fd != -1)
	{
		meta->ehdr = get_or_map_file_range(meta, PAGE_SIZE, fd, 0);
		if (!meta->ehdr) goto out;
		size_t shdrs_sz = meta->ehdr->e_shnum * meta->ehdr->e_shentsize;
		meta->shdrs = get_or_map_file_range(meta, shdrs_sz, fd, meta->ehdr->e_shoff);
		if (meta->shdrs)
		{
			unsigned nrelscn = 0; // how many rel/rela sections are there?
			for (unsigned i = 0; i < meta->ehdr->e_shnum; ++i)
			{
				if (meta->shdrs[i].sh_type == SHT_REL
						|| meta->shdrs[i].sh_type == SHT_RELA) ++nrelscn;
			}
			if (nrelscn > 0)
			{
				meta->rel_spine_idxs = __private_malloc(nrelscn * sizeof meta->rel_spine_idxs[0]);
				meta->rel_spine_scns = __private_malloc(nrelscn * sizeof meta->rel_spine_scns[0]);
				meta->rel_spine_len = nrelscn;
			}
			unsigned nrelscn_seen = 0;
			unsigned nrelent_seen = 0;
			for (unsigned i = 0; i < meta->ehdr->e_shnum; ++i)
			{
#define GET_OR_MAP_SCN(__j) get_or_map_file_range(meta, meta->shdrs[(__j)].sh_size, fd, meta->shdrs[(__j)].sh_offset)
				if (meta->shdrs[i].sh_type == SHT_DYNSYM)
				{
					meta->dynsymndx = i;
					meta->dynstrndx = meta->shdrs[i].sh_link;
				}
				if (meta->shdrs[i].sh_type == SHT_SYMTAB)
				{
					meta->symtabndx = i;
					meta->symtab = GET_OR_MAP_SCN(i);
					meta->strtabndx = meta->shdrs[i].sh_link;
					meta->strtab = GET_OR_MAP_SCN(meta->shdrs[i].sh_link);
				}
				if (i == meta->ehdr->e_shstrndx)
				{
					meta->shstrtab = GET_OR_MAP_SCN(i);
				}
				if (meta->shdrs[i].sh_type == SHT_REL
						|| meta->shdrs[i].sh_type == SHT_RELA)
				{
					unsigned nrel = meta->shdrs[i].sh_size / meta->shdrs[i].sh_entsize;
					meta->rel_spine_idxs[nrelscn_seen] = nrelent_seen;
					meta->rel_spine_scns[nrelscn_seen] = GET_OR_MAP_SCN(i);
					++nrelscn_seen;
					nrelent_seen += nrel;
				}
#undef GET_OR_MAP_SCN
			}

			/* Now define sections for all the allocated sections in the shdrs
			 * which overlap this phdr. */
			for (ElfW(Shdr) *shdr = meta->shdrs; shdr != meta->shdrs + meta->ehdr->e_shnum; ++shdr)
			{
				if ((shdr->sh_flags & SHF_ALLOC) &&
						shdr->sh_size > 0)
				{
					__static_section_allocator_notify_define_section(meta, shdr);
				}
			}
			// FIXME: the starts bitmaps need to be attached either to sections or
			// to segments (if we don't have section headers). That's a bit nasty.
			// It probably still works though.
		}
	out:
		close(fd);
	}
}
static void free_file_metadata(void *fm)
{
	struct file_metadata *meta = (struct file_metadata *) fm;
	__private_free((void*) meta->filename);
	for (unsigned i = 0; i < MAPPING_MAX; ++i)
	{
		if (meta->extra_mappings[i].mapping_pagealigned)
		{
			munmap(meta->extra_mappings[i].mapping_pagealigned,
				meta->extra_mappings[i].size);
		}
	}
	if (meta->rel_spine_idxs) __private_free(meta->rel_spine_idxs);
	if (meta->rel_spine_scns) __private_free(meta->rel_spine_scns);
	__private_free(meta);
}

static int discover_segments_cb(struct dl_phdr_info *info, size_t size, void *segments_as_void)
{
	struct segments *out = (struct segments *) segments_as_void;
	out->phnum = info->dlpi_phnum;
	out->phdrs = info->dlpi_phdr;
	unsigned nload = 0;
	for (int i = 0; i < info->dlpi_phnum; ++i)
	{
		if (info->dlpi_phdr[i].p_type == PT_LOAD) ++nload;
	}
	out->nload = nload;
	return 1; // can stop now
}

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info, size_t size, void *file_metadata)
{
	/* Produce the sorted symbols vector for this file. 
	 * We do this here because dynsym is shared across the whole file. */
	struct file_metadata *meta = (struct file_metadata *) file_metadata;
	unsigned nload = 0;
	for (unsigned i = 0; i < info->dlpi_phnum; ++i)
	{
		// if this phdr's a LOAD
		if (info->dlpi_phdr[i].p_type == PT_LOAD)
		{
			__static_segment_allocator_notify_define_segment(
					meta,
					i,
					nload++
				);
		}
	}
	return 1;
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

static liballocs_err_t get_info(void * obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* The only allocation we have is the bigalloc, so it's easy. */
	assert(b);
	if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;
	if (out_base) *out_base = b->begin;
	if (out_site) *out_site =
		((struct file_metadata *) (b->meta.un.opaque_data.data_ptr))
			->load_site;
	if (out_size) *out_size = (char*) b->end - (char*) b->begin;
	return NULL;
}

DEFAULT_GET_TYPE

struct allocator __static_file_allocator = {
	.name = "static-file",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type
};
