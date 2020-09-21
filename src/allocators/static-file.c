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
#include "raw-syscalls-defs.h" /* for raw_open */
#include "relf.h"
#include "librunt.h"
#include "liballocs_private.h"
#include "pageindex.h"
#include "allocsites.h"

/* We now split static metadata into static-file, static-segment,
   static-section and static-symbol. This file implements only static-file,
   but here is an overview of how the whole thing works.

   "Static" metadata is by definition something that doesn't change often.
   So we can store metadata in precomputed packed arrays, rather than a
   linked structure.

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

struct file_metadata *__static_file_allocator_notify_load(void *handle, const void *load_site);

void ( __attribute__((constructor(102))) __static_file_allocator_init)(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__runt_files_init();
		__mmap_allocator_init();
		__auxv_allocator_init();
		/* librunt has already snapshotted the "early libs" and done *its*
		 * metadata stuff. Our best bet might be if we can hook those calls so that
		 * they do our metadata stuff too. Can we? YES, our __static_file_allocator_notify_load
		 * is simply __wrap___runt_files_notify_load().  */
		/* For all loaded objects... */
		if (__liballocs_debug_level >= 10)
		{
			for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
			{
				/* l_addr isn't guaranteed to be mapped, so use _DYNAMIC a.k.a. l_ld'*/
				void *query_addr = l->l_ld;
				struct big_allocation *containing_mapping =__lookup_bigalloc_top_level(query_addr);
				struct big_allocation *containing_file = __lookup_bigalloc_under(
					query_addr, &__static_file_allocator, containing_mapping, NULL);
				assert(containing_file);
				struct allocs_file_metadata *afile =
						 containing_file->meta.un.opaque_data.data_ptr;	
				for (unsigned i_seg = 0; i_seg < afile->m.nload; ++i_seg)
				{
					union sym_or_reloc_rec *metavector = afile->m.segments[i_seg].metavector;
					size_t metavector_size = afile->m.segments[i_seg].metavector_size;
#if 1 /* librunt doesn't do this */
					// we print the whole metavector
					for (unsigned i = 0; i < metavector_size / sizeof *metavector; ++i)
					{
						fprintf(stream_err, "At %016lx there is a static alloc of kind %u, idx %08u, type %s\n",
							afile->m.l->l_addr + vaddr_from_rec(&metavector[i], afile),
							(unsigned) (metavector[i].is_reloc ? REC_RELOC : metavector[i].sym.kind),
							(unsigned) (metavector[i].is_reloc ? 0 : metavector[i].sym.idx),
							UNIQTYPE_NAME(
								metavector[i].is_reloc ? NULL :
								(struct uniqtype *)(((uintptr_t) metavector[i].sym.uniqtype_ptr_bits_no_lowbits)<<3)
							)
						);
					}
#endif
				}
			}
		}
		initialized = 1;
		trying_to_initialize = 0;
	}
}

// we define this a bit closer to the allocating code, but declare it now
static void free_file_metadata(void *afm);

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

/* Override the librunt one. We return librunt a doctored pointer
 * into the middle of the chunk, as our fields have to go first. */
struct file_metadata *__alloc_file_metadata(unsigned nsegs) __attribute__((visibility("protected")));
struct file_metadata *__alloc_file_metadata(unsigned nsegs)
{
	size_t meta_sz = offsetof(struct allocs_file_metadata, m)
			+ offsetof(struct file_metadata, segments)
		+ nsegs * sizeof (struct segment_metadata);
	struct allocs_file_metadata *meta = __private_malloc(meta_sz);
	if (!meta) abort();
	bzero(meta, meta_sz);
	return &meta->m;
}
void __insert_file_metadata(struct link_map *lm, struct file_metadata *fm) __attribute__((visibility("protected")));
void __insert_file_metadata(struct link_map *lm, struct file_metadata *fm)
{
	/* This is called by librunt during __runt_files_notify_load,
	 * passing a struct file_metadata *fm that it allocated earlier
	 * with __alloc_file_metadata(unsigned nsegs).
	 *
	 * We want to get the bigalloc and install our *base* pointer (not fm,
	 * but the container) as its metadata. */
	// FIXME: actually do the bigalloc stuff here?
}
/* FIXME: Instead of replacing librutn's call, wrap it and delete the duplication */
void __delete_file_metadata(struct file_metadata **p);
void __delete_file_metadata(struct file_metadata **p)
{
	/* This is called by librunt during __runt_files_notify_unload.
	 * WE SHOULD NEVER be called, because we wrap __runt_files_notify_unload
	 * and never use librunt's code. We don't need to do anything, because
	 * we use our bigalloc destructor to take care of the metadata we
	 * allocated earlier. The bigalloc is taken down in  */
	assert(0);
}
// unlike librunt
int __reopen_file(const char *filename) __attribute__((visibility("protected")));
int __reopen_file(const char *filename)
{
	return raw_open(filename, O_RDONLY, 0);
}

struct file_metadata *__real___runt_files_metdata_by_addr(const void *addr); // needed? NO!
struct file_metadata *__static_file_allocator_metadata_by_addr(const void *addr)
{
	/* PROBLEM: this needs to be callable *before* we've init'd ourselves.
	 * because libsystrap expects to be able to call it, *and*
	 * __mmap_allocator_init() calls libsystrap
	 * to do a first round of trapping, before files are init'd.
	 * The trick is that even though the mmap allocator isn't finished initing
	 * yet, it has definitely already set up the pageindex and bigallocs, including
	 * the allocs file metadata for the early libs... so it happily lets us
	 * query any loaded object that it might be trying to systrap. See the init
	 * sequence in mmap.c. */
	
	struct big_allocation *found = __lookup_bigalloc_from_root(
		addr, &__static_file_allocator, NULL);
	if (!found) return NULL;
	struct allocs_file_metadata *meta = found->meta.un.opaque_data.data_ptr;
	assert(meta);
	return (struct file_metadata *) &meta->m;
}
struct file_metadata *__wrap___runt_files_metadata_by_addr(const void *addr)
		__attribute__((alias("__static_file_allocator_metadata_by_addr")));

static void load_metadata(struct allocs_file_metadata *meta, void *handle)
{
	/* Load the separate meta-object for this object. */
	int ret_meta = dl_for_one_object_phdrs(handle,
		load_and_init_all_metadata_for_one_object, &meta->meta_obj_handle);
	// meta_obj_handle may be null -- we continue either way
	meta->extrasym = (meta->meta_obj_handle ? dlsym(meta->meta_obj_handle, "extrasym") : NULL);
	/* We still haven't filled in everything... */
	init_allocsites_info(meta);
	init_frames_info(meta);
}
void load_meta_objects_for_early_libs(void)
{
	assert(early_lib_handles[0]);
	for (unsigned i = 0; i < MAX_EARLY_LIBS; ++i)
	{
		if (!early_lib_handles[i]) break;
		struct file_metadata *meta = __static_file_allocator_metadata_by_addr(
			early_lib_handles[i]->l_ld);
		struct allocs_file_metadata *ameta = CONTAINER_OF(meta, struct allocs_file_metadata, m);
		load_metadata(ameta, early_lib_handles[i]);
		/* The segment metavector also needs (re-)setting up. */
		unsigned nload = 0;
		for (unsigned i = 0; i < meta->phnum; ++i)
		{
			// if this phdr's a LOAD
			if (meta->phdrs[i].p_type == PT_LOAD)
			{
				__static_segment_setup_metavector(ameta,
						i,
						nload++
					);
			}
		}
	}
}

struct file_metadata *__real___runt_files_notify_load(void *handle, const void *load_site);
struct file_metadata *__static_file_allocator_notify_load(void *handle, const void *load_site)
{
	/* DON'T init ourselves -- we can be called *before* our init runs,
	 * and that is by design. libsystrap requires us to have section metadata
	 * before the mmap allocator is fully initialized, so librunt will call
	 * in here really early to set up the early libs' metadata. */
	struct link_map *l = (struct link_map *) handle;
	debug_printf(1, "liballocs notified of load of object %s\n", l->l_name);
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
	if (highest_containing_mapping_bigalloc != lowest_containing_mapping_bigalloc)
	{
		/* This means the file "has holes" between its mappings.
		 * I've only seen this with ld.so, because it is mapped
		 * by the kernel. With GNU ld.so we never create holes
		 * for DSOs mapped by the ld.so itself. */
		assert((intptr_t) highest_containing_mapping_bigalloc->begin >
			(intptr_t) lowest_containing_mapping_bigalloc->end);
		if (0 != strcmp(l->l_name, __ldso_name))
		{
			debug_printf(0, "Aborting after seeing non-ld.so DSO with a hole. This is fixable....\n");
			abort();
		}
		debug_printf(0, "Saw ld.so with a hole in... checking the middle chunk is free");
		for (unsigned long i = PAGENUM(lowest_containing_mapping_bigalloc->end);
				i != PAGENUM(highest_containing_mapping_bigalloc->begin);
				++i)
		{
			assert(pageindex[i] == 0);
		}
		debug_printf(0, "Saw ld.so with a hole in... mapping the middle chunk");
		void *ret = mmap(lowest_containing_mapping_bigalloc->end,
			(uintptr_t) highest_containing_mapping_bigalloc->begin -
			(uintptr_t) lowest_containing_mapping_bigalloc->end,
				PROT_NONE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (MMAP_RETURN_IS_ERROR(ret))
		{
			debug_printf(0, "Aborting after failing to plug hole in ld.so mappings\n");
			abort();
		}
		/* Now we've plugged the hole, we need to coalesce the mappings.
		 * First let's check that the plug mapping has successfully been
		 * coalesced into the first bigalloc. */
		struct big_allocation *plug_mapping_bigalloc = NULL;
		__liballocs_get_memory_mapping(
			(void*)((intptr_t) highest_containing_mapping_bigalloc->begin - 1),
			&plug_mapping_bigalloc);
		assert(plug_mapping_bigalloc);
		assert(plug_mapping_bigalloc == lowest_containing_mapping_bigalloc);
		/* Now we want to coalesce the two now-abutting bigallocs and fix up the mapping
		 * sequence metadata. We
		 * - grab the mapping_sequence pointer from the higher-addressed bgialloc
		 * - delete that bigalloc
		 * - HACK the 'plug' mapping sequence element so it's not seen as anonymous
		 * - re-augment the mapping sequence with the mappings from the higher
		 * - free the mapping sequence we grabbed */
		struct mapping_sequence *upper_seq = (struct mapping_sequence *)
		     highest_containing_mapping_bigalloc->meta.un.opaque_data.data_ptr;
		struct mapping_sequence *lower_seq = (struct mapping_sequence *)
		    lowest_containing_mapping_bigalloc->meta.un.opaque_data.data_ptr;
		void *upper_end = highest_containing_mapping_bigalloc->end;
		/* Since the plug should have been added to the pre-existing sequence,
		 * we expect at least two mappings. */
		assert(lower_seq->nused >= 2);
		assert(lower_seq->mappings[lower_seq->nused - 1].is_anon);
		assert(0 == strcmp(lower_seq->filename, __ldso_name));
		lower_seq->mappings[lower_seq->nused - 1].is_anon = 0; // the HACK moment
		_Bool success = __liballocs_delete_bigalloc_at(highest_containing_mapping_bigalloc->begin,
			&__mmap_allocator);
		assert(success);
		__adjust_bigalloc_end(lowest_containing_mapping_bigalloc, upper_end);
		for (int i = 0; i < upper_seq->nused; ++i)
		{
			__augment_mapping_sequence(
				lower_seq,
				upper_seq->mappings[i].begin,
				upper_seq->mappings[i].end,
				upper_seq->mappings[i].prot,
				upper_seq->mappings[i].flags,
				upper_seq->mappings[i].offset,
				__ldso_name,
				upper_seq->mappings[i].caller);
		}
		assert(lower_seq->end == upper_end);
		__private_free(lower_seq);
	}
	struct big_allocation *containing_mapping_bigalloc = lowest_containing_mapping_bigalloc;
	size_t file_bigalloc_size = (uintptr_t)((char*) l->l_addr + bounds.limit_vaddr)
		- (uintptr_t) lowest_containing_mapping_bigalloc->begin;
	/* We want to create a single "big allocation" for the whole file. 
	 * However, that's a problem ta least in the case of executables
	 * mapped by the kernel: there isn't a single mapping sequence. We
	 * fixed that in allocators/mmap.c: if we detect a hole, we map
	 * it PROT_NONE, and ensure the rules on extending mapping_sequences
	 * will swallow this into the same sequence. */
	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) lowest_containing_mapping_bigalloc->begin, // the file begins at a page boundary
		file_bigalloc_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = NULL, /* for now... */
					.free_func = &free_file_metadata
				}
			}
		},
		containing_mapping_bigalloc,
		&__static_file_allocator
	);
	b->suballocator = &__static_segment_allocator;
	/* Now we're ready to call librunt... it will allocate the metadata 
	 * for us (by callback to __alloc_file_metadata). */
	struct file_metadata *fm = __real___runt_files_notify_load(handle, load_site);
	assert(fm);
	struct allocs_file_metadata *meta = CONTAINER_OF(fm, struct allocs_file_metadata, m);
	if (FILE_META_DESCRIBES_EXECUTABLE(&meta->m))
	{
		assert(!executable_file_bigalloc);
		executable_file_bigalloc = b;
	}
	b->meta.un.opaque_data.data_ptr = meta;
	_Bool we_are_early = 0;
	assert(early_lib_handles[0]);
	for (unsigned i = 0; i < MAX_EARLY_LIBS; ++i)
	{
		if (!early_lib_handles[i]) break;
		if (early_lib_handles[i] == handle) { we_are_early = 1; break; }
	}
	if (!we_are_early) load_metadata(meta, handle);
	return &meta->m;
}
struct file_metadata *__wrap___runt_files_notify_load(void *handle, const void *load_site) __attribute__((alias("__static_file_allocator_notify_load")));

static void free_file_metadata(void *afm_as_void)
{
	struct allocs_file_metadata *afm = (struct allocs_file_metadata *) afm_as_void;
	__runt_deinit_file_metadata(&afm->m);
	__private_free(afm);
}

/* FIXME: would be better if our dlclose hook gave us more than
 * just a filename. But what can it give us? We only know that
 * the ld.so really does the unload *after* it's happened, when
 * the structures have been removed. There is also a danger of
 * races here.
 *
 * I guess it could pre-copy the link map structure, and then if
 * it goes away, retain the . That would give us a "base address,
 * filename" pair. Even that is vulnerable to "reload racing", if
 * the file is immediately reopened.
 *
 * Another approach might be to intern the filename string, so that
 * we never free it but ensure it is re-used if the same filename
 * reoccurs. This would cause unbounded growth in a program that
 * loads unboundedly many files, unless we could reliably (i.e. non-
 * racily) refcount the interned strings somehow. Probably, issuing
 * and refbumping the interned strings could be made atomic w.r.t.
 * a sweep looking for zero-referenced interned strings. */
void __static_file_allocator_notify_unload(const char *copied_filename)
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
				struct allocs_file_metadata *afm = (struct allocs_file_metadata *) b->meta.un.opaque_data.data_ptr;
				if (0 == strcmp(copied_filename, afm->m.filename))
				{
					/* unload meta-object */
					dlclose(afm->meta_obj_handle);
					/* It's a match, so delete. FIXME: don't match by name (fragile);
					 * load addr is better */
					__liballocs_delete_bigalloc_at(b->begin, &__static_file_allocator);
					// this will call the callback free_func we installed in the bigalloc
				}
			}
		}
	}
}
void __wrap___runt_files_notify_unload(const char *copied_filename)
		__attribute__((alias("__static_file_allocator_notify_unload")));

static liballocs_err_t get_info(void * obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* The only allocation we have is the bigalloc, so it's easy. */
	assert(b);
	if (out_type) *out_type = pointer_to___uniqtype____uninterpreted_byte;
	if (out_base) *out_base = b->begin;
	if (out_site) *out_site =
		((struct allocs_file_metadata *) (b->meta.un.opaque_data.data_ptr))
			->m.load_site;
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
