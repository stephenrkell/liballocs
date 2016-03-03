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
#include <link.h>
#include "relf.h"
#include "liballocs_private.h"
#include "pageindex.h"
#include "raw-syscalls.h"

struct allocator __static_allocator = {
	.name = "static",
	.is_cacheable = 1
};

static _Bool trying_to_initialize;
static _Bool initialized;

int add_all_loaded_segments(struct dl_phdr_info *info, size_t size, void *data)
	__attribute__((visibility("hidden")));

void __static_allocator_init(void) __attribute__((constructor(101)));
void __static_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__mmap_allocator_init();
		dl_iterate_phdr(add_all_loaded_segments, /* any filename */ NULL);
		initialized = 1;
		trying_to_initialize = 0;
	}
}

void __static_allocator_notify_load(void *handle)
{
	int dlpi_ret = dl_iterate_phdr(add_all_loaded_segments, 
		((struct link_map *) handle)->l_name);
	assert(dlpi_ret != 0);
}

struct segment_metadata
{
	const char *filename;
	Elf64_Phdr *phdr;
};

static void free_segment_metadata(void *sm)
{
	struct segment_metadata *s = (struct segment_metadata *) sm;
	free((void*) s->filename);
	free(sm);
}

void __static_allocator_notify_unload(const char *copied_filename)
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
				__liballocs_delete_bigalloc(b->begin, &__static_allocator);
			}
		}
	}
}

int add_all_loaded_segments(struct dl_phdr_info *info, size_t size, void *data)
{
	static _Bool running;
	/* HACK: if we have an instance already running, quit early. */
	if (running) /* return 1; */ abort(); // i.e. debug this
	running = 1;
	write_string("Blah9000\n");
	const char *filename = (const char *) data;
	if (filename != NULL && 0 == strcmp(filename, info->dlpi_name))
	{
		write_string("Blah9001\n");
		const char *dynobj_name = dynobj_name_from_dlpi_name(info->dlpi_name, 
			(void*) info->dlpi_addr);
		if (!dynobj_name) dynobj_name = "(unknown)";

		// this is the file we care about, so iterate over its phdrs
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
				struct segment_metadata *m = malloc(sizeof (struct segment_metadata));
				*m = (struct segment_metadata) {
					/* We strdup once per segment, even though the filename could be 
					 * shared, in order to simplify the cleanup logic. */
					.filename = private_strdup(dynobj_name),
					.phdr = &info->dlpi_phdr[i]
				};
				
				const struct big_allocation *b = __liballocs_new_bigalloc(
					segment_start_addr,
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
			}
		}
		
		// if we were looking for a single file, and got here, then we found it; can stop now
		if (filename != NULL) { running = 0; return 1; }
	}
	write_string("Blah9050\n");

	running = 0;
	
	// keep going
	return 0;
}
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
				if (out_object_start) *out_object_start = p->allocsite;
				return p->uniqtype;
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




static liballocs_err_t get_info(void * obj, struct uniqtype **out_type, void **out_base, 
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
//				consider_blacklisting(obj);
		return &__liballocs_err_unrecognised_static_object;
	}

	// else we can go ahead
	if (out_base) *out_base = object_start;
	if (out_site) *out_site = object_start;
	if (out_size) *out_size = alloc_uniqtype->pos_maxoff;
	return NULL;
}
