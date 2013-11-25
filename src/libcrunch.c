/* Libcrunch contains all the non-inline code that we need for doing run-time 
 * type checks on C code. */

#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include "libcrunch.h"

static const char *allocsites_base;
static unsigned allocsites_base_len;

_Bool __libcrunch_is_initialized;
allocsmt_entry_type *__libcrunch_allocsmt;

static const char *allocsites_libfile_name(const char *objname, const char *suffix)
{
	static char libfile_name[4096];
	unsigned bytes_left = sizeof libfile_name - 1;
	
	libfile_name[0] = '\0';
	bytes_left--;
	// append the uniqtypes base path
	strncat(libfile_name, allocsites_base, bytes_left);
	bytes_left -= (bytes_left < allocsites_base_len) ? bytes_left : allocsites_base_len;
	
	// now append the executable name
	unsigned file_name_len = strlen(objname);
	assert(file_name_len > 0);
	strncat(libfile_name, objname, bytes_left);
	bytes_left -= (bytes_left < file_name_len) ? bytes_left : file_name_len;
	
	// now append the suffix
	strncat(libfile_name, suffix, bytes_left);
	// no need to compute the last bytes_left
	
	return &libfile_name[0];
}	

static int load_types_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	// load the -types.so object
	const char *libfile_name = allocsites_libfile_name(info->dlpi_name, "-types.so");

	// fprintf(stderr, "libcrunch: trying to open %s\n", libfile_name);

	dlerror();
	void *handle = dlopen(libfile_name, RTLD_NOW);
	if (!handle)
	{
		fprintf(stderr, "dlopen() error: %s\n", dlerror());
		exit(1);
	}
	
	// always continue with further objects
	return 0;
}

static int load_and_init_allocsites_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	// load the -types.so object
	const char *libfile_name = allocsites_libfile_name(info->dlpi_name, "-allocsites.so");

	// fprintf(stderr, "libcrunch: trying to open %s\n", libfile_name);
	dlerror();
	void *allocsites_handle = dlopen(libfile_name, RTLD_NOW);
	if (!allocsites_handle)
	{
		fprintf(stderr, "dlopen() error: %s\n", dlerror());
		exit(1);
	}
	
	dlerror();
	struct allocsite_entry *first_entry = (struct allocsite_entry *) dlsym(allocsites_handle, "allocsites");
	assert(first_entry); // allocsites cannot be null anyhow

	/* We walk through allocsites in this object, chaining together those which
	 * should be in the same bucket. NOTE that this is the kind of thing we'd
	 * like to get the linker to do for us, but it's not quite expressive enough. */
	struct allocsite_entry *cur_ent = first_entry;
	struct allocsite_entry *prev_ent = NULL;
	unsigned current_bucket_size = 1; // out of curiosity...
	for (; cur_ent->allocsite; prev_ent = cur_ent++)
	{
		// debugging: print out entry
		/* fprintf(stderr, "allocsite entry: %p, to uniqtype at %p\n", 
			cur_ent->allocsite, cur_ent->uniqtype); */
		
		// if we've moved to a different bucket, point the table entry at us
		struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, cur_ent->allocsite);
		struct allocsite_entry **prev_ent_bucketpos
		 = prev_ent ? ALLOCSMT_FUN(ADDR, prev_ent->allocsite) : NULL;
		
		// fix up the allocsite by the containing object's load address
		*((unsigned char **) &cur_ent->allocsite) += info->dlpi_addr;
		
		// first iteration is too early to do chaining, 
		// but we do need to set up the first bucket
		if (!prev_ent || bucketpos != prev_ent_bucketpos)
		{
			// fresh bucket, so should be null
			assert(!*bucketpos);
			*bucketpos = cur_ent;
		}
		if (!prev_ent) continue;
		
		void *cur_range_base = ALLOCSMT_FUN(ADDR_RANGE_BASE, cur_ent->allocsite);
		void *prev_range_base = ALLOCSMT_FUN(ADDR_RANGE_BASE, prev_ent->allocsite);
		
		if (cur_range_base == prev_range_base)
		{
			// chain these guys together
			prev_ent->next = cur_ent;
			cur_ent->prev = prev_ent;
			
			++current_bucket_size;
		} else current_bucket_size = 1; 
		// we don't (currently) distinguish buckets of zero from buckets of one
		
		// last iteration doesn't need special handling -- next will be null,
		// prev will be set within the "if" above, if it needs to be set.
	}

	// debugging: check that we can look up the first entry, if we are non-empty
	assert(!first_entry || 
		allocsite_to_uniqtype(first_entry->allocsite) == first_entry->uniqtype);
	
	return 0; // always continue
	
	// always continue with further objects
	return 0;
}

const struct rec *__libcrunch_uniqtype_void; // remember the location of the void uniqtype
/* counters */
unsigned long __libcrunch_begun;
unsigned long __libcrunch_aborted_init;
unsigned long __libcrunch_aborted_stack;
unsigned long __libcrunch_aborted_static;
unsigned long __libcrunch_aborted_unknown_storage;
unsigned long __libcrunch_aborted_unindexed_heap;
unsigned long __libcrunch_aborted_unrecognised_allocsite;
unsigned long __libcrunch_failed;
unsigned long __libcrunch_trivially_succeeded_null;
unsigned long __libcrunch_trivially_succeeded_void;
unsigned long __libcrunch_succeeded;

static void print_exit_summary(void)
{
	fprintf(stderr, "libcrunch summary: \n");
	fprintf(stderr, "checks begun:                          % 7ld\n", __libcrunch_begun);
	fprintf(stderr, "checks aborted due to init failure:    % 7ld\n", __libcrunch_aborted_init);
	fprintf(stderr, "checks aborted for stack objects:      % 7ld\n", __libcrunch_aborted_stack);
	fprintf(stderr, "checks aborted for static objects:     % 7ld\n", __libcrunch_aborted_static);
	fprintf(stderr, "checks aborted for unknown storage:    % 7ld\n", __libcrunch_aborted_unknown_storage);
	fprintf(stderr, "checks aborted for unindexed heap:     % 7ld\n", __libcrunch_aborted_unindexed_heap);
	fprintf(stderr, "checks aborted for unrecognised alloc: % 7ld\n", __libcrunch_aborted_unrecognised_allocsite);
	fprintf(stderr, "checks failed:                         % 7ld\n", __libcrunch_failed);
	fprintf(stderr, "checks trivially passed on null ptr:   % 7ld\n", __libcrunch_trivially_succeeded_null);
	fprintf(stderr, "checks trivially passed for void type: % 7ld\n", __libcrunch_trivially_succeeded_void);
	fprintf(stderr, "checks nontrivially passed:            % 7ld\n", __libcrunch_succeeded);
}

/* This is *not* a constructor. We don't want to be called too early,
 * because it might not be safe to open the -uniqtypes.so handle yet.
 * So, initialize on demand. */
int __libcrunch_global_init(void)
{
	if (__libcrunch_is_initialized) return 0; // we are okay
	static _Bool tried_to_initialize;
	
	if (tried_to_initialize) return -1;
	tried_to_initialize = 1;
	
	// print a summary when the program exits
	atexit(print_exit_summary);

	// to locate our executable, we use /proc
// 	int count = readlink("/proc/self/exe", execfile_name,
// 		sizeof execfile_name);
// 	if (count == -1) return -1; // nothing we can do
// 	unsigned execfile_name_len = count;
// 	
	allocsites_base = getenv("ALLOCSITES_BASE");
	if (!allocsites_base) allocsites_base = "/usr/lib/allocsites";
	allocsites_base_len = strlen(allocsites_base);
	
	int ret_types = dl_iterate_phdr(load_types_cb, NULL);
	assert(ret_types == 0);
	
	
	/* Allocate the memtable. 
	 * Assume we don't need to cover addresses >= STACK_BEGIN. */
	__libcrunch_allocsmt = MEMTABLE_NEW_WITH_TYPE(allocsmt_entry_type, allocsmt_entry_coverage, 
		(void*) 0, (void*) STACK_BEGIN);
	assert(__libcrunch_allocsmt != MAP_FAILED);
	
	/* Get a pointer to the start of the allocsites table. */
	struct allocsite_entry *first_entry;
	assert(__libcrunch_check_init() != -1);
	
	int ret_allocsites = dl_iterate_phdr(load_and_init_allocsites_cb, NULL);
	assert(ret_allocsites == 0);
	
	return 0;
}

/* FIXME: hook dlopen and dlclose so that we can */

/* This is left out-of-line because it's inherently a slow path. */
struct rec *typestr_to_uniqtype(const char *typestr)
{
	if (!typestr) return NULL;
	
	dlerror();
	void *returned = dlsym(RTLD_NEXT, typestr);
	if (!returned) return NULL;
	if (!__libcrunch_uniqtype_void && strcmp(typestr, "__uniqtype__void") == 0)
	{
		__libcrunch_uniqtype_void = (struct rec *) returned;
	}
	return (struct rec *) returned;
}

/* Force instantiation of __is_a in libcrunch, by repeating its prototype.
 * We do this so that linking an application -lcrunch is sufficient to
 * generate a weak *dynamic* reference to __is_a. */
int __is_a(const void *obj, const char *typestr);
int __is_aU(const void *obj, const struct rec *uniqtype);
int __is_a3(const void *obj, const char *typestr, const struct rec **maybe_uniqtype);

// same for initialization and, in fact, everything....
int __libcrunch_check_init(void);
enum object_memory_kind get_object_memory_kind(const void *obj);
struct rec *allocsite_to_uniqtype(const void *allocsite);
struct rec *typestr_to_uniqtype(const char *typestr);
