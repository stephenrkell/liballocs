/* Libcrunch contains all the non-inline code that we need for doing run-time 
 * type checks on C code. */

#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <link.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <libunwind.h>
#include "libcrunch.h"
#include "libcrunch_private.h"

static const char *allocsites_base;
static unsigned allocsites_base_len;
// keep these close, keep them fast
uintptr_t page_size __attribute__((visibility("protected")));
uintptr_t log_page_size __attribute__((visibility("protected")));
uintptr_t page_mask __attribute__((visibility("protected")));

int __libcrunch_debug_level;
_Bool __libcrunch_is_initialized;
allocsmt_entry_type *__libcrunch_allocsmt;

// these two are defined in addrmap.h as weak
void *__addrmap_executable_end_addr;
unsigned long __addrmap_max_stack_size;

// helper
static const void *typestr_to_uniqtype_from_lib(void *handle, const char *typestr);

// HACK
void __libcrunch_preload_init(void);

#define BLACKLIST_SIZE 8
struct blacklist_ent 
{
	uintptr_t bits; 
	uintptr_t mask; 
	void *actual_start;
	size_t actual_length;
} blacklist[BLACKLIST_SIZE];
static _Bool check_blacklist(const void *obj);
static void consider_blacklisting(const void *obj);

/* Some data types like void* and sockaddr appear to be used to size a malloc(), 
 * but are only used because they have the same size as the actual thing being
 * allocated (say a different type of pointer, or a family-specific sockaddr). 
 * We keep a list of these. The user can use the LIBCRUNCH_LAZY_HEAP_TYPES 
 * environment variable to add these. */
static unsigned lazy_heap_types_count;
static const char **lazy_heap_typenames;
static struct uniqtype **lazy_heap_types;

static int iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg);

static int print_type_cb(struct uniqtype *t, void *ignored)
{
	fprintf(stderr, "uniqtype addr %p, name %s, size %d bytes\n", 
		t, t->name, t->pos_maxoff);
	fflush(stderr);
	return 0;
}

static int match_typename_cb(struct uniqtype *t, void *ignored)
{
	for (unsigned i = 0; i < lazy_heap_types_count; ++i)
	{
		if (!lazy_heap_types[i] && 
			0 == strcmp(t->name, lazy_heap_typenames[i]))
		{
			// install this type in the lazy_heap_type slot
			lazy_heap_types[i] = t;
			
			// keep going -- we might have more to match
			return 0;
		}
	}
	return 0; // keep going
}

void __libcrunch_scan_lazy_typenames(void *typelib_handle)
{
	iterate_types(typelib_handle, match_typename_cb, NULL);

	// for (unsigned i = 0; i < lazy_heap_types_count; ++i)
	// {
	// 	if (lazy_heap_typenames[i] && !lazy_heap_types[i])
	// 	{
	// 		// look up 
	// 		const void *u = typestr_to_uniqtype_from_lib(typelib_handle, lazy_heap_typenames[i]);
	// 		// if we found it, install it
	// 		if (u) lazy_heap_types[i] = (struct uniqtype *) u;
	//	}
	// }
}

static ElfW(Dyn) *get_dynamic_section(void *handle)
{
	return ((struct link_map *) handle)->l_ld;
}

static ElfW(Dyn) *get_dynamic_entry_from_section(void *dynsec, unsigned long tag)
{
	ElfW(Dyn) *dynamic_section = dynsec;
	while (dynamic_section->d_tag != DT_NULL
		&& dynamic_section->d_tag != tag) ++dynamic_section;
	if (dynamic_section->d_tag == DT_NULL) return NULL;
	return dynamic_section;
}

static ElfW(Dyn) *get_dynamic_entry_from_handle(void *handle, unsigned long tag)
{
	return get_dynamic_entry_from_section(((struct link_map *) handle)->l_ld, tag);
}

static int iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg)
{
	/* Don't use dladdr() to iterate -- too slow! Instead, iterate 
	 * directly over the dynsym section. */
	unsigned char *load_addr = (unsigned char *) ((struct link_map *) typelib_handle)->l_addr;
	/* We don't have to add load_addr, because ld.so has already done it. */
	ElfW(Sym) *dynsym = (ElfW(Sym) *) get_dynamic_entry_from_handle(typelib_handle, DT_SYMTAB)->d_un.d_ptr;
	assert(dynsym);
	
	/* If dynsym is greater than STACK_BEGIN, it means it's the vdso --
	 * skip it, because it doesn't contain any uniqtypes and we may fault
	 * trying to read its dynsym. */
	if ((uintptr_t) dynsym > STACK_BEGIN) return 0;
	
	// check that we start with a null symtab entry
	static const ElfW(Sym) nullsym = { 0, 0, 0, 0, 0, 0 };
	assert(0 == memcmp(&nullsym, dynsym, sizeof nullsym));
	assert((unsigned char *) dynsym > load_addr);
	unsigned char *dynstr = (unsigned char *) get_dynamic_entry_from_handle(typelib_handle, DT_STRTAB)->d_un.d_ptr;
	assert(dynstr > (unsigned char *) dynsym);
	size_t dynsym_size = dynstr - (unsigned char *) dynsym;
	// round down, because dynstr might be padded
	dynsym_size = (dynsym_size / sizeof (ElfW(Sym))) * sizeof (ElfW(Sym));
	int cb_ret = 0;

	for (ElfW(Sym) *p_sym = dynsym; (unsigned char *) p_sym < (unsigned char *) dynsym + dynsym_size; 
		++p_sym)
	{
		if (ELF64_ST_TYPE(p_sym->st_info) == STT_OBJECT && 
			p_sym->st_shndx != SHN_UNDEF &&
			0 == strncmp("__uniqty", dynstr + p_sym->st_name, 8))
		{
			struct uniqtype *t = (struct uniqtype *) (load_addr + p_sym->st_value);
			// if our name comes out as null, we've probably done something wrong
			if (t->name)
			{
				cb_ret = cb(t, arg);
				if (cb_ret != 0) break;
			}
		}
	}
	
	return cb_ret;
}

static _Bool is_lazy_uniqtype(const void *u)
{
	for (unsigned i = 0; i < lazy_heap_types_count; ++i)
	{
		if (lazy_heap_types[i] == u) return 1;
	}
	return 0;
}

static _Bool done_init;
void __libcrunch_main_init(void) __attribute__((constructor(101)));
// NOTE: runs *before* the constructor in preload.c
void __libcrunch_main_init(void)
{
	assert(!done_init);
	
	done_init = 1;
}

// FIXME: do better!
static char *realpath_quick_hack(const char *arg)
{
	static char buf[4096];
	return realpath(arg, &buf[0]);
}

static const char *dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr)
{
	static char execfile_name[4096];
	
	if (strlen(dlpi_name) == 0)
	{
		/* libdl can give us an empty name for 
		 *
		 * - the executable;
		 * - itself;
		 * - any others?
		 *
		 * To avoid parsing /proc/self/maps, we use a quick hack: 
		 * ask dladdr, and expect it to know the pathname. It seems
		 * to work.
		 */
		if (dlpi_addr == 0)
		{
			// use /proc to get our executable filename
			int count = readlink("/proc/self/exe", execfile_name, sizeof execfile_name);
			assert(count != -1); // nothing we can do
			
			// use this filename now
			return execfile_name;
		}
		else
		{
			dlerror();
			Dl_info addr_info;
			int dladdr_ret = dladdr(dlpi_addr, &addr_info);
			if (dladdr_ret == 0)
			{
				debug_printf(1, "dladdr could not resolve library loaded at %p\n", dlpi_addr);
				return NULL;
				// char cmdbuf[4096];
				// int snret = snprintf(cmdbuf, 4096, "cat /proc/%d/maps", getpid());
				// assert(snret > 0);
				// system(cmdbuf);
				// assert(0 && "no filename available for some loaded object");
			}
			assert(addr_info.dli_fname != NULL);
			return realpath_quick_hack(addr_info.dli_fname);
		}
	} 
	else
	{
		// we need to realpath() it
		return realpath_quick_hack(dlpi_name);
	}
}

static const char *helper_libfile_name(const char *objname, const char *suffix)
{
	static char libfile_name[4096];
	unsigned bytes_left = sizeof libfile_name - 1;
	
	libfile_name[0] = '\0';
	bytes_left--;
	// append the uniqtypes base path
	strncat(libfile_name, allocsites_base, bytes_left);
	bytes_left -= (bytes_left < allocsites_base_len) ? bytes_left : allocsites_base_len;
	
	// now append the object name
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
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;

	// skip objects that are themselves types/allocsites objects
	if (0 == strncmp(canon_objname, allocsites_base, allocsites_base_len)) return 0;
	
	// get the -types.so object's name
	const char *libfile_name = helper_libfile_name(canon_objname, "-types.so");
	// don't load if we end with "-types.so"
	if (0 == strcmp("-types.so", canon_objname + strlen(canon_objname) - strlen("-types.so")))
	{
		return 0;
	}

	// fprintf(stderr, "libcrunch: trying to open %s\n", libfile_name);

	dlerror();
	void *handle = dlopen(libfile_name, RTLD_NOW | RTLD_GLOBAL);
	if (!handle)
	{
		debug_printf(1, "loading types object: %s", dlerror());
		return 0;
	}
	
	// if we want maximum output, print it
	if (__libcrunch_debug_level >= 5)
	{
		iterate_types(handle, print_type_cb, NULL);
	}
	
	// scan it for lazy-heap-alloc types
	__libcrunch_scan_lazy_typenames(handle);
	
	// always continue with further objects
	return 0;
}

static void chain_allocsite_entries(struct allocsite_entry *cur_ent, 
	struct allocsite_entry *prev_ent, unsigned *p_current_bucket_size, 
	intptr_t load_addr, intptr_t extrabits)
{
#define FIXADDR(a) 	((void*)((intptr_t)(a) | extrabits))

	// fix up the allocsite by the containing object's load address
	*((unsigned char **) &cur_ent->allocsite) += load_addr;

	// debugging: print out entry
	/* fprintf(stderr, "allocsite entry: %p, to uniqtype at %p\n", 
		cur_ent->allocsite, cur_ent->uniqtype); */

	// if we've moved to a different bucket, point the table entry at us
	struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, FIXADDR(cur_ent->allocsite));
	struct allocsite_entry **prev_ent_bucketpos
	 = prev_ent ? ALLOCSMT_FUN(ADDR, FIXADDR(prev_ent->allocsite)) : NULL;

	// first iteration is too early to do chaining, 
	// but we do need to set up the first bucket
	if (!prev_ent || bucketpos != prev_ent_bucketpos)
	{
		// fresh bucket, so should be null
		assert(*bucketpos == NULL);
		*bucketpos = cur_ent;
	}
	if (!prev_ent) return;

	void *cur_range_base = ALLOCSMT_FUN(ADDR_RANGE_BASE, FIXADDR(cur_ent->allocsite));
	void *prev_range_base = ALLOCSMT_FUN(ADDR_RANGE_BASE, FIXADDR(prev_ent->allocsite));

	if (cur_range_base == prev_range_base)
	{
		// chain these guys together
		prev_ent->next = cur_ent;
		cur_ent->prev = prev_ent;

		++(*p_current_bucket_size);
	} else *p_current_bucket_size = 1; 
	// we don't (currently) distinguish buckets of zero from buckets of one

	// last iteration doesn't need special handling -- next will be null,
	// prev will be set within the "if" above, if it needs to be set.
#undef FIXADDR
}

static int load_and_init_allocsites_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;
	
	// skip objects that are themselves types/allocsites objects
	if (0 == strncmp(canon_objname, allocsites_base, allocsites_base_len)) return 0;
	
	// get the -allocsites.so object's name
	const char *libfile_name = helper_libfile_name(canon_objname, "-allocsites.so");
	// don't load if we end with "-allocsites.so"
	if (0 == strcmp("-allocsites.so", canon_objname + strlen(canon_objname) - strlen("-allocsites.so")))
	{
		return 0;
	}

	// fprintf(stderr, "libcrunch: trying to open %s\n", libfile_name);
	dlerror();
	void *allocsites_handle = dlopen(libfile_name, RTLD_NOW);
	if (!allocsites_handle)
	{
		debug_printf(1, "loading allocsites object: %s", dlerror());
		return 0;
	}
	
	dlerror();
	struct allocsite_entry *first_entry = (struct allocsite_entry *) dlsym(allocsites_handle, "allocsites");
	// allocsites cannot be null anyhow
	assert(first_entry && "symbol 'allocsites' must be present in -allocsites.so"); 

	/* We walk through allocsites in this object, chaining together those which
	 * should be in the same bucket. NOTE that this is the kind of thing we'd
	 * like to get the linker to do for us, but it's not quite expressive enough. */
	struct allocsite_entry *cur_ent = first_entry;
	struct allocsite_entry *prev_ent = NULL;
	unsigned current_bucket_size = 1; // out of curiosity...
	for (; cur_ent->allocsite; prev_ent = cur_ent++)
	{
		chain_allocsite_entries(cur_ent, prev_ent, &current_bucket_size, 
			info->dlpi_addr, 0);
	}

	// debugging: check that we can look up the first entry, if we are non-empty
	assert(!first_entry || !first_entry->allocsite || 
		allocsite_to_uniqtype(first_entry->allocsite) == first_entry->uniqtype);
	
	// always continue with further objects
	return 0;
}

static int link_stackaddr_and_static_allocs_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;

	// skip objects that are themselves types/allocsites objects
	if (0 == strncmp(canon_objname, allocsites_base, allocsites_base_len)) return 0;
	
	// get the -allocsites.so object's name
	const char *libfile_name = helper_libfile_name(canon_objname, "-types.so");
	// don't load if we end with "-types.so"
	if (0 == strcmp("-types.so", canon_objname + strlen(canon_objname) - strlen("-types.so")))
	{
		return 0;
	}

	dlerror();
	void *types_handle = dlopen(libfile_name, RTLD_NOW | RTLD_NOLOAD);
	if (!types_handle)
	{
		debug_printf(1, "re-loading types object: %s", dlerror());
		return 0;
	}
	
	{
		dlerror();
		struct allocsite_entry *first_frame_entry = (struct allocsite_entry *) dlsym(types_handle, "frame_vaddrs");
		if (!first_frame_entry)
		{
			debug_printf(1, "Could not load frame vaddrs (%s)", dlerror());
			return 0;
		}

		/* We chain these much like the allocsites, BUT we OR each vaddr with 
		 * STACK_BEGIN first.  */
		struct allocsite_entry *cur_frame_ent = first_frame_entry;
		struct allocsite_entry *prev_frame_ent = NULL;
		unsigned current_frame_bucket_size = 1; // out of curiosity...
		for (; cur_frame_ent->allocsite; prev_frame_ent = cur_frame_ent++)
		{
			chain_allocsite_entries(cur_frame_ent, prev_frame_ent, &current_frame_bucket_size,
				info->dlpi_addr, STACK_BEGIN);
		}

		// debugging: check that we can look up the first entry, if we are non-empty
		assert(!first_frame_entry || !first_frame_entry->allocsite || 
			vaddr_to_uniqtype(first_frame_entry->allocsite) == first_frame_entry->uniqtype);
	}
	
	/* Now a similar job for the statics. */
	{
		dlerror();
		struct allocsite_entry *first_static_entry = (struct allocsite_entry *) dlsym(types_handle, "statics");
		if (!first_static_entry)
		{
			debug_printf(1, "Could not load statics (%s)", dlerror());
			return 0;
		}

		/* We chain these much like the allocsites, BUT we OR each vaddr with 
		 * STACK_BEGIN<<1 first.  */
		struct allocsite_entry *cur_static_ent = first_static_entry;
		struct allocsite_entry *prev_static_ent = NULL;
		unsigned current_static_bucket_size = 1; // out of curiosity...
		for (; cur_static_ent->allocsite; prev_static_ent = cur_static_ent++)
		{
			chain_allocsite_entries(cur_static_ent, prev_static_ent, &current_static_bucket_size,
				info->dlpi_addr, STACK_BEGIN<<1);
		}

		// debugging: check that we can look up the first entry, if we are non-empty
		assert(!first_static_entry || !first_static_entry->allocsite || 
			static_addr_to_uniqtype(first_static_entry->allocsite, NULL) == first_static_entry->uniqtype);
	}
	
	// always continue with further objects
	return 0;
	
}
static _Bool check_blacklist(const void *obj)
{
#ifndef NO_BLACKLIST
	for (struct blacklist_ent *ent = &blacklist[0];
		ent < &blacklist[BLACKLIST_SIZE]; ++ent)
	{
		if (!ent->mask) continue;
		if ((((uintptr_t) obj) & ent->mask) == ent->bits) return 1;
	}
#endif
	return 0;
}
static void consider_blacklisting(const void *obj)
{
#ifndef NO_BLACKLIST
	assert(!check_blacklist(obj));
	// is the addr in any mapped dynamic obj?
	Dl_info info = { NULL /* don't care about other fields */ };
	struct link_map *link_map;
	int ret = dladdr1(obj, &info, (void**) &link_map, RTLD_DL_LINKMAP);
	if (ret != 0 && info.dli_fname != NULL) /* zero means error, i.e. not a dynamic obj */ 
	{
		return; // couldn't be sure it's *not* in a mapped object
	}
	
	// PROBLEM: how do we find out its size?
	// HACK: just blacklist a page at a time?
	
	// if it's not in any shared obj, then we might want to blacklist it
	// can we extend an existing blacklist slot?
	struct blacklist_ent *slot = NULL;
	for (struct blacklist_ent *slot_to_extend = &blacklist[0];
		slot_to_extend < &blacklist[BLACKLIST_SIZE]; ++slot_to_extend)
	{
		if ((uintptr_t) slot_to_extend->actual_start + slot_to_extend->actual_length
			 == (((uintptr_t) obj) & page_mask))
		{
			// post-extend this one
			slot_to_extend->actual_length += page_size;
			slot = slot_to_extend;
			break;
		}
		else if ((uintptr_t) slot_to_extend->actual_start - page_size == (((uintptr_t) obj) & page_mask))
		{
			// pre-extend this one
			slot_to_extend->actual_start -= page_size;
			slot_to_extend->actual_length += page_size;
			slot = slot_to_extend;
			break;
		}
	}
	if (slot == NULL)
	{
		// look for a free slot
		struct blacklist_ent *free_slot = &blacklist[0];
		while (free_slot < &blacklist[BLACKLIST_SIZE]
		 && free_slot->mask != 0) ++free_slot;
		if (free_slot == &blacklist[BLACKLIST_SIZE]) 
		{
			return; // full
		}
		else 
		{
			slot = free_slot;
			slot->actual_start = (void *)(((uintptr_t) obj) & page_mask);
			slot->actual_length = page_size;
		}
	}
	
	// we just added or created a slot; update its bits
	uintptr_t bits_in_common = ~((uintptr_t) slot->actual_start ^ ((uintptr_t) slot->actual_start + slot->actual_length - 1));
	// which bits are common *throughout* the range of values?
	// we need to find the highest-bit-unset
	uintptr_t highest_bit_not_in_common = sizeof (uintptr_t) * 8 - 1;
	while ((bits_in_common & (1ul << highest_bit_not_in_common))) 
	{
		assert(highest_bit_not_in_common != 0);
		--highest_bit_not_in_common;
	}

	const uintptr_t minimum_mask = ~((1ul << highest_bit_not_in_common) - 1);
	const uintptr_t minimum_bits = ((uintptr_t) slot->actual_start) & minimum_mask;
	
	uintptr_t bits = minimum_bits;
	uintptr_t mask = minimum_mask;
	
	// grow the mask until 
	//   the bits/mask-defined blacklisted region starts no earlier than the actual region
	// AND the region ends no later than the actual region
	// WHERE the smallest mask we want is one page
	while (((bits & mask) < (uintptr_t) slot->actual_start
			|| (bits & mask) + (~mask + 1) > (uintptr_t) slot->actual_start + slot->actual_length)
		&& ~mask + 1 > page_size)
	{
		mask >>= 1;                            // shift the mask right
		mask |= 1ul<<sizeof (uintptr_t) * 8 - 1; // set the top bit of the mask
		bits = ((uintptr_t) slot->actual_start) & mask;
		
	}
	
	// if we got a zero-length entry, give up and zero the whole lot
	assert((bits | mask) >= (uintptr_t) slot->actual_start);
	assert(bits | ~mask <= (uintptr_t) slot->actual_start + slot->actual_length);
	
	slot->mask = mask;
	slot->bits = bits;
#endif
}

static void *main_bp; // beginning of main's stack frame

const struct uniqtype *__libcrunch_uniqtype_void; // remember the location of the void uniqtype
const struct uniqtype *__libcrunch_uniqtype_signed_char;
const struct uniqtype *__libcrunch_uniqtype_unsigned_char;
#define LOOKUP_CALLER_TYPE(frag, caller) /* FIXME: use caller not RTLD_DEFAULT -- use interval tree? */ \
    ( \
		(__libcrunch_uniqtype_ ## frag) ? __libcrunch_uniqtype_ ## frag : \
		(__libcrunch_uniqtype_ ## frag = dlsym(RTLD_DEFAULT, "__uniqtype__" #frag), \
			assert(__libcrunch_uniqtype_ ## frag), \
			__libcrunch_uniqtype_ ## frag \
		) \
	)

/* counters */
unsigned long __libcrunch_begun;
#ifdef LIBCRUNCH_EXTENDED_COUNTS
unsigned long __libcrunch_aborted_init;
unsigned long __libcrunch_trivially_succeeded;
#endif
unsigned long __libcrunch_aborted_stack;
unsigned long __libcrunch_aborted_static;
unsigned long __libcrunch_aborted_typestr;
unsigned long __libcrunch_aborted_unknown_storage;
unsigned long __libcrunch_hit_heap_case;
unsigned long __libcrunch_hit_stack_case;
unsigned long __libcrunch_hit_static_case;
unsigned long __libcrunch_lazy_heap_type_assignment;
unsigned long __libcrunch_aborted_unindexed_heap;
unsigned long __libcrunch_aborted_unrecognised_allocsite;
unsigned long __libcrunch_failed;
unsigned long __libcrunch_failed_in_alloc;
unsigned long __libcrunch_succeeded;

static unsigned long suppression_count;
enum check
{
	IS_A,
	LIKE_A
};
static enum check last_suppressed_check_kind;

static void print_exit_summary(void)
{
	if (__libcrunch_begun == 0) return;
	
	if (suppression_count > 0)
	{
		debug_printf(0, "Suppressed %d further occurrences of the previous error\n", 
				suppression_count);
	}
	
	fprintf(stderr, "libcrunch summary: \n");
	fprintf(stderr, "checks begun:                             % 7ld\n", __libcrunch_begun);
	fprintf(stderr, "-------------------------------------------------\n");
#ifdef LIBCRUNCH_EXTENDED_COUNTS
	fprintf(stderr, "checks aborted due to init failure:       % 7ld\n", __libcrunch_aborted_init);
#endif
	fprintf(stderr, "checks aborted for bad typename:          % 7ld\n", __libcrunch_aborted_typestr);
	fprintf(stderr, "checks aborted for unknown storage:       % 7ld\n", __libcrunch_aborted_unknown_storage);
#ifdef LIBCRUNCH_EXTENDED_COUNTS
	fprintf(stderr, "checks trivially passed:                  % 7ld\n", __libcrunch_trivially_succeeded);
#endif
	fprintf(stderr, "=================================================\n");
#ifdef LIBCRUNCH_EXTENDED_COUNTS
	fprintf(stderr, "checks remaining                          % 7ld\n", __libcrunch_begun - (__libcrunch_trivially_succeeded + __libcrunch_aborted_unknown_storage + __libcrunch_aborted_typestr + __libcrunch_aborted_init));
#else
	fprintf(stderr, "checks remaining                          % 7ld\n", __libcrunch_begun - (__libcrunch_aborted_unknown_storage + __libcrunch_aborted_typestr));
#endif	
	fprintf(stderr, "-------------------------------------------------\n");
	fprintf(stderr, "checks handled by static case:            % 7ld\n", __libcrunch_hit_static_case);
	fprintf(stderr, "checks handled by stack case:             % 7ld\n", __libcrunch_hit_stack_case);
	fprintf(stderr, "checks handled by heap case:              % 7ld\n", __libcrunch_hit_heap_case);
	fprintf(stderr, "-------------------------------------------------\n");
	fprintf(stderr, "   of which did lazy heap type assignment:% 7ld\n", __libcrunch_lazy_heap_type_assignment);
	fprintf(stderr, "-------------------------------------------------\n");
	fprintf(stderr, "checks aborted for unindexed heap:        % 7ld\n", __libcrunch_aborted_unindexed_heap);
	fprintf(stderr, "checks aborted for unknown heap allocsite:% 7ld\n", __libcrunch_aborted_unrecognised_allocsite);
	fprintf(stderr, "checks aborted for unknown stackframes:   % 7ld\n", __libcrunch_aborted_stack);
	fprintf(stderr, "checks aborted for unknown static obj:    % 7ld\n", __libcrunch_aborted_static);
	fprintf(stderr, "checks failed inside allocation functions:% 7ld\n", __libcrunch_failed_in_alloc);
	fprintf(stderr, "checks failed otherwise:                  % 7ld\n", __libcrunch_failed);
	fprintf(stderr, "checks nontrivially passed:               % 7ld\n", __libcrunch_succeeded);
}

/* This is *not* a constructor. We don't want to be called too early,
 * because it might not be safe to open the -uniqtypes.so handle yet.
 * So, initialize on demand. */
int __libcrunch_global_init(void)
{
	if (__libcrunch_is_initialized) return 0; // we are okay

	// don't try more than once to initialize
	static _Bool tried_to_initialize;
	if (tried_to_initialize) return -1;
	tried_to_initialize = 1;
	
	page_size = (uintptr_t) sysconf(_SC_PAGE_SIZE);
	log_page_size = integer_log2(page_size);
	page_mask = ~((uintptr_t) sysconf(_SC_PAGE_SIZE) - 1);
	
	// print a summary when the program exits
	atexit(print_exit_summary);
	
	// delay start-up here if the user asked for it
	if (getenv("LIBCRUNCH_DELAY_STARTUP"))
	{
		sleep(10);
	}

	// the user can specify where we get our -types.so and -allocsites.so
	allocsites_base = getenv("ALLOCSITES_BASE");
	if (!allocsites_base) allocsites_base = "/usr/lib/allocsites";
	allocsites_base_len = strlen(allocsites_base);
	
	const char *debug_level_str = getenv("LIBCRUNCH_DEBUG_LEVEL");
	if (debug_level_str) __libcrunch_debug_level = atoi(debug_level_str);

	/* We always include "signed char" in the lazy heap types (FIXME: this is a 
	 * C-specificity we'd rather not have here, but live with it for now.) 
	 * We count the other ones. */
	const char *lazy_heap_types_str = getenv("LIBCRUNCH_LAZY_HEAP_TYPES");
	unsigned upper_bound = 2; // signed char plus one string with zero spaces
	if (lazy_heap_types_str)
	{
		/* Count the lazy heap types */
		const char *pos = lazy_heap_types_str;
		while ((pos = strrchr(pos, ' ')) != NULL) { ++upper_bound; ++pos; }
	}
	/* Allocate and populate. */
	lazy_heap_typenames = calloc(upper_bound, sizeof (const char *));
	lazy_heap_types = calloc(upper_bound, sizeof (struct uniqtype *));

	// the first entry is always signed char
	lazy_heap_typenames[0] = "signed char";
	lazy_heap_types_count = 1;
	if (lazy_heap_types_str)
	{
		const char *pos = lazy_heap_types_str;
		const char *spacepos;
		do 
		{
			spacepos = strchrnul(pos, ' ');
			if (spacepos - pos > 0) 
			{
				assert(lazy_heap_types_count < upper_bound);
				lazy_heap_typenames[lazy_heap_types_count++] = strndup(pos, spacepos - pos);
			}

			pos = spacepos;
			while (*pos == ' ') ++pos;
		} while (*pos != '\0');
	}
	
	// grab the executable's end address
	dlerror();
	void *executable_handle = dlopen(NULL, RTLD_NOW | RTLD_NOLOAD);
	assert(executable_handle != NULL);
	__addrmap_executable_end_addr = dlsym(executable_handle, "_end");
	assert(__addrmap_executable_end_addr != 0);
	
	/* We have to scan for lazy heap types *in link order*, so that we see
	 * the first linked definition of any type that is multiply-defined.
	 * Do a scan now; we also scan when loading a types object, and when loading
	 * a user-dlopen()'d object. 
	 * 
	 * We don't use dl_iterate_phdr because it doesn't give us the link_map * itself. 
	 * Instead, walk the link map directly, like a debugger would
	 *                                           (like I always knew somebody should). */
	void *exec_dynamic = ((struct link_map *) executable_handle)->l_ld;
	assert(exec_dynamic != NULL);
	ElfW(Dyn) *dt_debug = get_dynamic_entry_from_section(exec_dynamic, DT_DEBUG);
	struct r_debug *r_debug = (struct r_debug *) dt_debug->d_un.d_ptr;
	for (struct link_map *l = r_debug->r_map; l; l = l->l_next)
	{
		__libcrunch_scan_lazy_typenames(l);
	}
	
	int ret_types = dl_iterate_phdr(load_types_cb, NULL);
	assert(ret_types == 0);
	
#ifndef NO_MEMTABLE
	/* Allocate the memtable. 
	 * Assume we don't need to cover addresses >= STACK_BEGIN.
	 * BUT we store vaddrs in the same table, with addresses ORed
	 * with STACK_BEGIN. 
	 * And we store static objects' addres in the same table, with addresses ORed
	 * with STACK_BEGIN<<1. 
	 * So quadruple up the size of the table accordingly. */
	__libcrunch_allocsmt = MEMTABLE_NEW_WITH_TYPE(allocsmt_entry_type, allocsmt_entry_coverage, 
		(void*) 0, (void*) (STACK_BEGIN << 2));
	assert(__libcrunch_allocsmt != MAP_FAILED);
	
	int ret_allocsites = dl_iterate_phdr(load_and_init_allocsites_cb, NULL);
	assert(ret_allocsites == 0);

	int ret_stackaddr = dl_iterate_phdr(link_stackaddr_and_static_allocs_cb, NULL);
	assert(ret_stackaddr == 0);
#endif
	// grab the maximum stack size
	struct rlimit rlim;
	int rlret = getrlimit(RLIMIT_STACK, &rlim);
	if (rlret == 0)
	{
		__addrmap_max_stack_size = rlim.rlim_cur;
	}
	
	// grab the start of main's stack frame -- we'll use this 
	// when walking the stack
	unw_cursor_t cursor;
	unw_context_t unw_context;
	int ret = unw_getcontext(&unw_context); assert(ret == 0);
	ret = unw_init_local(&cursor, &unw_context); assert(ret == 0);
	char buf[8];
	unw_word_t ip;
	unw_word_t sp;
	unw_word_t bp;
	_Bool have_bp;
	_Bool have_name;
	assert(ret == 0);
	do
	{
		// get bp, sp, ip and proc_name
		ret = unw_get_proc_name(&cursor, buf, sizeof buf, NULL); have_name = (ret == 0 || ret == -UNW_ENOMEM);
		buf[sizeof buf - 1] = '\0';
		// if (have_name) fprintf(stderr, "Saw frame %s\n", buf);

		ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(ret == 0);
		ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(ret == 0);
		ret = unw_get_reg(&cursor, UNW_TDEP_BP, &bp); have_bp = (ret == 0);
	} while ((!have_name || 0 != strcmp(buf, "main")) && 
		(ret = unw_step(&cursor)) > 0);

	// have we found main?
	if (have_name && 0 == strcmp(buf, "main"))
	{
		// did we get its bp?
		if (!have_bp)
		{
			// try stepping once more
			ret = unw_step(&cursor);
			if (ret == 0)
			{
				ret = unw_get_reg(&cursor, UNW_REG_SP, &bp);
			}

			if (ret == 0) have_bp = 1;
		}

		if (have_bp)
		{
			main_bp = (void*) (intptr_t) bp;
		}
		else
		{
			// underapproximate bp as the sp
			main_bp = (void*) (intptr_t) sp;
		}
	}
	
	if (main_bp == 0) 
	{
		// underapproximate bp as our current sp!
		debug_printf(1, "Warning: using egregious approximation for bp of main().\n");
		unw_word_t our_sp;
	#ifdef UNW_TARGET_X86
		__asm__ ("movl %%esp, %0\n" :"=r"(our_sp));
	#else // assume X86_64 for now
		__asm__("movq %%rsp, %0\n" : "=r"(our_sp));
	#endif
		main_bp = (void*) (intptr_t) our_sp;
	}
	assert(main_bp != 0);
	
	// also init the prefix tree
	init_prefix_tree_from_maps();

	__libcrunch_is_initialized = 1;

	debug_printf(1, "libcrunch successfully initialized\n");
	
	return 0;
}

static void *typeobj_handle_for_addr(void *caller)
{
	// find out what object the caller is in
	Dl_info info;
	dlerror();
	int dladdr_ret = dladdr(caller, &info);
	assert(dladdr_ret != 0);
	
	// dlopen the typeobj
	const char *types_libname = helper_libfile_name(dynobj_name_from_dlpi_name(info.dli_fname, info.dli_fbase), "-types.so");
	assert(types_libname != NULL);
	return dlopen(types_libname, RTLD_NOW | RTLD_NOLOAD);
}

void *__libcrunch_my_typeobj(void)
{
	__libcrunch_ensure_init();
	return typeobj_handle_for_addr(__builtin_return_address(0));
}

/* FIXME: hook dlopen and dlclose so that we can load/unload allocsites and types
 * as execution proceeds. */


/* This is left out-of-line because it's inherently a slow path. */
const void *__libcrunch_typestr_to_uniqtype(const char *typestr)
{
	if (!typestr) return NULL;
	
	/* Note that the client always gives us a header-based typestr to look up. 
	 * We erase the header part and walk symbols in the -types.so to look for 
	 * a unique match. FIXME: this requires us to define aliases in unique cases! 
	 * in types.so, so dumptypes has to do this. */
	static const char prefix[] = "__uniqtype_";
	static const int prefix_len = (sizeof prefix) - 1;
	assert(0 == strncmp(typestr, "__uniqtype_", prefix_len));
	int header_name_len;
	int nmatched = sscanf(typestr, "__uniqtype_%d", &header_name_len);
	char typestr_to_use[4096];
	if (nmatched == 1)
	{
		// assert sanity
		assert(header_name_len > 0 && header_name_len < 4096);
		// read the remainder
		typestr_to_use[0] = '\0';
		strcat(typestr_to_use, "__uniqtype_");
		strncat(typestr_to_use, typestr + prefix_len + header_name_len, 4096 - prefix_len);
		typestr = typestr_to_use;
	} // else assume it's already how we like it
	
	dlerror();
	// void *returned = dlsym(RTLD_DEFAULT, typestr);
	// void *caller = __builtin_return_address(1);
	// RTLD_GLOBAL means that we don't need to get the handle
	// void *returned = dlsym(typeobj_handle_for_addr(caller), typestr);
	return typestr_to_uniqtype_from_lib(RTLD_NEXT, typestr);
}	
static const void *typestr_to_uniqtype_from_lib(void *handle, const char *typestr)
{
	void *returned = dlsym(RTLD_DEFAULT, typestr);
	if (!returned) return NULL;

	return (struct uniqtype *) returned;
}

static inline 
_Bool 
(__attribute__((always_inline,gnu_inline)) get_alloc_info) (const void *obj, 
	const void *test_uniqtype, 
	const char **out_reason,
	const void **out_reason_ptr,
	memory_kind *out_memory_kind,
	const void **out_object_start,
	unsigned *out_block_element_count,
	struct uniqtype **out_alloc_uniqtype, 
	const void **out_alloc_site,
	signed *out_target_offset_within_uniqtype)
{
	int modulo; 
	signed target_offset_wholeblock;
	signed target_offset_within_uniqtype;

	memory_kind k = get_object_memory_kind(obj);
	if (__builtin_expect(k == UNKNOWN, 0))
	{
		k = prefix_tree_get_memory_kind(obj);
		if (__builtin_expect(k == UNKNOWN, 0))
		{
			// still unknown? we have one last trick, if not blacklisted
			_Bool blacklisted = check_blacklist(obj);
			if (!blacklisted)
			{
				prefix_tree_add_missing_maps();
				k = prefix_tree_get_memory_kind(obj);
				if (k == UNKNOWN)
				{
					prefix_tree_print_all_to_stderr();
					// completely wild pointer or kernel pointer
					debug_printf(1, "libcrunch saw wild pointer %p from caller %p\n", obj,
						__builtin_return_address(0));
					consider_blacklisting(obj);
				}
			}
		}
	}
	*out_alloc_site = 0; // will likely get updated later
	*out_memory_kind = k;
	switch(k)
	{
		case STACK:
		{
			++__libcrunch_hit_stack_case;
#define BEGINNING_OF_STACK (STACK_BEGIN - 1)
			// we want to walk a sequence of vaddrs!
			// how do we know which is the one we want?
			// we can get a uniqtype for each one, including maximum posoff and negoff
			// -- yes, use those
			// begin pasted-then-edited from stack.cpp in pmirror
			/* We declare all our variables up front, in the hope that we can rely on
			 * the stack pointer not moving between getcontext and the sanity check.
			 * FIXME: better would be to write this function in C90 and compile with
			 * special flags. */
			unw_cursor_t cursor, saved_cursor, prev_saved_cursor;
			unw_word_t higherframe_sp = 0, sp, bp = 0, ip = 0, higherframe_ip = 0, callee_ip;
			int unw_ret;
			unw_context_t unw_context;

#ifndef NDEBUG
			unw_word_t check_higherframe_sp;
			// sanity check
#ifdef UNW_TARGET_X86
			__asm__ ("movl %%esp, %0\n" :"=r"(check_higherframe_sp));
#else // assume X86_64 for now
			__asm__("movq %%rsp, %0\n" : "=r"(check_higherframe_sp));
#endif
#endif
			unw_ret = unw_getcontext(&unw_context);
			unw_init_local(&cursor, /*this->unw_as,*/ &unw_context);

			unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp);
// redundant #ifdef, but for clarity
#ifndef NDEBUG 
			assert(check_higherframe_sp == higherframe_sp);
#endif
			unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip);

			int step_ret;
			_Bool at_or_above_main = 0;
			do
			{
				callee_ip = ip;
				prev_saved_cursor = saved_cursor;	// prev_saved_cursor is the cursor into the callee's frame 
													// FIXME: will be garbage if callee_ip == 0
				saved_cursor = cursor; // saved_cursor is the *current* frame's cursor
					// and cursor, later, becomes the *next* (i.e. caller) frame's cursor

				/* First get the ip, sp and symname of the current stack frame. */
				unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
				unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0); // sp = higherframe_sp
				// try to get the bp, but no problem if we don't
				unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &bp); 
				_Bool got_bp = (unw_ret == 0);
				/* Also do a test about whether we're in main, above which we want to
				 * tolerate unwind failures more gracefully.
				 */
				char proc_name_buf[100];
				unw_word_t byte_offset_from_proc_start;
				at_or_above_main |= 
					(
						(got_bp && bp >= (intptr_t) main_bp)
					 || (sp >= (intptr_t) main_bp) // NOTE: this misses the in-main case
					);

				/* Now get the sp of the next higher stack frame, 
				 * i.e. the bp of the current frame. NOTE: we're still
				 * processing the stack frame ending at sp, but we
				 * hoist the unw_step call to here so that we can get
				 * the *bp* of the current frame a.k.a. the caller's bp 
				 * (without demanding that libunwind provides bp, e.g. 
				 * for code compiled with -fomit-frame-pointer). 
				 * This means "cursor" is no longer current -- use 
				 * saved_cursor for the remainder of this iteration!
				 * saved_cursor points to the deeper stack frame. */
				int step_ret = unw_step(&cursor);
				if (step_ret > 0)
				{
					unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp); assert(unw_ret == 0);
					// assert that for non-top-end frames, BP --> saved-SP relation holds
					// FIXME: hard-codes calling convention info
					if (got_bp && !at_or_above_main && higherframe_sp != bp + 2 * sizeof (void*))
					{
						// debug_printf(2, "Saw frame boundary with unusual sp/bp relation (higherframe_sp=%p, bp=%p != higherframe_sp + 2*sizeof(void*))", 
						// 	higherframe_sp, bp);
					}
					unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip); assert(unw_ret == 0);
				}
				/* NOTE that -UNW_EBADREG happens near the top of the stack where 
				 * unwind info gets patchy, so we should handle it mostly like the 
				 * BEGINNING_OF_STACK case if so... but only if we're at or above main
				 * (and anyway, we *should* have that unwind info, damnit!).
				 */
				else if (step_ret == 0 || (at_or_above_main && step_ret == -UNW_EBADREG))
				{
					higherframe_sp = BEGINNING_OF_STACK;
					higherframe_ip = 0x0;
				}
				else
				{
					// return value <1 means error

					*out_reason = "stack walk step failure";
					goto abort_stack;
					break;
				}
				
				// useful variables at this point: sp, ip, got_bp && bp, 
				// higherframe_sp, higherframe_ip, 
				// callee_ip

				// now do the stuff
				// 1. get the frame uniqtype for frame_ip
				/* NOTE: here we are doing one vaddr_to_uniqtype per frame.
				 * Can we optimise this, by ruling out some frames just by
				 * their bounding sps? YES, I'm sure we can. FIXME: do this!
				 * The difficulty is in the fact that frame offsets can be
				 * negative, i.e. arguments exist somewhere in the parent
				 * frame. */
				struct uniqtype *frame_desc = vaddr_to_uniqtype((void *) ip);
				if (!frame_desc)
				{
					// no frame descriptor for this frame; that's okay!
					// e.g. our libcrunch frames should (normally) have no descriptor
					continue;
				}
				// 2. what's the frame base? it's the higherframe stack pointer
				unsigned char *frame_base = (unsigned char *) higherframe_sp;
				// 3. is our candidate addr between frame-base - negoff and frame_base + posoff?
				if ((unsigned char *) obj >= frame_base - frame_desc->neg_maxoff  // is unsigned, so subtract
					&& (unsigned char *) obj < frame_base + frame_desc->pos_maxoff)
				{
					*out_object_start = frame_base;
					*out_alloc_uniqtype = frame_desc;
					*out_alloc_site = (void*)(intptr_t) ip; // HMM -- is this the best way to represent this?
					goto out_success;
				}
				else
				{
					// have we gone too far? we are going upwards in memory...
					// ... so if our lowest addr is still too high
					if (frame_base - frame_desc->neg_maxoff > (unsigned char *) obj)
					{
						*out_reason = "stack walk reached higher frame";
						goto abort_stack;
					}
				}

				assert(step_ret > 0 || higherframe_sp == BEGINNING_OF_STACK);
			} while (higherframe_sp != BEGINNING_OF_STACK);
			// if we hit the termination condition, we've failed
			if (higherframe_sp == BEGINNING_OF_STACK)
			{
				*out_reason = "stack walk reached top-of-stack";
				goto abort_stack;
			}
		#undef BEGINNING_OF_STACK
		// end pasted from pmirror stack.cpp
		break; // end case STACK
		abort_stack:
			if (!*out_reason) *out_reason = "stack object";
			*out_reason_ptr = obj;
			++__libcrunch_aborted_stack;
			return 1;
		} // end case STACK
		case HEAP:
		{
			++__libcrunch_hit_heap_case;
			/* For heap allocations, we look up the allocation site.
			 * (This also yields an offset within a toplevel object.)
			 * Then we translate the allocation site to a uniqtypes rec location.
			 * (For direct calls in eagerly-loaded code, we can cache this information
			 * within uniqtypes itself. How? Make uniqtypes include a hash table with
			 * initial contents mapping allocsites to uniqtype recs. This hash table
			 * is initialized during load, but can be extended as new allocsites
			 * are discovered, e.g. indirect ones.)
			 */
			struct deep_entry *deep = NULL;
			struct insert *heap_info = lookup_object_info(obj, (void**) out_object_start, &deep);
			if (!heap_info)
			{
				*out_reason = "unindexed heap object";
				*out_reason_ptr = obj;
				++__libcrunch_aborted_unindexed_heap;
				return 1;
			}
			assert(get_object_memory_kind(heap_info) == HEAP
				|| get_object_memory_kind(heap_info) == UNKNOWN); // might not have seen that maps yet
			assert(prefix_tree_get_memory_kind((void*)(uintptr_t) heap_info->alloc_site) == STATIC);

			unsigned alloc_chunksize;
			if (deep) 
			{
				alloc_chunksize = deep->size_4bytes << 2;
			} else alloc_chunksize = malloc_usable_size((void*) *out_object_start);
			
			/* Now we have a uniqtype or an allocsite. For long-lived objects 
			 * the uniqtype will have been installed in the heap header already.
			 */
			if (__builtin_expect(heap_info->alloc_site_flag, 1))
			{
				*out_alloc_site = NULL;
				*out_alloc_uniqtype = (void*)(uintptr_t)heap_info->alloc_site;
			}
			else
			{
				/* Look up the allocsite's uniqtype, and install it in the heap info 
				 * (on NDEBUG builds only, because it reduces debuggability a bit).
				 * 
				 * AND UNLESS it's a lazy uniqtype, in which case the target type of the 
				 * cast we're checking is the one we assign to the . */
				void *alloc_site = (void*)(uintptr_t)heap_info->alloc_site;
				*out_alloc_site = alloc_site;
				struct uniqtype *alloc_uniqtype = allocsite_to_uniqtype(alloc_site/*, heap_info*/);
				*out_alloc_uniqtype = alloc_uniqtype;
				if (!alloc_uniqtype) 
				{
					*out_reason = "unrecognised allocsite";
					*out_reason_ptr = alloc_site;
					++__libcrunch_aborted_unrecognised_allocsite;
					return 1;
				}
				if (__builtin_expect(is_lazy_uniqtype(alloc_uniqtype), 0))
				{
					++__libcrunch_lazy_heap_type_assignment;
					heap_info->alloc_site_flag = 1;
					heap_info->alloc_site = (uintptr_t) test_uniqtype;
					*out_alloc_site = 0;
					*out_alloc_uniqtype = (struct uniqtype *) test_uniqtype;
					goto out_success; // FIXME: we'd rather return from __is_a early right here
				}
				
#ifdef NDEBUG
				// FIXME: make this atomic using a union
				heap_info->alloc_site_flag = 1;
				heap_info->alloc_site = (uintptr_t) *out_alloc_uniqtype;
#endif
			}

			/* FIXME: scrounge in-heap header bits for next/prev and allocsite as follows:
			 *    on 32-bit x86, exploit that code is not loaded in top half of AS;
			 *    on 64-bit x86, exploit that certain bits of an addr are always 0. 
			 */
			 
			unsigned header_size = sizeof (struct insert);
			*out_block_element_count = (alloc_chunksize - header_size) / (*out_alloc_uniqtype)->pos_maxoff;
			//__libcrunch_private_assert(chunk_size % alloc_uniqtype->pos_maxoff == 0,
			//	"chunk size should be multiple of element size", __FILE__, __LINE__, __func__);
			break;
		}
		case STATIC:
		{
			++__libcrunch_hit_static_case;
//			/* We use a blacklist to rule out static addrs that map to things like 
//			 * mmap()'d regions (which we never have typeinfo for)
//			 * or uninstrumented libraries (which we happen not to have typeinfo for). */
//			_Bool blacklisted = check_blacklist(obj);
//			if (blacklisted)
//			{
//				// FIXME: record blacklist hits separately
//				reason = "unrecognised static object";
//				reason_ptr = obj;
//				++__libcrunch_aborted_static;
//				goto abort;
//			}
			*out_alloc_uniqtype = static_addr_to_uniqtype(obj, (void**) out_object_start);
			if (!*out_alloc_uniqtype)
			{
				*out_reason = "unrecognised static object";
				*out_reason_ptr = obj;
				++__libcrunch_aborted_static;
//				consider_blacklisting(obj);
				return 1;
			}
			// else we can go ahead
			*out_alloc_site = *out_object_start;
			break;
		}
		case UNKNOWN:
		case MAPPED_FILE:
		default:
		{
			*out_reason = "object of unknown storage";
			*out_reason_ptr = obj;
			++__libcrunch_aborted_unknown_storage;
			return 1;
		}
	}
	
out_success:
	target_offset_wholeblock = (char*) obj - (char*) *out_object_start;
	/* If we're searching in an array, we need to take the offset modulo the 
	 * element size. Otherwise just take the whole-block offset. */
	if ((*out_alloc_uniqtype)->pos_maxoff != 0 && (*out_alloc_uniqtype)->neg_maxoff == 0)
	{
		target_offset_within_uniqtype = target_offset_wholeblock % (*out_alloc_uniqtype)->pos_maxoff;
	} else target_offset_within_uniqtype = target_offset_wholeblock;
	// assert that the signs are the same
	assert(target_offset_wholeblock < 0 
		? target_offset_within_uniqtype < 0 
		: target_offset_within_uniqtype >= 0);
	*out_target_offset_within_uniqtype = target_offset_within_uniqtype;
	
	return 0;
}

static inline _Bool descend_to_first_subobject_spanning(
	signed *p_target_offset_within_uniqtype,
	struct uniqtype **p_cur_obj_uniqtype,
	struct uniqtype **p_cur_containing_uniqtype,
	struct contained **p_cur_contained_pos)
{
	struct uniqtype *cur_obj_uniqtype = *p_cur_obj_uniqtype;
	signed target_offset_within_uniqtype = *p_target_offset_within_uniqtype;
	/* Calculate the offset to descend to, if any. This is different for 
	 * structs versus arrays. */
	if (cur_obj_uniqtype->is_array)
	{
		unsigned num_contained = cur_obj_uniqtype->array_len;
		struct uniqtype *element_uniqtype = cur_obj_uniqtype->contained[0].ptr;
		unsigned target_element_index
		 = target_offset_within_uniqtype / element_uniqtype->pos_maxoff;
		if (num_contained > target_element_index)
		{
			*p_cur_containing_uniqtype = cur_obj_uniqtype;
			*p_cur_contained_pos = &cur_obj_uniqtype->contained[0];
			*p_cur_obj_uniqtype = element_uniqtype;
			*p_target_offset_within_uniqtype = target_offset_within_uniqtype % element_uniqtype->pos_maxoff;
			return 1;
		} else return 0;
	}
	else // struct/union case
	{
		unsigned num_contained = cur_obj_uniqtype->nmemb;

		int lower_ind = 0;
		int upper_ind = num_contained;
		while (lower_ind + 1 < upper_ind) // difference of >= 2
		{
			/* Bisect the interval */
			int bisect_ind = (upper_ind + lower_ind) / 2;
			__libcrunch_private_assert(bisect_ind > lower_ind, "bisection progress", 
				__FILE__, __LINE__, __func__);
			if (cur_obj_uniqtype->contained[bisect_ind].offset > target_offset_within_uniqtype)
			{
				/* Our solution lies in the lower half of the interval */
				upper_ind = bisect_ind;
			} else lower_ind = bisect_ind;
		}

		if (lower_ind + 1 == upper_ind)
		{
			/* We found one offset */
			__libcrunch_private_assert(cur_obj_uniqtype->contained[lower_ind].offset <= target_offset_within_uniqtype,
				"offset underapproximates", __FILE__, __LINE__, __func__);

			/* ... but we might not have found the *lowest* index, in the 
			 * case of a union. Scan backwards so that we have the lowest. 
			 * FIXME: need to account for the element size? Or here are we
			 * ignoring padding anyway? */
			while (lower_ind > 0 
				&& cur_obj_uniqtype->contained[lower_ind-1].offset
					 == cur_obj_uniqtype->contained[lower_ind].offset)
			{
				--lower_ind;
			}
			*p_cur_contained_pos = &cur_obj_uniqtype->contained[lower_ind];
			*p_cur_containing_uniqtype = cur_obj_uniqtype;
			*p_cur_obj_uniqtype
			 = cur_obj_uniqtype->contained[lower_ind].ptr;
			/* p_cur_obj_uniqtype now points to the subobject's uniqtype. 
			 * We still have to adjust the offset. */
			*p_target_offset_within_uniqtype
			 = target_offset_within_uniqtype - cur_obj_uniqtype->contained[lower_ind].offset;

			return 1;
		}
		else /* lower_ind >= upper_ind */
		{
			// this should mean num_contained == 0
			__libcrunch_private_assert(num_contained == 0,
				"no contained objects", __FILE__, __LINE__, __func__);
			return 0;
		}
	}
}

static inline _Bool recursively_test_subobjects(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype)
{
	if (target_offset_within_uniqtype == 0 && cur_obj_uniqtype == test_uniqtype) return 1;
	else
	{
		/* We might have *multiple* subobjects spanning the offset. 
		 * Test all of them. */
		struct uniqtype *containing_uniqtype = NULL;
		struct contained *contained_pos = NULL;
		
		signed sub_target_offset = target_offset_within_uniqtype;
		struct uniqtype *contained_uniqtype = cur_obj_uniqtype;
		
		_Bool success = descend_to_first_subobject_spanning(
			&sub_target_offset, &contained_uniqtype,
			&containing_uniqtype, &contained_pos);
		// now we have a *new* sub_target_offset and contained_uniqtype
		
		if (!success) return 0;
		do {
			assert(containing_uniqtype == cur_obj_uniqtype);
			_Bool recursive_test = recursively_test_subobjects(
					sub_target_offset,
					contained_uniqtype, test_uniqtype);
			if (__builtin_expect(recursive_test, 1)) return 1;
			// else look for a later contained subobject at the same offset
			unsigned subobj_ind = contained_pos - &containing_uniqtype->contained[0];
			assert(subobj_ind >= 0);
			assert(subobj_ind == 0 || subobj_ind < containing_uniqtype->nmemb);
			if (__builtin_expect(
					containing_uniqtype->nmemb <= subobj_ind + 1
					|| containing_uniqtype->contained[subobj_ind + 1].offset != 
						containing_uniqtype->contained[subobj_ind].offset,
				1))
			{
				// no more subobjects at the same offset, so fail
				return 0;
			} 
			else
			{
				contained_pos = &containing_uniqtype->contained[subobj_ind + 1];
				contained_uniqtype = contained_pos->ptr;
			}
		} while (1);
		
		assert(0);
	}
}

/* Optimised version, for when you already know the uniqtype address. */
int __is_a_internal(const void *obj, const void *arg)
{
	/* We might not be initialized yet (recall that __libcrunch_global_init is 
	 * not a constructor, because it's not safe to call super-early). */
	__libcrunch_check_init();
	
	const struct uniqtype *test_uniqtype = (const struct uniqtype *) arg;
	const char *reason = NULL; // if we abort, set this to a string lit
	const void *reason_ptr = NULL; // if we abort, set this to a useful address
	memory_kind k;
	const void *object_start;
	unsigned block_element_count = 1;
	struct uniqtype *alloc_uniqtype = (struct uniqtype *)0;
	const void *alloc_site;
	signed target_offset_within_uniqtype;
	
	_Bool abort = get_alloc_info(obj, 
		arg, 
		&reason,
		&reason_ptr,
		&k,
		&object_start,
		&block_element_count,
		&alloc_uniqtype,
		&alloc_site,
		&target_offset_within_uniqtype);
	
	if (__builtin_expect(abort, 0)) return 1; // we've already counted it
	
	struct uniqtype *cur_obj_uniqtype = alloc_uniqtype;
	struct uniqtype *cur_containing_uniqtype = NULL;
	struct contained *cur_contained_pos = NULL;
// 	do
// 	{
// 		/* If we have offset == 0, we can check at this uniqtype.
// 		 * We also pass if our current object is an array of the test uniqtype
// 		 * and the offset is a multiple of the array element size. 
// 		 * FIXME: we don't check the bounds of the array, but I think we 
// 		 * don't have to. */
// 		if (target_offset_within_uniqtype == 0
// 					&& cur_obj_uniqtype == test_uniqtype) 
// 		{
// 			++__libcrunch_succeeded;
// 			return 1;
// 		}
// 	} while (descend_to_first_subobject_spanning(&target_offset_within_uniqtype, &cur_obj_uniqtype,
// 			&cur_containing_uniqtype, &cur_contained_pos));
	_Bool success = recursively_test_subobjects(target_offset_within_uniqtype, 
			cur_obj_uniqtype, test_uniqtype);
	if (__builtin_expect(success, 1))
	{
			++__libcrunch_succeeded;
			return 1;
	}
	
	// if we got here, the check failed
	if (__current_allocsite || __currently_freeing)
	{
		++__libcrunch_failed_in_alloc;
		// suppress warning
	}
	else
	{
		++__libcrunch_failed;
		
		static const void *last_failed_site;
		static const void *last_failed_object;
		static const struct uniqtype *last_failed_test_type;
		
		if (last_failed_site == __builtin_return_address(0)
				&& last_failed_object == obj
				&& last_failed_test_type == test_uniqtype
				&& last_suppressed_check_kind == IS_A)
		{
			++suppression_count;
		}
		else
		{
			if (suppression_count > 0)
			{
			debug_printf(0, "Suppressed %d further occurrences of the previous error\n", 
					suppression_count);
			}
			
			debug_printf(0, "Failed check __is_a_internal(%p, %p a.k.a. \"%s\") at %p, "
					"%d bytes into an allocation of a %s%s%s "
					"(deepest subobject: %s at offset %d) "
					"originating at %p\n", 
				obj, test_uniqtype, test_uniqtype->name,
				__builtin_return_address(0), // make sure our *caller*, if any, is inlined
				(char*) obj - (char*) object_start,
				name_for_memory_kind(k), (k == HEAP && block_element_count > 1) ? " block of " : " ", 
				alloc_uniqtype ? (alloc_uniqtype->name ?: "(unnamed type)") : "(unknown type)", 
				(cur_obj_uniqtype ? cur_obj_uniqtype->name : "(none)"), target_offset_within_uniqtype, 
				alloc_site);
			last_failed_site = __builtin_return_address(0);
			last_failed_object = obj;
			last_failed_test_type = test_uniqtype;
			suppression_count = 0;
		}
	}
	return 1; // HACK: so that the program will continue
}

/* Optimised version, for when you already know the uniqtype address. */
int __like_a_internal(const void *obj, const void *arg)
{
	// FIXME: use our recursive subobject search here? HMM -- semantics are non-obvious.
	
	/* We might not be initialized yet (recall that __libcrunch_global_init is 
	 * not a constructor, because it's not safe to call super-early). */
	__libcrunch_check_init();
	
	const struct uniqtype *test_uniqtype = (const struct uniqtype *) arg;
	const char *reason = NULL; // if we abort, set this to a string lit
	const void *reason_ptr = NULL; // if we abort, set this to a useful address
	memory_kind k;
	const void *object_start;
	unsigned block_element_count = 1;
	struct uniqtype *alloc_uniqtype = (struct uniqtype *)0;
	const void *alloc_site;
	signed target_offset_within_uniqtype;
	void *caller_address = __builtin_return_address(0);
	
	_Bool abort = get_alloc_info(obj, 
		arg, 
		&reason,
		&reason_ptr,
		&k,
		&object_start,
		&block_element_count,
		&alloc_uniqtype, 
		&alloc_site,
		&target_offset_within_uniqtype);
	
	if (__builtin_expect(abort, 0)) return 1; // we've already counted it
	struct uniqtype *cur_obj_uniqtype = alloc_uniqtype;
	struct uniqtype *cur_containing_uniqtype = NULL;
	struct contained *cur_contained_pos = NULL;
	
	/* Descend the subobject hierarchy until our target offset is zero, i.e. we 
	 * find the outermost thing in the subobject tree that starts at the address
	 * we were passed (obj). */
	while (target_offset_within_uniqtype != 0)
	{
		_Bool success = descend_to_first_subobject_spanning(
				&target_offset_within_uniqtype, &cur_obj_uniqtype, &cur_containing_uniqtype,
				&cur_contained_pos);
		if (!success) goto like_a_failed;
	}
	
	// trivially, identical types are like one another
	if (test_uniqtype == cur_obj_uniqtype) goto like_a_succeeded;
	
	// arrays are special
	_Bool matches;
	if (__builtin_expect((cur_obj_uniqtype->is_array || test_uniqtype->is_array), 0))
	{
		matches = 
			test_uniqtype == cur_obj_uniqtype
		||  (test_uniqtype->is_array && test_uniqtype->array_len == 1 
				&& test_uniqtype->contained[0].ptr == cur_obj_uniqtype)
		||  (cur_obj_uniqtype->is_array && cur_obj_uniqtype->array_len == 1
				&& cur_obj_uniqtype->contained[0].ptr == test_uniqtype);
		/* We don't need to allow an array of one blah to be like a different
		 * array of one blah, because they should be the same type. 
		 * FIXME: there's a difficult case: an array of statically unknown length, 
		 * which happens to have length 1. */
		if (matches) goto like_a_succeeded; else goto like_a_failed;
	}
	
	/* Okay, we can start the like-a test: for each element in the test type, 
	 * do we have a type-equivalent in the object type?
	 * 
	 * We make an exception for arrays of char (signed or unsigned): if an
	 * element in the test type is such an array, we skip over any number of
	 * fields in the object type, until we reach the offset of the end element.  */
	unsigned i_obj_subobj = 0, i_test_subobj = 0;
	for (; 
		i_obj_subobj < cur_obj_uniqtype->nmemb && i_test_subobj < test_uniqtype->nmemb; 
		++i_test_subobj, ++i_obj_subobj)
	{
		if (__builtin_expect(test_uniqtype->contained[i_test_subobj].ptr->is_array
			&& (test_uniqtype->contained[i_test_subobj].ptr->contained[0].ptr
					== LOOKUP_CALLER_TYPE(signed_char, caller_address)
			|| test_uniqtype->contained[i_test_subobj].ptr->contained[0].ptr
					== LOOKUP_CALLER_TYPE(unsigned_char, caller_address)), 0))
		{
			// we will skip this field in the test type
			signed target_off =
				test_uniqtype->nmemb > i_test_subobj + 1
			 ?  test_uniqtype->contained[i_test_subobj + 1].offset
			 :  test_uniqtype->contained[i_test_subobj].offset
			      + test_uniqtype->contained[i_test_subobj].ptr->pos_maxoff;
			
			// ... if there's more in the test type, advance i_obj_subobj
			while (i_obj_subobj + 1 < cur_obj_uniqtype->nmemb &&
				cur_obj_uniqtype->contained[i_obj_subobj + 1].offset < target_off) ++i_obj_subobj;
			/* We fail if we ran out of stuff in the target object type
			 * AND there is more to go in the test type. */
			if (i_obj_subobj + 1 >= cur_obj_uniqtype->nmemb
			 && test_uniqtype->nmemb > i_test_subobj + 1) goto like_a_failed;
				
			continue;
		}
		matches = 
				test_uniqtype->contained[i_test_subobj].offset == cur_obj_uniqtype->contained[i_obj_subobj].offset
		 && 	test_uniqtype->contained[i_test_subobj].ptr == cur_obj_uniqtype->contained[i_obj_subobj].ptr;
		if (!matches) goto like_a_failed;
	}
	// if we terminated because we ran out of fields in the target type, fail
	if (i_test_subobj < test_uniqtype->nmemb) goto like_a_failed;
	
like_a_succeeded:
	++__libcrunch_succeeded;
	return 1;
	
	// if we got here, we've failed
	// if we got here, the check failed
like_a_failed:
	if (__current_allocsite) 
	{
		++__libcrunch_failed_in_alloc;
		// suppress warning
	}
	else
	{
		++__libcrunch_failed;
		debug_printf(0, "Failed check __like_a_internal(%p, %p a.k.a. \"%s\") at %p, allocation was a %s%s%s originating at %p\n", 
			obj, test_uniqtype, test_uniqtype->name,
			__builtin_return_address(0), // make sure our *caller*, if any, is inlined
			name_for_memory_kind(k), (k == HEAP && block_element_count > 1) ? " block of " : " ", 
			alloc_uniqtype ? (alloc_uniqtype->name ?: "(unnamed type)") : "(unknown type)", 
			alloc_site);
	}
	return 1; // HACK: so that the program will continue
}
