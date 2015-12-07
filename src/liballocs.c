#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <link.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef USE_REAL_LIBUNWIND
#include <libunwind.h>
#endif
#include "relf.h"
#include "liballocs.h"
#include "liballocs_private.h"

/* Force a definition of this inline function to be emitted.
 * Debug builds use this, since they won't inline the call to it
 * from the wrapper function. */
int 
__liballocs_walk_subobjects_spanning_rec(
	signed accum_offset, unsigned accum_depth,
	const signed target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, signed span_start_offset, unsigned depth,
		struct uniqtype *containing, struct contained *contained_pos, void *arg),
	void *arg
	);

#ifndef USE_REAL_LIBUNWIND
#include "fake-libunwind.h"
int unw_get_proc_name(unw_cursor_t *p_cursor, char *buf, size_t n, unw_word_t *offp) __attribute__((visibility("hidden")));
int unw_get_proc_name(unw_cursor_t *p_cursor, char *buf, size_t n, unw_word_t *offp)
{
	assert(!offp);
	dlerror();
	Dl_info info = dladdr_with_cache((void*) p_cursor->frame_ip);
	if (!info.dli_fname) return 1;
	if (!info.dli_sname) return 2;
	else 
	{
		strncpy(buf, info.dli_sname, n);
		return 0;
	}
}
#endif

char exe_basename[4096] __attribute__((visibility("hidden")));
char exe_fullname[4096] __attribute__((visibility("hidden")));
FILE *stream_err __attribute__((visibility("hidden")));

struct addrlist __liballocs_unrecognised_heap_alloc_sites = { 0, 0, NULL };

static const char *allocsites_base;
static unsigned allocsites_base_len;

int __liballocs_debug_level;
_Bool __liballocs_is_initialized;
allocsmt_entry_type *__liballocs_allocsmt;

// these two are defined in addrmap.h as weak
void *__addrmap_executable_end_addr;
unsigned long __addrmap_max_stack_size;

// helper
static const void *typestr_to_uniqtype_from_lib(void *handle, const char *typestr);

// HACK
void __liballocs_preload_init(void);

struct liballocs_err
{
	const char *message;
};
struct liballocs_err __liballocs_err_stack_walk_step_failure 
 = { "stack walk reached higher frame" };
struct liballocs_err __liballocs_err_stack_walk_reached_higher_frame 
 = { "stack walk reached higher frame" };
struct liballocs_err __liballocs_err_stack_walk_reached_top_of_stack 
 = { "stack walk reached top-of-stack" };
struct liballocs_err __liballocs_err_unknown_stack_walk_problem 
 = { "unknown stack walk problem" };
struct liballocs_err __liballocs_err_unindexed_heap_object
 = { "unindexed heap object" };
struct liballocs_err __liballocs_err_unrecognised_alloc_site
 = { "unrecognised alloc site" };
struct liballocs_err __liballocs_err_unrecognised_static_object
 = { "unrecognised static object" };
struct liballocs_err __liballocs_err_object_of_unknown_storage
 = { "object of unknown storage" };

const char *__liballocs_errstring(struct liballocs_err *err)
{
	return err->message;
}

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

struct dl_for_one_phdr_cb_args
{
	struct link_map *link_map_to_match;
	int (*actual_callback) (struct dl_phdr_info *info, size_t size, void *data);
	void *actual_arg;
};

static int dl_for_one_phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct dl_for_one_phdr_cb_args *args = (struct dl_for_one_phdr_cb_args *) data;
	/* Only call the callback if the link map matches. */
	if (args->link_map_to_match->l_addr == info->dlpi_addr)
	{
		return args->actual_callback(info, size, args->actual_arg);
	} else return 0; // keep going
}

int dl_for_one_object_phdrs(void *handle,
	int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
	void *data)
{
	struct dl_for_one_phdr_cb_args args = {
		(struct link_map *) handle, 
		callback,
		data
	};
	dl_iterate_phdr(dl_for_one_phdr_cb, &args);
}


static int iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg);

static int print_type_cb(struct uniqtype *t, void *ignored)
{
	fprintf(stream_err, "uniqtype addr %p, name %s, size %d bytes\n", 
		t, t->name, t->pos_maxoff);
	fflush(stream_err);
	return 0;
}

int __liballocs_iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg) __attribute__((visibility("protected")));
int __liballocs_iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg)
{
	/* Don't use dladdr() to iterate -- too slow! Instead, iterate 
	 * directly over the dynsym section. */
	struct link_map *h = typelib_handle;
	unsigned char *load_addr = (unsigned char *) h->l_addr;
	
	/* If load address is greater than STACK_BEGIN, it's suspicious -- 
	 * perhaps a vdso-like thing. Skip it. The vdso itself is detected
	 * below (it lives in user memory, but points into kernel memory). */
	if (!load_addr || (uintptr_t) load_addr > STACK_BEGIN) return 0;
	
	/* We don't have to add load_addr, because ld.so has already done it. */
	ElfW(Dyn) *dynsym_ent = dynamic_lookup(h->l_ld, DT_SYMTAB);
	assert(dynsym_ent);
	ElfW(Sym) *dynsym = (ElfW(Sym) *) dynsym_ent->d_un.d_ptr;
	assert(dynsym);
	/* Catch the vdso case. */
	if (!dynsym || (uintptr_t) dynsym > STACK_BEGIN) return 0;
	
	ElfW(Dyn) *hash_ent = (ElfW(Dyn) *) dynamic_lookup(h->l_ld, DT_HASH);
	ElfW(Word) *hash = hash_ent ? (ElfW(Word) *) hash_ent->d_un.d_ptr : NULL;
	if ((intptr_t) dynsym < 0 || (intptr_t) hash < 0)
	{
		/* We've got a pointer to kernel memory, probably vdso. 
		 * On some kernels, the vdso mapping address is randomized
		 * but its contents are not fixed up appropriately. This 
		 * means that addresses read from the vdso can't be trusted
		 * and will probably segfault.
		 */
		debug_printf(2, "detected risk of buggy VDSO with unrelocated (kernel-address) content... skipping\n");
		return 0;
	}
	// check that we start with a null symtab entry
	static const ElfW(Sym) nullsym = { 0, 0, 0, 0, 0, 0 };
	assert(0 == memcmp(&nullsym, dynsym, sizeof nullsym));
	if ((dynsym && (char*) dynsym < MINIMUM_USER_ADDRESS) || (hash && (char*) hash < MINIMUM_USER_ADDRESS))
	{
		/* We've got a pointer to a very low address, probably from
		 * an unrelocated .dynamic section entry. This happens most
		 * often with the VDSO. The ld.so is supposed to relocate these
		 * addresses, but when VDSO handling changed in Linux
		 * (some time between 3.8.0 and 3.18.0) to use load-relative addresses
		 * instead of pre-relocated addresses, ld.so still hadn't caught on
		 * that it now needed to relocate these. 
		 */
		debug_printf(2, "detected likely-unrelocated (load-relative) .dynamic content... skipping\n");
		return 0;
	}
	// get the symtab size
	unsigned long nsyms = dynamic_symbol_count(h->l_ld);
	ElfW(Dyn) *dynstr_ent = dynamic_lookup(h->l_ld, DT_STRTAB);
	assert(dynstr_ent);
	char *dynstr = (char*) dynstr_ent->d_un.d_ptr;

	int cb_ret = 0;

	for (ElfW(Sym) *p_sym = dynsym; p_sym <  dynsym + nsyms; ++p_sym)
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
/* FIXME: invalidate cache entries on dlclose(). */
#ifndef DLADDR_CACHE_SIZE
#define DLADDR_CACHE_SIZE 16
#endif
Dl_info dladdr_with_cache(const void *addr); // __attribute__((visibility("protected")));
Dl_info dladdr_with_cache(const void *addr)
{
	struct cache_rec { const void *addr; Dl_info info; };
	
	static struct cache_rec cache[DLADDR_CACHE_SIZE];
	static unsigned next_free;
	
	for (unsigned i = 0; i < DLADDR_CACHE_SIZE; ++i)
	{
		if (cache[i].addr)
		{
			if (cache[i].addr == addr)
			{
				return cache[i].info;
			}
		}
	}
	
	Dl_info info;
	int ret = dladdr(addr, &info);
	assert(ret != 0);

	/* always cache the dladdr result */
	cache[next_free++] = (struct cache_rec) { addr, info };
	if (next_free == DLADDR_CACHE_SIZE)
	{
		debug_printf(5, "dladdr cache wrapped around\n");
		next_free = 0;
	}
	
	return info;
}

const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr)
{
	Dl_info info = dladdr_with_cache(addr);
	
	static __thread char buf[8192];
	
	snprintf(buf, sizeof buf, "%s`%s+%p", 
		info.dli_fname ? basename(info.dli_fname) : "unknown", 
		info.dli_sname ? info.dli_sname : "unknown", 
		info.dli_saddr
			? (void*)((char*) addr - (char*) info.dli_saddr)
			: NULL);
		
	buf[sizeof buf - 1] = '\0';
	
	return buf;
}


static _Bool done_init;
void __liballocs_main_init(void) __attribute__((constructor(101),visibility("protected")));
// NOTE: runs *before* the constructor in preload.c
void __liballocs_main_init(void)
{
	assert(!done_init);
	
	done_init = 1;
}

// FIXME: do better!
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg)
{
	static char buf[4096];
	return realpath(arg, &buf[0]);
}

const char *dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr) __attribute__((visibility("hidden")));
const char *dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr)
{
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
			assert(exe_fullname[0] != '\0');
			// use this filename now
			return exe_fullname;
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
			return realpath_quick(addr_info.dli_fname);
		}
	} 
	else
	{
		// we need to realpath() it
		return realpath_quick(dlpi_name);
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

// HACK
extern void __libcrunch_scan_lazy_typenames(void *handle) __attribute__((weak));

int load_types_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
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

	// fprintf(stream_err, "liballocs: trying to open %s\n", libfile_name);

	dlerror();
	// load with NOLOAD first, so that duplicate loads are harmless
	void *handle = (orig_dlopen ? orig_dlopen :dlopen)(libfile_name, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
	if (handle) return 0;
	
	dlerror();
	handle = (orig_dlopen ? orig_dlopen :dlopen)(libfile_name, RTLD_NOW | RTLD_GLOBAL);
	if (!handle)
	{
		debug_printf(1, "loading types object: %s\n", dlerror());
		return 0;
	}
	debug_printf(3, "loaded types object: %s\n", libfile_name);
	
	// if we want maximum output, print it
	if (__liballocs_debug_level >= 6)
	{
		__liballocs_iterate_types(handle, print_type_cb, NULL);
	}
	
	// HACK: scan it for lazy-heap-alloc types
	if (__libcrunch_scan_lazy_typenames) __libcrunch_scan_lazy_typenames(handle);

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
	/* fprintf(stream_err, "allocsite entry: %p, to uniqtype at %p\n", 
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

int load_and_init_allocsites_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
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

	// fprintf(stream_err, "liballocs: trying to open %s\n", libfile_name);
	// load with NOLOAD first, so that duplicate loads are harmless
	dlerror();
	void *allocsites_handle = (orig_dlopen ? orig_dlopen : dlopen)(libfile_name, RTLD_NOW | RTLD_NOLOAD);
	if (allocsites_handle) return 0;
	
	dlerror();
	allocsites_handle = (orig_dlopen ? orig_dlopen : dlopen)(libfile_name, RTLD_NOW);
	if (!allocsites_handle)
	{
		debug_printf(1, "loading allocsites object: %s\n", dlerror());
		return 0;
	}
	debug_printf(1, "loaded allocsites object: %s\n", libfile_name);
	
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

int link_stackaddr_and_static_allocs_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
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
	void *types_handle = (orig_dlopen ? orig_dlopen : dlopen)(libfile_name, RTLD_NOW | RTLD_NOLOAD);
	if (!types_handle)
	{
		debug_printf(1, "re-loading types object: %s\n", dlerror());
		return 0;
	}
	
	{
		dlerror();
		struct frame_allocsite_entry *first_frame_entry
		 = (struct frame_allocsite_entry *) dlsym(types_handle, "frame_vaddrs");
		if (!first_frame_entry)
		{
			debug_printf(1, "Could not load frame vaddrs (%s)", dlerror());
			return 0;
		}

		/* We chain these much like the allocsites, BUT we OR each vaddr with 
		 * STACK_BEGIN first.  */
		struct frame_allocsite_entry *cur_frame_ent = first_frame_entry;
		struct frame_allocsite_entry *prev_frame_ent = NULL;
		unsigned current_frame_bucket_size = 1; // out of curiosity...
		for (; cur_frame_ent->entry.allocsite; prev_frame_ent = cur_frame_ent++)
		{
			chain_allocsite_entries(cur_frame_ent ? &cur_frame_ent->entry : NULL, 
				prev_frame_ent ? &cur_frame_ent->entry : NULL, 
				&current_frame_bucket_size,
				info->dlpi_addr, STACK_BEGIN);
		}

		// debugging: check that we can look up the first entry, if we are non-empty
		assert(!first_frame_entry || !first_frame_entry->entry.allocsite || 
			vaddr_to_uniqtype(first_frame_entry->entry.allocsite) == first_frame_entry->entry.uniqtype);
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
			 == (((uintptr_t) obj) & PAGE_MASK))
		{
			// post-extend this one
			slot_to_extend->actual_length += PAGE_SIZE;
			slot = slot_to_extend;
			break;
		}
		else if ((uintptr_t) slot_to_extend->actual_start - PAGE_SIZE == (((uintptr_t) obj) & PAGE_MASK))
		{
			// pre-extend this one
			slot_to_extend->actual_start -= PAGE_SIZE;
			slot_to_extend->actual_length += PAGE_SIZE;
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
			slot->actual_start = (void *)(((uintptr_t) obj) & PAGE_MASK);
			slot->actual_length = PAGE_SIZE;
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
		&& ~mask + 1 > PAGE_SIZE)
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

void *__liballocs_main_bp; // beginning of main's stack frame

// const struct uniqtype *__liballocs_uniqtype_void; // remember the location of the void uniqtype
// const struct uniqtype *__liballocs_uniqtype_signed_char;
// const struct uniqtype *__liballocs_uniqtype_unsigned_char;
// #define LOOKUP_CALLER_TYPE(frag, caller) /* FIXME: use caller not RTLD_DEFAULT -- use interval tree? */ \
//     ( \
// 		(__liballocs_uniqtype_ ## frag) ? __liballocs_uniqtype_ ## frag : \
// 		(__liballocs_uniqtype_ ## frag = dlsym(RTLD_DEFAULT, "__uniqtype__" #frag), \
// 			assert(__liballocs_uniqtype_ ## frag), \
// 			__liballocs_uniqtype_ ## frag \
// 		) \
// 	)

/* counters */
unsigned long __liballocs_aborted_stack;
unsigned long __liballocs_aborted_static;
unsigned long __liballocs_aborted_unknown_storage;
unsigned long __liballocs_hit_heap_case;
unsigned long __liballocs_hit_stack_case;
unsigned long __liballocs_hit_static_case;
unsigned long __liballocs_aborted_unindexed_heap;
unsigned long __liballocs_aborted_unrecognised_allocsite;

static void print_exit_summary(void)
{
	if (__liballocs_aborted_unknown_storage + __liballocs_hit_static_case + __liballocs_hit_stack_case
			 + __liballocs_hit_heap_case > 0)
	{
		fprintf(stream_err, "====================================================\n");
		fprintf(stream_err, "liballocs summary: \n");
		fprintf(stream_err, "----------------------------------------------------\n");
		fprintf(stream_err, "queries aborted for unknown storage:       % 9ld\n", __liballocs_aborted_unknown_storage);
		fprintf(stream_err, "queries handled by static case:            % 9ld\n", __liballocs_hit_static_case);
		fprintf(stream_err, "queries handled by stack case:             % 9ld\n", __liballocs_hit_stack_case);
		fprintf(stream_err, "queries handled by heap case:              % 9ld\n", __liballocs_hit_heap_case);
		fprintf(stream_err, "----------------------------------------------------\n");
		fprintf(stream_err, "queries aborted for unindexed heap:        % 9ld\n", __liballocs_aborted_unindexed_heap);
		fprintf(stream_err, "queries aborted for unknown heap allocsite:% 9ld\n", __liballocs_aborted_unrecognised_allocsite);
		fprintf(stream_err, "queries aborted for unknown stackframes:   % 9ld\n", __liballocs_aborted_stack);
		fprintf(stream_err, "queries aborted for unknown static obj:    % 9ld\n", __liballocs_aborted_static);
		fprintf(stream_err, "====================================================\n");
		for (unsigned i = 0; i < __liballocs_unrecognised_heap_alloc_sites.count; ++i)
		{
			if (i == 0)
			{
				fprintf(stream_err, "Saw the following unrecognised heap alloc sites: \n");
			}
			fprintf(stream_err, "%p (%s)\n", __liballocs_unrecognised_heap_alloc_sites.addrs[i], 
					format_symbolic_address(__liballocs_unrecognised_heap_alloc_sites.addrs[i]));
		}
	}
	
	if (getenv("LIBALLOCS_DUMP_SMAPS_AT_EXIT"))
	{
		char buffer[4096];
		size_t bytes;
		FILE *smaps = fopen("/proc/self/smaps", "r");
		if (smaps)
		{
			while (0 < (bytes = fread(buffer, 1, sizeof(buffer), smaps)))
			{
				fwrite(buffer, 1, bytes, stream_err);
			}
		}
		else fprintf(stream_err, "Couldn't read from smaps!\n");
	}
}

int biggest_vaddr_cb(struct dl_phdr_info *info, size_t size, void *load_addr)
{
	int biggest_seen = 0;
	
	if (info && (void*) info->dlpi_addr == load_addr && info->dlpi_phdr)
	{
		/* This is the object we want; iterate over its phdrs. */
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				/* We can round down to int because vaddrs *within* an object 
				 * will not be more than 2^31 from the object base. */
				uintptr_t max_plus_one = (int) (info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz);
				if (max_plus_one > biggest_seen) biggest_seen = max_plus_one;
			}
		}
		/* Return the biggest we saw. */
		return biggest_seen;
	}
	
	/* keep going */
	return 0;
}

void *biggest_vaddr_in_obj(void *handle)
{
	/* Get the phdrs of the object. */
	struct link_map *lm = handle;
	
	int seen = dl_iterate_phdr(biggest_vaddr_cb, (void*) lm->l_addr);
			
	return (void*)(uintptr_t)seen;
}

/* This is *not* a constructor. We don't want to be called too early,
 * because it might not be safe to open the -uniqtypes.so handle yet.
 * So, initialize on demand. */
int __liballocs_global_init(void) __attribute__((constructor,visibility("protected")));
int __liballocs_global_init(void)
{
	if (__liballocs_is_initialized) return 0; // we are okay

	// don't try more than once to initialize
	static _Bool tried_to_initialize;
	if (tried_to_initialize) return -1;
	tried_to_initialize = 1;
	
	// print a summary when the program exits
	atexit(print_exit_summary);
	
	// delay start-up here if the user asked for it
	if (getenv("LIBALLOCS_DELAY_STARTUP"))
	{
		sleep(10);
	}
	
	// figure out where our output goes
	const char *errvar = getenv("LIBALLOCS_ERR");
	if (errvar)
	{
		// try opening it
		stream_err = fopen(errvar, "w");
		if (!stream_err)
		{
			stream_err = stderr;
			debug_printf(0, "could not open %s for writing\n", errvar);
		}
	} else stream_err = stderr;
	assert(stream_err);

	// the user can specify where we get our -types.so and -allocsites.so
	allocsites_base = getenv("ALLOCSITES_BASE");
	if (!allocsites_base) allocsites_base = "/usr/lib/allocsites";
	allocsites_base_len = strlen(allocsites_base);
	
	const char *debug_level_str = getenv("LIBALLOCS_DEBUG_LEVEL");
	if (debug_level_str) __liballocs_debug_level = atoi(debug_level_str);

	if (!orig_dlopen && safe_to_call_malloc) // might have been done by a pre-init call to our preload dlopen
	{
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlopen);
	}

	/* NOTE that we get called during allocation. So we should avoid 
	 * doing anything that causes more allocation, or else we should
	 * handle the reentrancy gracefully. Calling the dynamic linker
	 * is dangerous. What can we do? Either
	 * 
	 * 1. try to make this function run early, i.e. before main() 
	 *    and during a non-allocation context. 
	 * 
	 * or
	 * 
	 * 2. get the end address without resort to dlopen()... but then
	 *    what about the types objects? 
	 * 
	 * It seems that option 1 is better. 
	 */

	// grab the executable's end address
	// we used to try dlsym()'ing "_end" but this doesn't work! 
	// Not all executables have _end and _begin exported as dynamic syms
	// Also, we don't want to call dlsym since it might not be safe to malloc.
	// Get the phdrs directly from the auxv.
	/* void *executable_handle = dlopen(NULL, RTLD_NOW | RTLD_NOLOAD);
	assert(executable_handle != NULL);
	__addrmap_executable_end_addr = biggest_vaddr_in_obj(executable_handle);*/
	
	char dummy;
	ElfW(auxv_t) *auxv = get_auxv((const char **) environ, &dummy);
	assert(auxv);
	ElfW(auxv_t) *ph_auxv = auxv_lookup(auxv, AT_PHDR);
	ElfW(auxv_t) *phnum_auxv = auxv_lookup(auxv, AT_PHNUM);
	assert(ph_auxv);
	assert(phnum_auxv);
	uintptr_t biggest_seen = 0;
	for (int i = 0; i < phnum_auxv->a_un.a_val; ++i)
	{
		ElfW(Phdr) *phdr = ((ElfW(Phdr)*) ph_auxv->a_un.a_val) + i;
		if (phdr->p_type == PT_LOAD)
		{
			/* We can round down to int because vaddrs *within* an object 
			 * will not be more than 2^31 from the object base. */
			uintptr_t max_plus_one = (int) (phdr->p_vaddr + phdr->p_memsz);
			if (max_plus_one > biggest_seen) biggest_seen = max_plus_one;
		}
	}
	__addrmap_executable_end_addr = (void*) biggest_seen;
	assert(__addrmap_executable_end_addr != 0);
	assert((char*) __addrmap_executable_end_addr < (char*) BIGGEST_SANE_EXECUTABLE_VADDR);
	
	// grab the executable's basename
	ssize_t readlink_ret = readlink("/proc/self/exe", exe_fullname, sizeof exe_fullname);
	if (readlink_ret != -1)
	{
		strncpy(exe_basename, basename(exe_fullname), sizeof exe_basename); // GNU basename
		exe_basename[sizeof exe_basename - 1] = '\0';
	}
	
	int ret_types = dl_iterate_phdr(load_types_for_one_object, NULL);
	assert(ret_types == 0);
	
#ifndef NO_MEMTABLE
	/* Allocate the memtable. 
	 * Assume we don't need to cover addresses >= STACK_BEGIN.
	 * BUT we store vaddrs in the same table, with addresses ORed
	 * with STACK_BEGIN. 
	 * And we store static objects' addres in the same table, with addresses ORed
	 * with STACK_BEGIN<<1. 
	 * So quadruple up the size of the table accordingly. */
	__liballocs_allocsmt = MEMTABLE_NEW_WITH_TYPE(allocsmt_entry_type, allocsmt_entry_coverage, 
		(void*) 0, (void*) (STACK_BEGIN << 2));
	assert(__liballocs_allocsmt != MAP_FAILED);
	
	int ret_allocsites = dl_iterate_phdr(load_and_init_allocsites_for_one_object, NULL);
	assert(ret_allocsites == 0);

	int ret_stackaddr = dl_iterate_phdr(link_stackaddr_and_static_allocs_for_one_object, NULL);
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
		// if (have_name) fprintf(stream_err, "Saw frame %s\n", buf);

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
			__liballocs_main_bp = (void*) (intptr_t) bp;
		}
		else
		{
			// underapproximate bp as the sp
			__liballocs_main_bp = (void*) (intptr_t) sp;
		}
	}
	
	if (__liballocs_main_bp == 0) 
	{
		// underapproximate bp as our current sp!
		debug_printf(1, "Warning: using egregious approximation for bp of main().\n");
		unw_word_t our_sp;
	#ifdef UNW_TARGET_X86
		__asm__ ("movl %%esp, %0\n" :"=r"(our_sp));
	#else // assume X86_64 for now
		__asm__("movq %%rsp, %0\n" : "=r"(our_sp));
	#endif
		__liballocs_main_bp = (void*) (intptr_t) our_sp;
	}
	assert(__liballocs_main_bp != 0);
	
	// also init the l0 index -- danger! avoid allocation here too
	__liballocs_init_l0();

	__liballocs_is_initialized = 1;

	debug_printf(1, "liballocs successfully initialized\n");
	
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
	void *handle = (orig_dlopen ? orig_dlopen : dlopen)(types_libname, RTLD_NOW | RTLD_NOLOAD);
	if (handle == NULL)
		printf("Error: %s\n", dlerror());
	return handle;
}

void *__liballocs_my_typeobj(void) __attribute__((visibility("protected")));
void *__liballocs_my_typeobj(void)
{
	__liballocs_ensure_init();
	return typeobj_handle_for_addr(__builtin_return_address(0));
}

/* FIXME: hook dlopen and dlclose so that we can load/unload allocsites and types
 * as execution proceeds. */


/* This is left out-of-line because it's inherently a slow path. */
const void *__liballocs_typestr_to_uniqtype(const char *typestr) __attribute__((visibility("protected")));
const void *__liballocs_typestr_to_uniqtype(const char *typestr)
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

_Bool __liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched) __attribute__((visibility("protected")));
_Bool __liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched)
{
	if (target_offset_within_uniqtype == 0 && (!test_uniqtype || cur_obj_uniqtype == test_uniqtype)) return 1;
	else
	{
		/* We might have *multiple* subobjects spanning the offset. 
		 * Test all of them. */
		struct uniqtype *containing_uniqtype = NULL;
		struct contained *contained_pos = NULL;
		
		signed sub_target_offset = target_offset_within_uniqtype;
		struct uniqtype *contained_uniqtype = cur_obj_uniqtype;
		
		_Bool success = __liballocs_first_subobject_spanning(
			&sub_target_offset, &contained_uniqtype,
			&containing_uniqtype, &contained_pos);
		// now we have a *new* sub_target_offset and contained_uniqtype
		
		if (!success) return 0;
		
		*p_cumulative_offset_searched += contained_pos->offset;
		
		if (last_attempted_uniqtype) *last_attempted_uniqtype = contained_uniqtype;
		if (last_uniqtype_offset) *last_uniqtype_offset = sub_target_offset;
		do {
			assert(containing_uniqtype == cur_obj_uniqtype);
			_Bool recursive_test = __liballocs_find_matching_subobject(
					sub_target_offset,
					contained_uniqtype, test_uniqtype, 
					last_attempted_uniqtype, last_uniqtype_offset, p_cumulative_offset_searched);
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

struct uniqtype * 
__liballocs_get_alloc_type(void *obj)
{
	memory_kind k;
	const void *object_start;
	struct uniqtype *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		NULL, &out, NULL);
	
	if (err) return NULL;
	
	return out;
}

struct uniqtype * 
__liballocs_get_outermost_type(void *obj)
{
	return __liballocs_get_alloc_type(obj);
}
