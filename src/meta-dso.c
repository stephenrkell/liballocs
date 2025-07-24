#define _GNU_SOURCE

#include <stdio.h>
#include <link.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "librunt.h"
#include "relf.h"
#include "maps.h"
#include "liballocs.h"
#include "liballocs_private.h"

#ifdef _LIBGEN_H
#error "liballocs.c needs GNU basename() so must not include libgen.h"
#endif

const char *meta_base __attribute__((visibility("hidden")));
unsigned meta_base_len __attribute__((visibility("hidden")));

__attribute__((visibility("hidden")))
const char *ensure_meta_base(void)
{
	if (meta_base) return meta_base;
	// the user can specify where we get our -meta.so
	meta_base = getenv("META_BASE");
	if (!meta_base) meta_base = "/usr/lib/meta";
	meta_base_len = strlen(meta_base);
	return meta_base;
}

// helper
static const void *typestr_to_uniqtype_from_lib(void *handle, const char *typestr);

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

__attribute__((visibility("hidden")))
const char *meta_libfile_name(const char *objname)
{
	/* we must have a canonical filename */
	if (objname[0] != '/') return NULL;
	ensure_meta_base();
#ifndef NO_TLS
	static __thread char libfile_name[4096]; // FIXME
#else
	static char libfile_name[4096]; // FIXME
#endif
	unsigned bytes_left = sizeof libfile_name - 1;
	
	libfile_name[0] = '\0';
	bytes_left--;
	// append the uniqtypes base path
	strncat(libfile_name, meta_base, bytes_left);
	bytes_left -= (bytes_left < meta_base_len) ? bytes_left : meta_base_len;
	
	// now append the object name
	unsigned file_name_len = strlen(objname);
	assert(file_name_len > 0);
	strncat(libfile_name, objname, bytes_left);
	bytes_left -= (bytes_left < file_name_len) ? bytes_left : file_name_len;
	
	// now append the suffix
	strncat(libfile_name, META_OBJ_SUFFIX, bytes_left);
	// no need to compute the last bytes_left
	
	return &libfile_name[0];
}
const char *__liballocs_meta_libfile_name(const char *objname)
{
	return meta_libfile_name(objname);
}

/* HACK to avoid too much librunt dependency in this allocsld-borrowed code. */
#ifndef IN_LIBALLOCS_DSO
#define get_exe_command_basename(...) "(no name)"
#endif
__attribute__((visibility("hidden")))
int find_and_open_meta_libfile(const char *objname)
{
	const char *meta_buf = meta_libfile_name(objname);
	/* open it and fstat it */
	int fd_meta = open(meta_buf, O_RDONLY);
	if (fd_meta == -1)
	{
		debug_printf(1, "Could not open meta-DSO `%s' (%s)\n", meta_buf, strerror(errno));
		return -1;
	}
	struct stat statbuf_meta;
	int ret = fstat(fd_meta, &statbuf_meta);
	if (ret != 0)
	{
		debug_printf(1, "Could not fstat meta-DSO `%s' (%s)\n", meta_buf, strerror(errno));	
		close(fd_meta);
		return -1;
	}
	// also stat the actual ld.so!
	struct stat statbuf_base;
	ret = stat(objname, &statbuf_base);
	if (ret != 0)
	{
		/* Is it a problem if we can't stat it? We just can't do our newer-than check. 
		 * FIXME: our approach here is already vulnerable to false positives e.g.
		 * if a new binary/metadata is being installed while an old process is running
		 * this code... we will compare against the timestamp of the new base binary. */
		debug_printf(0, "Could not stat base DSO `%s' (%s) -- deleted on disk?\n", objname, strerror(errno));
	}
	// is the base file newer than the meta file? if so, we don't load it
	if (statbuf_base.st_mtime > statbuf_meta.st_mtime)
	{
		debug_printf(0, "Declining to load out-of-date meta-DSO `%s' (%s)\n", meta_buf, strerror(errno));
		close(fd_meta);
		return -1;
	}
	return fd_meta;
}
#ifndef IN_LIBALLOCS_DSO
#undef get_exe_command_basename
#endif

/* We use this file for generic meta-obj routines, from allocsld.
 * But the following can only work in liballocs.
 * (HACK: is_meta_object_for_lib should work from outside, but pulls in too
 * much of librunt and breaks the link of allocsld. So put it in here for now.
 * It might work to separate out dynobj_name_from_dlpi_name and realpath_quick
 * in librunt.a so that they are in their own .o file, or one that doesn't pull
 * in the preload stuff anyway.) */
#ifdef IN_LIBALLOCS_DSO

// HACK
extern void __libcrunch_scan_lazy_typenames(void *handle) __attribute__((weak));

_Bool is_meta_object_for_lib(struct link_map *maybe_meta, struct link_map *l)
{
	// get the canonical libfile name
	const char *canon_l_objname = dynobj_name_from_dlpi_name(l->l_name,
		(void*) l->l_addr); // always returns non-null
	const char *types_objname_not_norm = meta_libfile_name(canon_l_objname);
	if (!types_objname_not_norm) return 0;
	const char *types_objname_norm = realpath_quick(types_objname_not_norm);
	if (!types_objname_norm) return 0; /* meta obj does not exist */
	char types_objname_buf[4096];
	strncpy(types_objname_buf, types_objname_norm, sizeof types_objname_buf - 1);
	types_objname_buf[sizeof types_objname_buf - 1] = '\0';
	const char *canon_types_objname = dynobj_name_from_dlpi_name(maybe_meta->l_name,
		(void*) maybe_meta->l_addr); // always returns nonnull
	if (0 == strcmp(types_objname_buf, canon_types_objname)) return 1;
	else return 0;
}

int load_and_init_all_metadata_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
{
	void *meta_handle = NULL;
	void **maybe_out_handle = (void**) data;
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;
	_Bool is_exe = (info->dlpi_addr == 0) || (0 == strcmp(canon_objname, get_exe_dynobj_fullname()));
	const char *canon_basename = basename(canon_objname);
	_Bool is_libc = ((0 == strncmp(canon_basename, "libc", 4))
				&& (canon_basename[4] == '-' || canon_basename[4] == '.'));

	// skip objects that are themselves meta objects (i.e. are under the meta_base path)
	// FIXME: what about embedded meta objects? we haven't implemented those yet....
	if (0 == strcmp(canon_objname, ensure_meta_base())) return 0;
	
	// get the -meta.so object's name
	const char *libfile_name = meta_libfile_name(canon_objname);
	if (!libfile_name) return 0;
	// don't load if we end with "-meta.so", wherever we are
	// FIXME: not sure we need *both* this test and the one above (for being under meta_base)
	if (0 == strcmp(META_OBJ_SUFFIX, canon_objname + strlen(canon_objname) - strlen(META_OBJ_SUFFIX)))
	{
		return 0;
	}
	
	/* FIXME: do a stat() check on the mtime of our meta-obj
	 * versus the mtime of the base obj.
	 * If the base obj is newer, complain. */

	// FIXME BUG: dlerror can SEGFAULT if called here (why?), also appears below
	//dlerror();
	// load with NOLOAD first, so that duplicate loads are harmless
	/* Towards meta-completeness: use the real dlopen, so that meta-objs
	 * are also loaded. We will fail to load their meta-obj. */
	meta_handle = dlopen(libfile_name, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
	if (meta_handle)
	{
		/* That means the object is already loaded. How did that happen? */
		debug_printf(0, "meta object unexpectedly already loaded: %s\n", libfile_name);
		*maybe_out_handle = meta_handle;
		dlclose(meta_handle); // decrement the refcount, but won't free the link_map
		return 0;
	}
	errno = 0;
	//dlerror();
	meta_handle = dlopen(libfile_name, RTLD_NOW | RTLD_GLOBAL);
	errno = 0;
	if (!meta_handle)
	{
		/* The dlerror message will repeat the libfile name, so no need to print it. */
		debug_printf((is_exe || is_libc) ? 0 : 1, "error loading meta object: %s\n",
			dlerror());
		return 0;
	}
	debug_printf(3, "loaded meta object: %s\n", libfile_name);
	if (maybe_out_handle) *maybe_out_handle = meta_handle;

	// HACK: scan it for lazy-heap-alloc types
	if (__libcrunch_scan_lazy_typenames) __libcrunch_scan_lazy_typenames(meta_handle);

	// always continue with further objects
#ifndef NO_MEMTABLE
	dlerror();
	// FIXME: new version
	//struct allocsite_entry *first_entry = (struct allocsite_entry *) dlsym(meta_handle, "allocsites");
#endif
	if (&__hook_loaded_one_object_meta) __hook_loaded_one_object_meta(info, size, meta_handle);
#ifndef NO_MEMTABLE
	return 0; //link_said_stop;
#else
	return 0;
#endif
}

static int swap_out_segment_pages(struct dl_phdr_info *info, size_t size, void *load_addr)
{
	for (int i = 0; i < info->dlpi_phnum; ++i)
	{
		const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
		if (phdr->p_type == PT_LOAD)
		{
			uintptr_t begin_addr = (uintptr_t) load_addr + phdr->p_vaddr;
			uintptr_t end_addr = (uintptr_t) begin_addr + phdr->p_memsz;
			void *base = (void*) ROUND_DOWN(begin_addr, PAGE_SIZE);
			size_t len = ROUND_UP(end_addr, PAGE_SIZE) - (uintptr_t) base;
			/* FIXME: I don't think this is the right call. 
			 * In fact I don't think Linux lets us forcibly swap out
			 * a private mapping, which is what we're asking. */
			int ret = 0; // msync(base, len, MS_SYNC|MS_INVALIDATE);
			if (ret == -1) warnx("msync() returned %s\n", strerror(errno));
		}
	}
	return 0; // "keep going"
}

int __liballocs_iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg) __attribute__((visibility("protected")));
int __liballocs_iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg)
{
	/* Don't use dladdr() to iterate -- too slow! Instead, iterate 
	 * directly over the dynsym section.
	 * FIXME: this seems broken. We don't get the unique "active" definition
	 * of the uniqtype, necessarily, cf. the overridden ones.
	 * In libcrunch we scan the typelibs "in link order" of the corresponding
	 * actual libs, and hit the  first def we get; this is *probably* correct, but... */
	struct link_map *h = typelib_handle;
	unsigned char *load_addr = (unsigned char *) h->l_addr;
	
	/* If load address is greater than STACK_BEGIN, it's suspicious -- 
	 * perhaps a vdso-like thing. Skip it. The vdso itself is detected
	 * below (it lives in user memory, but points into kernel memory). */
	if (!load_addr || (intptr_t) load_addr < 0) return 0;
	
	/* We don't have to add load_addr, because ld.so has already done it. */
	ElfW(Dyn) *dynsym_ent = dynamic_lookup(h->l_ld, DT_SYMTAB);
	assert(dynsym_ent);
	ElfW(Sym) *dynsym = (ElfW(Sym) *) dynsym_ent->d_un.d_ptr;
	assert(dynsym);
	/* Catch the vdso case. */
	if (!dynsym || (intptr_t) dynsym < 0) return 0;
	
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
	unsigned long nsyms = dynamic_symbol_count(h->l_ld, h);
	ElfW(Dyn) *dynstr_ent = dynamic_lookup(h->l_ld, DT_STRTAB);
	assert(dynstr_ent);
	char *dynstr = (char*) dynstr_ent->d_un.d_ptr;

	int cb_ret = 0;
	for (ElfW(Sym) *p_sym = dynsym; p_sym <  dynsym + nsyms; ++p_sym)
	{
		const char *name = p_sym->st_name ? dynstr + p_sym->st_name : NULL;
		if (ELF64_ST_TYPE(p_sym->st_info) == STT_OBJECT && 
			p_sym->st_shndx != SHN_UNDEF &&
			0 == strncmp("__uniqty", name, 8) &&
			(0 != strcmp("_subobj_names", 
					dynstr + p_sym->st_name + strlen(name)
						 - (sizeof "_subobj_names" - 1)
				)
			)
		)
		{
			struct uniqtype *t = (struct uniqtype *) (load_addr + p_sym->st_value);
			// if our name comes out as null, we've probably done something wrong
			if (UNIQTYPE_IS_SANE(t))
			{
				cb_ret = cb(t, arg);
				if (cb_ret != 0) break;
			}
			else warnx("Saw insane uniqtype %s at %p in file %s", name, t, h->l_name);
		}
	}
	
	/* HACK: after we do a pass over the types, our memory consumption will appear
	 * huge, even though we don't need this stuff any more. */
	dl_for_one_object_phdrs(typelib_handle, swap_out_segment_pages, load_addr);
	
	return cb_ret;
}

static void *metaobj_handle_for_addr(void *caller)
{
	// find out what object the caller is in
	Dl_info info;
	dlerror();
	int dladdr_ret = dladdr(caller, &info);
	assert(dladdr_ret != 0);
	
	// dlopen the metaobj
	const char *meta_libname = meta_libfile_name(dynobj_name_from_dlpi_name(info.dli_fname, info.dli_fbase));
	if (!meta_libname)
	{
		debug_printf(1, "No metaobj handle for addr %p", caller);
		return NULL;
	}
	
	void *handle = (orig_dlopen ? orig_dlopen : dlopen)(meta_libname, RTLD_NOW | RTLD_NOLOAD);
	if (handle == NULL)
	{
		debug_printf(1, "No metaobj loaded for addr %p, typeobj name %s", caller, meta_libname);
		return NULL;
	}
	dlclose(handle); // unbump refcount; it will remain at least 1
	return handle;
}

void *__liballocs_my_metaobj(void) __attribute__((visibility("protected")));
void *__liballocs_my_metaobj(void)
{
	__liballocs_ensure_init();
	return metaobj_handle_for_addr(__builtin_return_address(0));
}

#endif
