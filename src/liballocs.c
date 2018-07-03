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
#include <dwarf.h> /* for DW_ATE_* */
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef USE_REAL_LIBUNWIND
#include <libunwind.h>
#endif
#include "maps.h"
#include "relf.h"
#include "systrap.h"
#include "raw-syscalls.h"
#include "liballocs.h"
#include "liballocs_private.h"
#include "dlbind.h"

#ifdef _LIBGEN_H
#error "liballocs.c needs GNU basename() so must not include libgen.h"
#endif

void *__liballocs_rt_uniqtypes_obj;
ElfW(Sym) *__liballocs_rt_uniqtypes_dynsym;
ElfW(Word) *__liballocs_rt_uniqtypes_gnu_hash;
unsigned char *__liballocs_rt_uniqtypes_dynstr;

static void update_rt_uniqtypes_obj(void *handle, void *old_base)
{
	_Bool unchanged_base = (handle == __liballocs_rt_uniqtypes_obj) &&
		(void*) ((struct link_map *) handle)->l_addr == old_base;
	if (!unchanged_base)
	{
		__liballocs_rt_uniqtypes_obj = handle;
		__liballocs_rt_uniqtypes_dynsym = get_dynsym(handle);
		__liballocs_rt_uniqtypes_dynstr = get_dynstr(handle);
		__liballocs_rt_uniqtypes_gnu_hash = get_gnu_hash(handle);
	}
}

struct uniqtype *
__liballocs_get_or_create_array_type(struct uniqtype *element_t, unsigned array_len)
{
	assert(element_t);
	assert(element_t->pos_maxoff > 0);
	assert(element_t->pos_maxoff != UNIQTYPE_POS_MAXOFF_UNBOUNDED);
	
	char precise_uniqtype_name[4096];
	const char *element_name = UNIQTYPE_NAME(element_t); /* gets "simple", not symbol, name */
	snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
			"__uniqtype____ARR%d_%s", array_len, element_name);
	/* FIXME: compute hash code. Should be an easy case. */
	
	/* Does such a type exist?
	 * On the assumption that we get called many times for the same typename,
	 * and that usually therefore it *does* exist but in the synthetic libdlbind
	 * object, we try a GNU hash lookup on that first. */
	ElfW(Sym) *found_sym = __liballocs_rt_uniqtypes_gnu_hash ?
		gnu_hash_lookup(__liballocs_rt_uniqtypes_gnu_hash,
			__liballocs_rt_uniqtypes_dynsym, __liballocs_rt_uniqtypes_dynstr,
			precise_uniqtype_name)
		: NULL;
	void *found = (found_sym ? sym_to_addr(found_sym) : NULL);
	if (NULL != found || NULL != (found = dlsym(NULL, precise_uniqtype_name)))
	{
		return (struct uniqtype *) found;
	}
	else
	{
		/* Create it and memoise using libdlbind. */
		size_t sz = offsetof(struct uniqtype, related) + 1 * (sizeof (struct uniqtype_rel_info));
		void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
		struct uniqtype *allocated_uniqtype = allocated;
		*allocated_uniqtype = (struct uniqtype) {
			.pos_maxoff = array_len * element_t->pos_maxoff,
			.un = {
				array: {
					.is_array = 1,
					.nelems = array_len
				}
			},
			.make_precise = NULL
		};
		allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
			.un = {
				t: {
					.ptr = element_t
				}
			}
		};
		void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
		void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
			allocated, sz, STT_OBJECT);
		assert(reloaded);
		update_rt_uniqtypes_obj(reloaded, old_base);
		
		return allocated_uniqtype;
	}
}

struct uniqtype *
__liballocs_make_array_precise_with_memory_bounds(struct uniqtype *in,
   struct uniqtype *out, unsigned long out_len,
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt)
{
	unsigned long precise_size = ((char*) memrange_base + memrange_sz) - (char*) obj;
	struct uniqtype *element_t = UNIQTYPE_ARRAY_ELEMENT_TYPE(in);
	assert(element_t);
	assert(element_t->pos_maxoff > 0);
	assert(element_t->pos_maxoff != UNIQTYPE_POS_MAXOFF_UNBOUNDED);
	
	unsigned array_len = precise_size / element_t->pos_maxoff;
	assert(precise_size % element_t->pos_maxoff == 0); /* too strict? */
	
	return __liballocs_get_or_create_array_type(element_t, precise_size / element_t->pos_maxoff);
}

struct uniqtype *
__liballocs_make_precise_identity(struct uniqtype *in,
   struct uniqtype *out, unsigned long out_len,
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt)
{
	return in;
}

/* This is the "bzip2 fix". We need the ability to dynamically re-bless memory
 * as a simultaneous combination (union) of a new type and the type it had earlier.
 * PROBLEM: what do we call the union? OK, we can make it anonymous, but we're going
 * (for now) to skip computing the summary code. So build a name by concatenating
 * the constituent element names. */
struct uniqtype *
__liballocs_get_or_create_union_type(unsigned n, /* struct uniqtype *first_memb_t, */...)
{
	if (n == 0) return NULL;
	va_list ap;
	va_start(ap, n);
#define UNION_NAME_MAXLEN 4096
	char union_raw_name[UNION_NAME_MAXLEN] = { '\0' };
	unsigned cur_len = 0;
	struct uniqtype *membs[n]; // ooh, C99 variable-length array...
	unsigned n_left = n;
	unsigned max_len = 0;
	while (n_left > 0)
	{
		struct uniqtype *memb_t = va_arg(ap, struct uniqtype *);
		assert(memb_t);
		assert(memb_t->pos_maxoff > 0);
		assert(memb_t->pos_maxoff != UNIQTYPE_POS_MAXOFF_UNBOUNDED);
		const char *memb_name = NAME_FOR_UNIQTYPE(memb_t);
		membs[n - n_left] = memb_t;
		unsigned len = strlen(memb_name);
		if (cur_len + len >= UNION_NAME_MAXLEN) return NULL;
		strcat(union_raw_name, memb_name);
		if (memb_t->pos_maxoff > max_len) max_len = memb_t->pos_maxoff;
		--n_left;
	}
	char union_uniqtype_name[UNION_NAME_MAXLEN + sizeof "__uniqtype____SYNTHUNION_"] = { '\0' };
	strcat(union_uniqtype_name, "__uniqtype____SYNTHUNION_");
	strcat(union_uniqtype_name, union_raw_name);
#undef UNION_NAME_MAXLEN
	/* FIXME: compute hash code. Should be an easy case. */
	/* Does such a type exist? */
	void *found = NULL;
	if (NULL != (found = dlsym(NULL, union_uniqtype_name)))
	{
		return (struct uniqtype *) found;
	}
	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + n * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = max_len,
		.un = {
			composite: {
				.kind = COMPOSITE,
				.nmemb = n,
				.not_simultaneous = 0
			}
		},
		.make_precise = NULL
	};
	for (unsigned i = 0; i < n; ++i)
	{
		struct uniqtype *memb_t = membs[i];
		allocated_uniqtype->related[i] = (struct uniqtype_rel_info) {
			.un = {
				memb: {
					.ptr = memb_t,
					.off = 0,
					.is_absolute_address = 0,
					.may_be_invalid = 0
				}
			}
		};
	}
	
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, union_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);
	update_rt_uniqtypes_obj(reloaded, old_base);

	return allocated_uniqtype;
}

/* Force a definition of this inline function to be emitted.
 * Debug builds use this, since they won't inline the call to it
 * from the wrapper function. */
int 
__liballocs_walk_subobjects_spanning_rec(
	unsigned accum_offset, unsigned accum_depth,
	const unsigned target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, unsigned span_start_offset, unsigned depth,
		struct uniqtype *containing, struct uniqtype_rel_info *contained_pos, 
		unsigned containing_span_start_offset, void *arg),
	void *arg
	);

#ifndef USE_REAL_LIBUNWIND
#include "fake-libunwind.h"
int unw_get_proc_name(unw_cursor_t *p_cursor, char *buf, size_t n, unw_word_t *offp) __attribute__((visibility("hidden")));
int unw_get_proc_name(unw_cursor_t *p_cursor, char *buf, size_t n, unw_word_t *offp)
{
	assert(!offp);
	//dlerror();
	//Dl_info info = dladdr_with_cache((void*) p_cursor->frame_ip);
	//if (!info.dli_fname) return 1;
	//if (!info.dli_sname) return 2;
	/* For robustness, use fake_dladdr. */
	const char *sname;
	int success = fake_dladdr((void*) p_cursor->frame_ip, NULL, NULL, &sname, NULL);
	if (!success) return 1;
	else 
	{
		strncpy(buf, sname, n);
		return 0;
	}
}
#endif

char *get_exe_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_fullname(void)
{
	static char exe_fullname[4096];
	static _Bool tried;
	if (!exe_fullname[0] && !tried)
	{
		tried = 1;
		// grab the executable's basename; if we fail, we won't try again
		int ret __attribute__((unused))
		 = readlink("/proc/self/exe", exe_fullname, sizeof exe_fullname);
		errno = 0;
	}
	if (exe_fullname[0]) return exe_fullname;
	else return NULL;
}

char *get_exe_basename(void) __attribute__((visibility("hidden")));
char *get_exe_basename(void)
{
	static char exe_basename[4096];
	static _Bool tried;
	if (!exe_basename[0] && !tried)
	{
		tried = 1;
		char *exe_fullname = get_exe_fullname();
		if (exe_fullname)
		{
			strncpy(exe_basename, basename(exe_fullname), sizeof exe_basename); // GNU basename
			exe_basename[sizeof exe_basename - 1] = '\0';
		}
	}
	if (exe_basename[0]) return exe_basename;
	else return NULL;
}

const char __ldso_name[] = "/lib64/ld-linux-x86-64.so.2"; // FIXME: sysdep
FILE *stream_err __attribute__((visibility("hidden")));

struct addrlist __liballocs_unrecognised_heap_alloc_sites = { 0, 0, NULL };

static const char *meta_base;
static unsigned meta_base_len;

int __liballocs_debug_level;
_Bool __liballocs_is_initialized;
allocsmt_entry_type *__liballocs_allocsmt;

// these two are defined in addrmap.h as weak
unsigned long __addrmap_max_stack_size;

// helper
static const void *typestr_to_uniqtype_from_lib(void *handle, const char *typestr);

// HACK
void __liballocs_preload_init(void);

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
	return dl_iterate_phdr(dl_for_one_phdr_cb, &args);
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

// static int iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg);

static int print_type_cb(struct uniqtype *t, void *ignored)
{
	fprintf(stream_err, "uniqtype addr %p, name %s, size %d bytes\n", 
		t, UNIQTYPE_NAME(t), t->pos_maxoff);
	fflush(stream_err);
	return 0;
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

const char *(__attribute__((pure)) __liballocs_uniqtype_symbol_name)(const struct uniqtype *u)
{
	if (!u) return NULL;
	Dl_info i = dladdr_with_cache(u);
	if (i.dli_saddr == u)
	{
		return i.dli_sname;
	} else return NULL;
}

const char *(__attribute__((pure)) __liballocs_uniqtype_name)(const struct uniqtype *u)
{
	if (!u) return "(no type)";
	const char *symbol_name = __liballocs_uniqtype_symbol_name(u);
	if (symbol_name)
	{
		if (0 == strncmp(symbol_name, "__uniqtype__", sizeof "__uniqtype__" - 1))
		{
			/* Codeless. */
			return symbol_name + sizeof "__uniqtype__" - 1;
		}
		else if (0 == strncmp(symbol_name, "__uniqtype_", sizeof "__uniqtype_" - 1))
		{
			/* With code. */
			return symbol_name + sizeof "__uniqtype_" - 1 + /* code + underscore */ 9;
		}
		return symbol_name;
	}
	return "(unnamed type)";
}

struct allocsite_entry *__liballocs_allocsite_to_entry(const void *allocsite)
{ return allocsite_to_entry(allocsite); }

struct uniqtype *__liballocs_allocsite_to_uniqtype(const void *allocsite)
{ return allocsite_to_uniqtype(allocsite); }

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

	/* This is a dummy: we choose not to initialise anything at this point, for now. */

	done_init = 1;
}

// FIXME: do better!
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg)
{
	static char buf[4096];
	errno = 0;
	char *ret = realpath(arg, &buf[0]);
	if (errno) { errno = 0; return NULL; }
	return ret;
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
		 * - any others? vdso?
		 */
		if (dlpi_addr == 0) return get_exe_fullname();
		else
		{
			/* HMM -- empty dlpi_name but non-zero load addr.
			 * Is it the vdso? */
			struct link_map *l = get_highest_loaded_object_below((char*) dlpi_addr);
			ElfW(Dyn) *strtab_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
			if (strtab_ent && (intptr_t) strtab_ent->d_un.d_val < 0)
			{
				/* BUGGY vdso, but good enough for me. */
				return "[vdso]";
				//const char *strtab = (const char *) strtab_ent->d_un.d_ptr;
				//ElfW(Dyn) *soname_ent = dynamic_lookup(l->l_ld, DT_SONAME);
				//const char *soname_str = strtab + soname_ent->d_un.d_val;
				//if (strstr(soname_str, "vdso"))
				//{
				//	// okay, vdso
				//	return "[vdso]";
				//}
			}
			else
			{
				/* This is probably a PIE executable or a shared object
				 * being interpreted as an executable. */
				return get_exe_fullname();
			}
		}
	}
	else
	{
		// we need to realpath() it
		const char *maybe_real = realpath_quick(dlpi_name);
		if (maybe_real) return maybe_real;
		/* If realpath said nothing, it's a bogus non-empty filename. 
		 * Return the filename directly. */
		return dlpi_name;
	}
}

static const char *meta_libfile_name(const char *objname)
{
	/* we must have a canonical filename */
	if (objname[0] != '/') return NULL;
	
	static __thread char libfile_name[4096]; // FIXME
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

static void chain_allocsite_entries(struct allocsite_entry *cur_ent, 
	struct allocsite_entry *prev_ent, unsigned *p_current_bucket_size, 
	intptr_t load_addr, intptr_t extrabits)
{
#define FIXADDR(a) 	((void*)((intptr_t)(a) | extrabits))

	// fix up the allocsite by the containing object's load address
	*((unsigned char **) &cur_ent->allocsite) += load_addr;

	// debugging: print out entry
	debug_printf(4, "allocsite entry: %p, extrabits %p, to uniqtype at %p\n", 
		cur_ent->allocsite, (void*) extrabits, cur_ent->uniqtype);

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
		debug_printf(4, "starting a new bucket for allocsite %p, mapped from %p\n", 
			cur_ent->allocsite, bucketpos);
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

int link_stackaddr_and_static_allocs_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
{
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;

	// skip objects that are themselves meta objects
	if (0 == strncmp(canon_objname, meta_base, meta_base_len)) return 0;
	
	// get the meta object's name
	const char *libfile_name = meta_libfile_name(canon_objname);
	if (!libfile_name) return 0;
	// don't load if we end with "-meta.so"
	if (0 == strcmp(META_OBJ_SUFFIX, canon_objname + strlen(canon_objname) - strlen(META_OBJ_SUFFIX)))
	{
		return 0;
	}

	dlerror();
	void *meta_handle = (orig_dlopen ? orig_dlopen : dlopen)(libfile_name, RTLD_NOW | RTLD_NOLOAD);
	if (!meta_handle)
	{
		debug_printf(1, "re-loading meta object: %s\n", dlerror());
		return 0;
	}
	
	{
		dlerror();
		struct frame_allocsite_entry *first_frame_entry
		 = (struct frame_allocsite_entry *) dlsym(meta_handle, "frame_vaddrs");
		if (!first_frame_entry)
		{
			debug_printf(1, "Could not load frame vaddrs (%s)\n", dlerror());
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
				prev_frame_ent ? &prev_frame_ent->entry : NULL, 
				&current_frame_bucket_size,
				info->dlpi_addr, 0x800000000000ul);
		}

		// debugging: check that we can look up the first entry, if we are non-empty
		assert(!first_frame_entry || !first_frame_entry->entry.allocsite || 
			vaddr_to_stack_uniqtype(first_frame_entry->entry.allocsite).u == first_frame_entry->entry.uniqtype);
	}
	
	/* Now a similar job for the statics. */
	{
		dlerror();
		struct static_allocsite_entry *first_static_entry
		 = (struct static_allocsite_entry *) dlsym(meta_handle, "statics");
		if (!first_static_entry)
		{
			debug_printf(1, "Could not load statics (%s)", dlerror());
			return 0;
		}

		/* We chain these much like the allocsites, BUT we OR each vaddr with 
		 * STACK_BEGIN<<1 first.  */
		struct static_allocsite_entry *cur_static_ent = first_static_entry;
		struct static_allocsite_entry *prev_static_ent = NULL;
		unsigned current_static_bucket_size = 1; // out of curiosity...
		for (; !STATIC_ALLOCSITE_IS_NULL(cur_static_ent); prev_static_ent = cur_static_ent++)
		{
			chain_allocsite_entries(cur_static_ent ? &cur_static_ent->entry : NULL, 
					prev_static_ent ? &prev_static_ent->entry : NULL,
					&current_static_bucket_size,
				info->dlpi_addr, 0x800000000000ul<<1);
		}

		// debugging: check that we can look up the first entry, if we are non-empty
		assert(!first_static_entry || STATIC_ALLOCSITE_IS_NULL(first_static_entry) || 
			static_addr_to_uniqtype(first_static_entry->entry.allocsite, NULL)
				== first_static_entry->entry.uniqtype);
	}
	
	// always continue with further objects
	return 0;
}

int load_and_init_all_metadata_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
{
	void *meta_handle = NULL;
	void *maybe_out_handle = data;
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;
	_Bool is_exe = (info->dlpi_addr == 0) || (0 == strcmp(canon_objname, get_exe_fullname()));
	const char *canon_basename = basename(canon_objname);
	_Bool is_libc = ((0 == strncmp(canon_basename, "libc", 4))
				&& (canon_basename[4] == '-' || canon_basename[4] == '.'));

	// skip objects that are themselves meta objects
	// FIXME: what about embedded meta objects?
	if (0 == strncmp(canon_objname, meta_base, meta_base_len)) return 0;
	
	// get the -meta.so object's name
	const char *libfile_name = meta_libfile_name(canon_objname);
	if (!libfile_name) return 0;
	// don't load if we end with "-meta.so"
	if (0 == strcmp(META_OBJ_SUFFIX, canon_objname + strlen(canon_objname) - strlen(META_OBJ_SUFFIX)))
	{
		return 0;
	}

	dlerror();
	// load with NOLOAD first, so that duplicate loads are harmless
	meta_handle = (orig_dlopen ? orig_dlopen : dlopen)(libfile_name, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
	if (meta_handle) return 0;
	errno = 0;
	dlerror();
	meta_handle = (orig_dlopen ? orig_dlopen : dlopen)(libfile_name, RTLD_NOW | RTLD_GLOBAL);
	errno = 0;
	if (!meta_handle)
	{
		debug_printf((is_exe || is_libc) ? 0 : 1, "loading meta object: %s\n", dlerror());
		return 0;
	}
	debug_printf(3, "loaded meta object: %s\n", libfile_name);
	if (maybe_out_handle) *(void**) maybe_out_handle = meta_handle;

	// HACK: scan it for lazy-heap-alloc types
	if (__libcrunch_scan_lazy_typenames) __libcrunch_scan_lazy_typenames(meta_handle);

	// always continue with further objects
#ifndef NO_MEMTABLE
	dlerror();
	struct allocsite_entry *first_entry = (struct allocsite_entry *) dlsym(meta_handle, "allocsites");
	// allocsites cannot be null anyhow
	assert(first_entry && "symbol 'allocsites' must be present in -allocsites.so"); 
	unsigned n_allocsites = 0;

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
		++n_allocsites;
	}
	
	issue_allocsites_ids(n_allocsites, first_entry, (const void *) info->dlpi_addr);

	// debugging: check that we can look up the first entry, if we are non-empty
	assert(!first_entry || !first_entry->allocsite || 
		allocsite_to_uniqtype(first_entry->allocsite) == first_entry->uniqtype);
	int link_said_stop = link_stackaddr_and_static_allocs_for_one_object(info, size, NULL);
#endif
	if (&__hook_loaded_one_object_meta) __hook_loaded_one_object_meta(info, size, meta_handle);
#ifndef NO_MEMTABLE
	return link_said_stop;
#else
	return 0;
#endif
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
		mask |= 1ul<<(sizeof (uintptr_t) * 8 - 1); // set the top bit of the mask
		bits = ((uintptr_t) slot->actual_start) & mask;
		
	}
	
	// if we got a zero-length entry, give up and zero the whole lot
	assert((bits | mask) >= (uintptr_t) slot->actual_start);
	assert((bits | ~mask) <= (uintptr_t) slot->actual_start + slot->actual_length);
	
	slot->mask = mask;
	slot->bits = bits;
#endif
}

void *__liballocs_main_bp; // beginning of main's stack frame

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

/* We're allowed to malloc, thanks to __private_malloc(), but we 
 * we shouldn't call strdup because libc will do the malloc. */
char *__liballocs_private_strdup(const char *s)
{
	size_t len = strlen(s);
	char *mem = __wrap_dlmalloc(len + 1);
	strncpy(mem, s, len);
	mem[len] = '\0';
	return mem;
}
char *__liballocs_private_strndup(const char *s, size_t n)
{
	size_t maxlen = strlen(s);
	size_t len = (n > maxlen) ? maxlen : n;
	char *mem = __wrap_dlmalloc(len + 1);
	strncpy(mem, s, len);
	mem[len] = '\0';
	return mem;
}
void *__notify_copy(void *dest, const void *src, unsigned long n)
{
	/* We do nothing here. But libcrunch will wrap us. */
	return dest;
}

/* These have hidden visibility */
struct uniqtype *pointer_to___uniqtype__void;
struct uniqtype *pointer_to___uniqtype__signed_char;
struct uniqtype *pointer_to___uniqtype__unsigned_char;
struct uniqtype *pointer_to___uniqtype____PTR_signed_char;
struct uniqtype *pointer_to___uniqtype____PTR___PTR_signed_char;
struct uniqtype *pointer_to___uniqtype__long_unsigned_int;
struct uniqtype *pointer_to___uniqtype__long_int;
struct uniqtype *pointer_to___uniqtype__Elf64_auxv_t;
struct uniqtype *pointer_to___uniqtype____ARR0_signed_char;
struct uniqtype *pointer_to___uniqtype__intptr_t;

/* We want to be called early, but not too early, ecause it might not be safe 
 * to open the -uniqtypes.so handle yet. */
int __liballocs_global_init(void) __attribute__((constructor(103),visibility("protected")));
int __liballocs_global_init(void)
{
	// write_string("Hello from liballocs global init!\n");
	if (__liballocs_is_initialized) return 0; // we are okay

	// don't try more than once to initialize
	static _Bool tried_to_initialize;
	if (tried_to_initialize) return -1;
	tried_to_initialize = 1;
	
	static _Bool trying_to_initialize;
	if (trying_to_initialize) return 0;
	trying_to_initialize = 1;
	
	// print a summary when the program exits
	atexit(print_exit_summary);
	
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
	meta_base = getenv("META_BASE");
	if (!meta_base) meta_base = "/usr/lib/meta";
	meta_base_len = strlen(meta_base);
	
	const char *debug_level_str = getenv("LIBALLOCS_DEBUG_LEVEL");
	if (debug_level_str) __liballocs_debug_level = atoi(debug_level_str);

	if (!orig_dlopen && safe_to_call_malloc) // might have been done by a pre-init call to our preload dlopen
	{
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlopen);
		orig_memmove = dlsym(RTLD_NEXT, "memmove");
		assert(orig_memmove);
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
#ifndef NO_MEMTABLE
	/* Allocate the memtable. 
	 * Assume we don't need to cover addresses >= STACK_BEGIN.
	 * BUT we store vaddrs in the same table, with addresses ORed
	 * with STACK_BEGIN. 
	 * And we store static objects' addres in the same table, with addresses ORed
	 * with STACK_BEGIN<<1. 
	 * So quadruple up the size of the table accordingly.
	 * To avoid the address space getting into a configuration that screws up our
	 * shadow-space arrangement, always place this table at 0x300000000000. */
	__liballocs_allocsmt = MEMTABLE_NEW_WITH_TYPE_AT_ADDR(allocsmt_entry_type, allocsmt_entry_coverage, 
		(void*) 0, (void*) (0x800000000000ul << 2), (const void*) 0x300000000000ul);
	if (__liballocs_allocsmt == MAP_FAILED) abort();
	debug_printf(3, "allocsmt at %p\n", __liballocs_allocsmt);
#endif
	/* Initialize the generic malloc thingy first, because libdl will want to malloc 
	 * when we call it. */
	__generic_malloc_allocator_init();
	int ret_hook = dl_iterate_phdr(load_and_init_all_metadata_for_one_object, NULL);
	
	/* Don't do this. They all have constructors, so it's not necessary.
	 * Moreover, the mmap allocator's constructor 
	 * calls *us* (if we haven't already run) 
	 * because it can't start the systrap before we've loaded all the
	 * metadata for the loaded objects (the "__brk" problem). */
	// __stack_allocator_init();
	// __mmap_allocator_init();
	// __static_allocator_init();
	// __auxv_allocator_init();
	
	// don't init dlbind here -- do it in the mmap allocator, *after* we've started systrap
	//__libdlbind_do_init();
	//__liballocs_rt_uniqtypes_obj = dlcreate("duniqtypes");
	
	trying_to_initialize = 0;
	__liballocs_is_initialized = 1;

	debug_printf(1, "liballocs successfully initialized\n");
	
	return 0;
}

void __liballocs_post_systrap_init(void)
{
	/* For testing, become no-op if systrap was not init'd. */
	if (__liballocs_systrap_is_initialized)
	{
		/* Now we can correctly initialize libdlbind. */
		__libdlbind_do_init();
		__liballocs_rt_uniqtypes_obj = dlcreate("duniqtypes");
		/* Init the other stuff we happen to cache about the object. */
		update_rt_uniqtypes_obj(__liballocs_rt_uniqtypes_obj, NULL);

		/* Now we can grab our uniqtype pointers, or create them. */
		/* Because the Unix linker is broken (see notes below on uniquing),
		 * we can't have uniqueness of anything defined in a preload,
		 * and from a preload we also can't bind to anything defined elsewhere.
		 * So we use the dynamic linker to work around this mess. */
		pointer_to___uniqtype__void = dlsym(RTLD_DEFAULT, "__uniqtype__void");
	#define SIZE_FOR_NRELATED(n) offsetof(struct uniqtype, related) + (n) * sizeof (struct uniqtype_rel_info)
	#define CREATE(varname, symname, nrelated, ...) \
			size_t sz = SIZE_FOR_NRELATED(nrelated); \
			pointer_to_ ## varname = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE); \
			if (!pointer_to_ ## varname) abort(); \
			*(struct uniqtype *) pointer_to_ ## varname = (struct uniqtype) __VA_ARGS__; \
			old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;\
			reloaded = dlbind(__liballocs_rt_uniqtypes_obj, #symname, pointer_to_ ## varname, sz, STT_OBJECT); \
			update_rt_uniqtypes_obj(reloaded, old_base)
		void *reloaded;
		void *old_base;
		if (!pointer_to___uniqtype__void)
		{
			CREATE(__uniqtype__void, __uniqtype__void, 1, {
				.pos_maxoff = 0,
				.un = { _void: { .kind = VOID } }
			});
		}
		pointer_to___uniqtype__signed_char = dlsym(RTLD_DEFAULT, "__uniqtype__signed_char$8");
		if (!pointer_to___uniqtype__signed_char)
		{
			CREATE(__uniqtype__signed_char, __uniqtype__signed_char$8, 1, {
				.pos_maxoff = 1,
				.un = { base: { .kind = BASE, .enc = DW_ATE_signed_char } }
			});
		}
		pointer_to___uniqtype__unsigned_char = dlsym(RTLD_DEFAULT, "__uniqtype__unsigned_char$8");
		if (!pointer_to___uniqtype__unsigned_char)
		{
			CREATE(__uniqtype__unsigned_char, __uniqtype__unsigned_char$8, 1, {
				.pos_maxoff = 1,
				.un = { base: { .kind = BASE, .enc = DW_ATE_unsigned_char } }
			});
		}

		if (!(pointer_to___uniqtype__unsigned_char->related[0].un.t.ptr)) pointer_to___uniqtype__unsigned_char->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__signed_char } } };
		if (!(pointer_to___uniqtype__signed_char->related[0].un.t.ptr)) pointer_to___uniqtype__signed_char->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__unsigned_char } } };
		
		pointer_to___uniqtype__long_unsigned_int = dlsym(RTLD_DEFAULT, "__uniqtype__uint$64");
		if (!pointer_to___uniqtype__long_unsigned_int)
		{
			CREATE(__uniqtype__long_unsigned_int, __uniqtype__uint$64, 1, {
				.pos_maxoff = 8,
				.un = { base: { .kind = BASE, .enc = DW_ATE_unsigned } }
			});
		}
		pointer_to___uniqtype__long_int = dlsym(RTLD_DEFAULT, "__uniqtype__int$64");
		if (!pointer_to___uniqtype__long_int)
		{
			CREATE(__uniqtype__long_int, __uniqtype__int$64, 1, {
				.pos_maxoff = 8,
				.un = { base: { .kind = BASE, .enc = DW_ATE_signed } }
			});
		}

		if (!(pointer_to___uniqtype__long_unsigned_int->related[0].un.t.ptr)) pointer_to___uniqtype__long_unsigned_int->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__long_int } } };
		if (!(pointer_to___uniqtype__long_int->related[0].un.t.ptr)) pointer_to___uniqtype__long_int->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__long_unsigned_int } } };

		pointer_to___uniqtype____PTR_signed_char = dlsym(RTLD_DEFAULT, "__uniqtype____PTR_signed_char$8");
		if (!pointer_to___uniqtype____PTR_signed_char)
		{
			CREATE(__uniqtype____PTR_signed_char, __uniqtype____PTR_signed_char$8, 1, {
				.pos_maxoff = sizeof (char*),
				.un = { address: { .kind = ADDRESS, .indir_level = 1 } }
			});
			pointer_to___uniqtype____PTR_signed_char->related[0] = (struct uniqtype_rel_info) {
				{ t : { pointer_to___uniqtype__signed_char } }
			};
		}
		pointer_to___uniqtype____PTR___PTR_signed_char = dlsym(RTLD_DEFAULT, "__uniqtype____PTR___PTR_signed_char$8");
		if (!pointer_to___uniqtype____PTR___PTR_signed_char)
		{
			CREATE(__uniqtype____PTR___PTR_signed_char, __uniqtype____PTR___PTR_signed_char$8, 1, {
				.pos_maxoff = sizeof (char**),
				.un = { address: { .kind = ADDRESS, .indir_level = 2 } }
			});
			pointer_to___uniqtype____PTR___PTR_signed_char->related[0] = (struct uniqtype_rel_info) {
				{ t : { pointer_to___uniqtype____PTR_signed_char } }
			};
		}
		pointer_to___uniqtype__Elf64_auxv_t = dlsym(RTLD_DEFAULT, "__uniqtype__Elf64_auxv_t");
		if (!pointer_to___uniqtype__Elf64_auxv_t)
		{
			/* typedef struct {
			  uint64_t a_type;
			  union { uint64_t a_val; } a_un;
			} Elf64_auxv_t; */
			/* This one is tricky because the anonymous union derives its
			 * summary code, hence its identity, from the header file path
			 * where it is defined, usually /usr/include/elf.h.
			 * Since there is only one element in the union, and since we
			 * (if we reach this line) don't have a unique auxv_t definition
			 * in the guest program, we pretend it's just a pair of uint64s. */
			CREATE(__uniqtype__Elf64_auxv_t, __uniqtype__Elf64_auxv_t, 2, {
				.pos_maxoff = 16,
				.un = { composite: { .kind = COMPOSITE, .nmemb = 2, .not_simultaneous = 0 } }
			});
			pointer_to___uniqtype__Elf64_auxv_t->related[0] = (struct uniqtype_rel_info) {
				{ t : { pointer_to___uniqtype__long_unsigned_int } }
			};
			pointer_to___uniqtype__Elf64_auxv_t->related[1] = (struct uniqtype_rel_info) {
				{ t : { pointer_to___uniqtype__long_unsigned_int } }
			};
		}
		pointer_to___uniqtype____ARR0_signed_char = dlsym(RTLD_DEFAULT, "__uniqtype____ARR0_signed_char$8");
		if (!pointer_to___uniqtype____ARR0_signed_char)
		{
			// FIXME: handle this
		}
		pointer_to___uniqtype__intptr_t = dlsym(RTLD_DEFAULT, "__uniqtype__intptr_t");
		if (!pointer_to___uniqtype__intptr_t)
		{
			// FIXME: handle this
		}
#undef CREATE
#undef SIZE_FOR_NRELATED
	}
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
	// FIXME: this has bumped the refcount and we'll never unbump it
	return handle;
}

void *__liballocs_my_metaobj(void) __attribute__((visibility("protected")));
void *__liballocs_my_metaobj(void)
{
	__liballocs_ensure_init();
	return metaobj_handle_for_addr(__builtin_return_address(0));
}

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

liballocs_err_t extract_and_output_alloc_site_and_type(
    struct insert *p_ins,
    struct uniqtype **out_type,
    void **out_site
)
{
	if (!p_ins)
	{
		++__liballocs_aborted_unindexed_heap;
		return &__liballocs_err_unindexed_heap_object;
	}
	void *alloc_site_addr = (void *) ((uintptr_t) p_ins->alloc_site);

	/* Now we have a uniqtype or an allocsite. For long-lived objects 
	 * the uniqtype will have been installed in the heap header already.
	 * This is the expected case.
	 */
	struct uniqtype *alloc_uniqtype;
	if (__builtin_expect(p_ins->alloc_site_flag, 1))
	{
		if (out_site)
		{
			//unsigned short id = (unsigned short) p_ins->un.bits;
			//if (id != (unsigned short) -1)
			//{
			//	const void *allocsite = __liballocs_allocsite_by_id(id);
			//	*out_site = (void*) allocsite;
			//}
			//else 
			*out_site = NULL;
		}
		/* Clear the low-order bit, which is available as an extra flag 
		 * bit. libcrunch uses this to track whether an object is "loose"
		 * or not. Loose objects have approximate type info that might be 
		 * "refined" later, typically e.g. from __PTR_void to __PTR_T.
		 * FIXME: this should just be determined by abstractness of the type. */
		alloc_uniqtype = (struct uniqtype *)((uintptr_t)(p_ins->alloc_site) & ~0x1ul);
	}
	else
	{
		/* Look up the allocsite's uniqtype, and install it in the heap info 
		 * (on NDEBUG builds only, because it reduces debuggability a bit). */
		uintptr_t alloc_site_addr = p_ins->alloc_site;
		void *alloc_site = (void*) alloc_site_addr;
		if (out_site) *out_site = alloc_site;
		struct allocsite_entry *entry = allocsite_to_entry(alloc_site/*, p_ins*/);
		alloc_uniqtype = entry ? entry->uniqtype : NULL;
		/* Remember the unrecog'd alloc sites we see. */
		if (!alloc_uniqtype && alloc_site && 
				!__liballocs_addrlist_contains(&__liballocs_unrecognised_heap_alloc_sites, alloc_site))
		{
			__liballocs_addrlist_add(&__liballocs_unrecognised_heap_alloc_sites, alloc_site);
		}
#ifdef NDEBUG
		// install it for future lookups
		// FIXME: make this atomic using a union
		// Is this in a loose state? NO. We always make it strict.
		// The client might override us by noticing that we return
		// it a dynamically-sized alloc with a uniqtype.
		// This means we're the first query to rewrite the alloc site,
		// and is the client's queue to go poking in the insert.
		p_ins->alloc_site_flag = 1;
		p_ins->alloc_site = (uintptr_t) alloc_uniqtype /* | 0x0ul */;
		/* How do we get the id? Doing a binary search on the by-id spine is
		 * okay because there will be very few of them. We don't want to do
		 * a binary search on the table proper. But that's okay. We get
		 * everything we need. */
		struct allocsites_by_object_base_address_entry *found
		 = __liballocs_find_allocsite_lookup_entry((const void *) alloc_site_addr);
		if (found)
		{
			unsigned short id = found->by_id->start_id + (entry - found->by_id->ptr);
			//p_ins->un.bits = id;
			// what to do with the id?? We have no spare bits...
			// we could scrounge a few but certainly not 16 of them.
			// When we're using a bitmap, we will have the space.
		}
		
#endif
	}

	// if we didn't get an alloc uniqtype, we abort
	if (!alloc_uniqtype) 
	{
		//if (__builtin_expect(k == HEAP, 1))
		//{
			++__liballocs_aborted_unrecognised_allocsite;
		//}
		//else ++__liballocs_aborted_stack;
			
		/* We used to do this in clear_alloc_site_metadata in libcrunch... 
		 * In cases where heap classification failed, we null out the allocsite 
		 * to avoid repeated searching. We only do this for non-debug
		 * builds because it makes debugging a bit harder.
		 * NOTE that we don't want the insert to look like a deep-index
		 * terminator, so we set the flag.
		 */
		if (p_ins)
		{
	#ifdef NDEBUG
			p_ins->alloc_site_flag = 1;
			p_ins->alloc_site = 0;
	#endif
			assert(INSERT_DESCRIBES_OBJECT(p_ins));
			assert(!INSERT_IS_NULL(p_ins));
		}
			
		return &__liballocs_err_unrecognised_alloc_site;;
	}
	// else output it
	if (out_type) *out_type = alloc_uniqtype;
	
	/* return success */
	return NULL;
}

#ifdef __liballocs_get_base
#undef __liballocs_get_base
#endif
void *
__liballocs_get_alloc_base(void *obj)
{
	const void *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, &out,
		NULL, NULL, NULL);
	if (err) return NULL;
	return (void*) out;
}
#ifdef __liballocs_get_alloc_base
#undef __liballocs_get_alloc_base
#endif
void *__liballocs_get_alloc_base(void *obj) __attribute__((alias("__liballocs_get_base")));

void *
__liballocs_get_alloc_base_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num)
{
	const void *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, out_a, &out,
		NULL, NULL, NULL);
	if (err) return NULL;
	*out_num = pageindex[PAGENUM(obj)]; /* FIXME: should also check it's precise */
	return (void*) out;
}

#ifdef __liballocs_get_type
#undef __liballocs_get_type
#endif
struct uniqtype * 
__liballocs_get_type(void *obj)
{
	struct uniqtype *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		NULL, &out, NULL);
	if (err) return NULL;
	return out;
}
#ifdef __liballocs_get_alloc_type
#undef __liballocs_get_alloc_type
#endif
void *__liballocs_get_alloc_type(void *obj) __attribute__((alias("__liballocs_get_type")));

struct uniqtype *
__liballocs_get_alloc_type_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num)
{
	struct uniqtype *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, out_a, NULL,
		NULL, &out, NULL);
	if (err) return NULL;
	*out_num = pageindex[PAGENUM(obj)]; /* FIXME: should also check it's precise */
	return out;
}

struct uniqtype * 
__liballocs_get_outermost_type(void *obj)
{
	return __liballocs_get_alloc_type(obj);
}

struct uniqtype * 
__liballocs_get_inner_type(void *obj, unsigned skip_at_bottom)
{
	struct allocator *a = NULL;
	const void *alloc_start;
	size_t alloc_size_bytes;
	struct uniqtype *u = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj,
		&a,
		&alloc_start,
		&alloc_size_bytes,
		&u,
		NULL);
	
	if (__builtin_expect(err != NULL, 0)) goto failed;
	unsigned target_offset_within_uniqtype = (char*) obj - (char*) alloc_start;
	if (u->make_precise)
	{
		/* FIXME: should really do a fuller treatment of make_precise, to allow e.g. */
		/* returning a fresh uniqtype into a buffer, and (even) passing mcontext. */
		u = u->make_precise(u,
			NULL, 0,
			(void*) obj, (void*) alloc_start, alloc_size_bytes, __builtin_return_address(0),
			NULL);
		/* FIXME: now ask the meta-alloc protocol to update that object's metadata to this type. */
	}
	
	/* Descend the subobject hierarchy until we can't descend any more. */
	_Bool success = 1;
	struct uniqtype *cur_containing_uniqtype = NULL;
	struct uniqtype_rel_info *cur_contained_pos = NULL;
	while (success)
	{
		success = __liballocs_first_subobject_spanning(
				&target_offset_within_uniqtype, &u, &cur_containing_uniqtype,
				&cur_contained_pos);
	}
	
	return (skip_at_bottom == 0) ? u
		 : (skip_at_bottom == 1) ? cur_containing_uniqtype
		 : NULL; // HACK, horrible, FIXME etc.
failed:
	return NULL;
}

void *
__liballocs_get_alloc_site(void *obj)
{
	const void *alloc_site = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		NULL, NULL, &alloc_site);
	return (void*) alloc_site;
}

unsigned long
__liballocs_get_alloc_size(void *obj)
{
	unsigned long alloc_size;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		&alloc_size, NULL, NULL);
	
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return 0;
	return alloc_size;
}

struct allocator *
__liballocs_get_leaf_allocator(void *obj)
{
	struct allocator *a = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, &a, NULL, 
		NULL, NULL, NULL);
	
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return 0;
	
	return a;
}

struct mapping_entry *__liballocs_get_memory_mapping(const void *obj,
		struct big_allocation **maybe_out_bigalloc)
{
	struct big_allocation *the_bigalloc = __lookup_bigalloc_top_level(obj);
	if (!the_bigalloc) return NULL;
	assert(the_bigalloc->allocated_by == &__mmap_allocator);
	assert(the_bigalloc->meta.what == DATA_PTR);
	struct mapping_sequence *seq = the_bigalloc->meta.un.opaque_data.data_ptr;
	if (!seq)
	{
		/* It's a pool belonging to our own dlmalloc. HMM. Do we pretend it
		 * doesn't exist? */
		return NULL;
	}
	struct mapping_entry *found = __mmap_allocator_find_entry(obj, seq);
	if (found)
	{
		if (maybe_out_bigalloc) *maybe_out_bigalloc = the_bigalloc;
		return found;
	}
	return NULL;
}

/* Utility code. Suspiciously convenient for bzip2. */
int __liballocs_add_type_to_block(void *block, struct uniqtype *t)
{
	struct big_allocation *maybe_the_allocation = NULL;
	struct allocator *a = __liballocs_leaf_allocator_for(block, NULL, &maybe_the_allocation);
	if (!a) return 1;
	struct uniqtype *old_type = NULL;
	void *base;
	size_t sz;
	liballocs_err_t err = a->get_info(/* a, */ block, maybe_the_allocation, &old_type, &base, &sz, NULL);
	if (!old_type) return 2;
	if (old_type->make_precise) old_type = old_type->make_precise(old_type,
		NULL, 0, block, block, sz, __builtin_return_address(0), NULL);
	struct uniqtype *new_type = __liballocs_get_or_create_array_type(t, sz / t->pos_maxoff);
	if (!new_type) return 3;
	struct uniqtype *union_type = __liballocs_get_or_create_union_type(2,
		old_type,
		new_type
    );
	err = a->set_type(/*a, */ maybe_the_allocation, block, union_type);
	assert(!err);
	struct uniqtype *got_t = __liballocs_get_alloc_type(block);
	assert(got_t == union_type);
	return 0;
}

/* Instantiate inlines from liballocs.h. */
extern inline struct liballocs_err *__liballocs_get_alloc_info(const void *obj, 
	struct allocator **out_allocator, const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site);

extern inline _Bool 
__liballocs_find_matching_subobject(unsigned target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, unsigned *last_uniqtype_offset,
		unsigned *p_cumulative_offset_searched,
		struct uniqtype **p_cur_containing_uniqtype,
		struct uniqtype_rel_info **p_cur_contained_pos);

