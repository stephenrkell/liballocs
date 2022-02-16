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
/* Bit of a hack: we don't assume a system-wide 'dwarf.h' and instead vendor
 * our chosen libdwarf. The best way to get at it is still via libdwarfpp. */
#ifndef DWARF_H
#define DWARF_H "dwarf.h"
#endif
#include DWARF_H
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "librunt.h"
#include "maps.h"
#include "relf.h"
#include "systrap.h"
#include "raw-syscalls-defs.h"
#include "liballocs.h"
#include "liballocs_private.h"
#include "allocsites.h"
#include "dlbind.h"

#ifdef _LIBGEN_H
#error "liballocs.c needs GNU basename() so must not include libgen.h"
#endif

void *__liballocs_rt_uniqtypes_obj;
ElfW(Sym) *__liballocs_rt_uniqtypes_dynsym;
ElfW(Word) *__liballocs_rt_uniqtypes_gnu_hash;
unsigned char *__liballocs_rt_uniqtypes_dynstr;

/* FIXME: why is this function necessary?
 * We keep pointers into this object. Why?
 * We use them only in get_type_from_symname,
 * which appears to be just a faster way than fake_dlsym. */
__attribute__((visibility("hidden")))
void
update_rt_uniqtypes_obj(void *handle, void *old_base)
{
	_Bool unchanged_base = (handle == __liballocs_rt_uniqtypes_obj) &&
		(void*) ((struct link_map *) handle)->l_addr == old_base;
	if (!unchanged_base)
	{
		/* FIXME: if we get here, it's bad! Our dlbind stuff just moved.
		 * We really need to fix libdlbind so that this doesn't happen,
		 * i.e. sticking its fingers more deeply into the ld.so. */
		__liballocs_rt_uniqtypes_obj = handle;
		__liballocs_rt_uniqtypes_dynsym = get_dynsym(handle);
		__liballocs_rt_uniqtypes_dynstr = get_dynstr(handle);
		__liballocs_rt_uniqtypes_gnu_hash = get_gnu_hash(handle);
	}
}

static struct uniqtype *
get_type_from_symname(const char *precise_uniqtype_name)
{
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
	if (found) return (struct uniqtype *) found;
	return (struct uniqtype *) dlsym(NULL, precise_uniqtype_name);
}

static
struct uniqtype *
get_or_create_array_type(struct uniqtype *element_t, unsigned array_len)
{
	char precise_uniqtype_name[4096];
	const char *element_name = UNIQTYPE_NAME(element_t); /* gets "simple", not symbol, name */
	if (array_len == UNIQTYPE_ARRAY_LENGTH_UNBOUNDED)
	{
		snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
				"__uniqtype____ARR_%s",
				element_name);
	}
	else
	{
		snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
				"__uniqtype____ARR%d_%s",
				array_len,
				element_name);
	}
	/* FIXME: compute hash code. Should be an easy case. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + 1 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = (array_len == UNIQTYPE_ARRAY_LENGTH_UNBOUNDED)
				? UNIQTYPE_POS_MAXOFF_UNBOUNDED
				: (array_len * element_t->pos_maxoff),
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

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_get_or_create_array_type(struct uniqtype *element_t, unsigned array_len)
{
	if (!element_t || element_t == (void*) -1) return NULL;
	assert(array_len < UNIQTYPE_ARRAY_LENGTH_UNBOUNDED);
	if (element_t->pos_maxoff == 0) return NULL;
	if (element_t->pos_maxoff == UNIQTYPE_POS_MAXOFF_UNBOUNDED) return NULL;
	return get_or_create_array_type(element_t, array_len);
}
struct uniqtype *
__liballocs_get_or_create_unbounded_array_type(struct uniqtype *element_t)
{
	if (!element_t || element_t == (void*) -1) return NULL;
	if (element_t->pos_maxoff == 0) return NULL;
	if (element_t->pos_maxoff == UNIQTYPE_POS_MAXOFF_UNBOUNDED) return NULL;
	return get_or_create_array_type(element_t, UNIQTYPE_ARRAY_LENGTH_UNBOUNDED);
}
struct uniqtype *
__liballocs_get_or_create_flexible_array_type(struct uniqtype *element_t)
{
	assert(element_t);
	if (element_t->pos_maxoff == 0) return NULL;
	if (element_t->pos_maxoff == UNIQTYPE_POS_MAXOFF_UNBOUNDED) return NULL;

	char precise_uniqtype_name[4096];
	const char *element_name = UNIQTYPE_NAME(element_t); /* gets "simple", not symbol, name */
	snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
			"__uniqtype____ARR_%s", element_name);
	/* FIXME: compute hash code. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + 1 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = UNIQTYPE_POS_MAXOFF_UNBOUNDED,
		.un = {
			array: {
				.is_array = 1,
				.nelems = UNIQTYPE_ARRAY_LENGTH_UNBOUNDED
			}
		},
		.make_precise = __liballocs_make_array_precise_with_memory_bounds
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

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_get_or_create_address_type(const struct uniqtype *pointee_t)
{
	assert(pointee_t);

	char precise_uniqtype_name[4096];
	const char *pointee_name = UNIQTYPE_NAME(pointee_t); /* gets "simple", not symbol, name */
	snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
			"__uniqtype____PTR_%s", pointee_name);
	/* FIXME: compute hash code. Should be an easy case. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	int indir_level;
	const struct uniqtype *ultimate_pointee_t;
	if (UNIQTYPE_IS_POINTER_TYPE(pointee_t))
	{
		indir_level = 1 + pointee_t->un.address.indir_level;
		ultimate_pointee_t = UNIQTYPE_ULTIMATE_POINTEE_TYPE(pointee_t);
	}
	else
	{
		indir_level = 1;
		ultimate_pointee_t = pointee_t;
	}

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + 2 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = sizeof(void *),
		.un = {
			address: {
				.kind = ADDRESS,
				.indir_level = indir_level,
				.genericity = 0,
			}
		},
		.make_precise = NULL
	};
	allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
		.un = { t: { .ptr = (struct uniqtype *) pointee_t } }
	};
	allocated_uniqtype->related[1] = (struct uniqtype_rel_info) {
		.un = { t: { .ptr = (struct uniqtype *) ultimate_pointee_t } }
	};
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_get_or_create_subprogram_type(struct uniqtype *return_type, unsigned narg, struct uniqtype **arg_types)
{
	assert(return_type);
	assert(narg == 0 || arg_types);

	char precise_uniqtype_name[4096];
	memcpy(precise_uniqtype_name, "__uniqtype____FUN_FROM_", sizeof "__uniqtype____FUN_FROM_");
	unsigned uniqtype_name_pos = sizeof "__uniqtype____FUN_FROM_" - 1;
	for (unsigned i = 0; i < narg; ++i)
	{
		char *uniqtype_arg_name = precise_uniqtype_name + uniqtype_name_pos;
		unsigned bufsz = sizeof precise_uniqtype_name - uniqtype_name_pos;
		uniqtype_name_pos += snprintf(uniqtype_arg_name, bufsz, "__ARG%d_%s", i, UNIQTYPE_NAME(arg_types[i]));
	}

	char *uniqtype_ret_name = precise_uniqtype_name + uniqtype_name_pos;
	unsigned bufsz = sizeof precise_uniqtype_name - uniqtype_name_pos;
	snprintf(uniqtype_ret_name, bufsz, "__FUN_TO_%s", UNIQTYPE_NAME(return_type));

	/* FIXME: compute hash code. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + (1+narg) * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = UNIQTYPE_POS_MAXOFF_UNBOUNDED,
		.un = {
			subprogram: {
				.kind = SUBPROGRAM,
				.narg = narg,
				.nret = 1,
				.is_va = 0,
				.cc = 0, // What is the good calling convention choice ?
			}
		},
		.make_precise = NULL,
	};
	allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
		.un = {
			t: {
				.ptr = return_type
			}
		}
	};
	for (unsigned i = 0; i < narg; i++)
	{
		allocated_uniqtype->related[i+1] = (struct uniqtype_rel_info) {
			.un = {
				t: {
					.ptr = arg_types[i]
				}
			}
		};
	}
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
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
	// assert(precise_size % element_t->pos_maxoff == 0); // too strict?
	/* YES it's too strict. For why, see the note under heap_index.h's 'sizes' diagram. */
	
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

#ifdef USE_FAKE_LIBUNWIND
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

FILE *stream_err __attribute__((visibility("hidden")));

struct addrlist __liballocs_unrecognised_heap_alloc_sites = { 0, 0, NULL };

const char *meta_base __attribute__((visibility("hidden")));
unsigned meta_base_len __attribute__((visibility("hidden")));

int __liballocs_debug_level;
_Bool __liballocs_is_initialized;

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
	fprintf(get_stream_err(), "uniqtype addr %p, name %s, size %d bytes\n",
		t, UNIQTYPE_NAME(t), t->pos_maxoff);
	fflush(get_stream_err());
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
	Dl_info i = dladdr_with_cache((char *)u + 1);
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


_Bool done_main_init __attribute__((visibility("hidden")));
void __liballocs_main_init(void) __attribute__((constructor(101),visibility("protected")));
// NOTE: runs *before* the constructor in preload.c
__attribute__((constructor(101),visibility("protected")))
void __liballocs_main_init(void)
{
	assert(!done_main_init);

	/* This is a dummy: we choose not to initialise anything at this point, for now.
	 * PROBLEM: gcc optimizes the constructor out! Because after eliminating done_init,
	 * we have no observable effect, it concludes there's no need to put us in
	 * .init_array. This rightly fails our 'constructor priority' check. We make the
	 * done_main_init non-static as a workaround. */

	done_main_init = 1;
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
const char *__liballocs_meta_libfile_name(const char *objname)
{
	return meta_libfile_name(objname);
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

int load_and_init_all_metadata_for_one_object(struct dl_phdr_info *info, size_t size, void *data)
{
	void *meta_handle = NULL;
	void **maybe_out_handle = (void**) data;
	// get the canonical libfile name
	const char *canon_objname = dynobj_name_from_dlpi_name(info->dlpi_name, (void *) info->dlpi_addr);
	if (!canon_objname) return 0;
	_Bool is_exe = (info->dlpi_addr == 0) || (0 == strcmp(canon_objname, get_exe_fullname()));
	const char *canon_basename = basename(canon_objname);
	_Bool is_libc = ((0 == strncmp(canon_basename, "libc", 4))
				&& (canon_basename[4] == '-' || canon_basename[4] == '.'));

	// skip objects that are themselves meta objects (i.e. are under the meta_base path)
	// FIXME: what about embedded meta objects?
	assert(meta_base);
	assert(meta_base_len);
	if (0 == strncmp(canon_objname, meta_base, meta_base_len)) return 0;
	
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
		fprintf(get_stream_err(), "====================================================\n");
		fprintf(get_stream_err(), "liballocs summary: \n");
		fprintf(get_stream_err(), "----------------------------------------------------\n");
		fprintf(get_stream_err(), "queries aborted for unknown storage:       % 9ld\n", __liballocs_aborted_unknown_storage);
		fprintf(get_stream_err(), "queries handled by static case:            % 9ld\n", __liballocs_hit_static_case);
		fprintf(get_stream_err(), "queries handled by stack case:             % 9ld\n", __liballocs_hit_stack_case);
		fprintf(get_stream_err(), "queries handled by heap case:              % 9ld\n", __liballocs_hit_heap_case);
		fprintf(get_stream_err(), "----------------------------------------------------\n");
		fprintf(get_stream_err(), "queries aborted for unindexed heap:        % 9ld\n", __liballocs_aborted_unindexed_heap);
		fprintf(get_stream_err(), "queries aborted for unknown heap allocsite:% 9ld\n", __liballocs_aborted_unrecognised_allocsite);
		fprintf(get_stream_err(), "queries aborted for unknown stackframes:   % 9ld\n", __liballocs_aborted_stack);
		fprintf(get_stream_err(), "queries aborted for unknown static obj:    % 9ld\n", __liballocs_aborted_static);
		fprintf(get_stream_err(), "====================================================\n");
		for (unsigned i = 0; i < __liballocs_unrecognised_heap_alloc_sites.count; ++i)
		{
			if (i == 0)
			{
				fprintf(get_stream_err(), "Saw the following unrecognised heap alloc sites: \n");
			}
			fprintf(get_stream_err(), "%p (%s)\n", __liballocs_unrecognised_heap_alloc_sites.addrs[i], 
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
				fwrite(buffer, 1, bytes, get_stream_err());
			}
		}
		else fprintf(get_stream_err(), "Couldn't read from smaps!\n");
	}
}

/* __private_malloc is defined by our Makefile as __wrap_dlmalloc.
 * Since dlmalloc does not include a strdup, we need to define
 * that explicitly. */
char *__liballocs_private_strdup(const char *s)
{
	size_t len = strlen(s) + 1;
	char *mem = __private_malloc(len);
	if (!mem) return NULL;
	return memcpy(mem, s, len);
}
char *__private_strdup(const char *s) __attribute__((alias("__liballocs_private_strdup")));
char *__liballocs_private_strndup(const char *s, size_t n)
{
	size_t maxlen = strlen(s);
	size_t len = (n > maxlen ? maxlen : n) + 1;
	char *mem = __private_malloc(len);
	if (!mem) return NULL;
	return memcpy(mem, s, len);
}
char *__private_strndup(const char *s, size_t n) __attribute__((alias("__liballocs_private_strndup")));

/* These have hidden visibility */
struct uniqtype *pointer_to___uniqtype__void;
struct uniqtype *pointer_to___uniqtype____uninterpreted_byte;
struct uniqtype *pointer_to___uniqtype__signed_char;
struct uniqtype *pointer_to___uniqtype__unsigned_char;
struct uniqtype *pointer_to___uniqtype____uninterpreted_byte;
struct uniqtype *pointer_to___uniqtype____PTR_signed_char;
struct uniqtype *pointer_to___uniqtype____PTR___PTR_signed_char;
struct uniqtype *pointer_to___uniqtype__long_unsigned_int;
struct uniqtype *pointer_to___uniqtype__long_int;
struct uniqtype *pointer_to___uniqtype__Elf64_auxv_t;
struct uniqtype *pointer_to___uniqtype____ARR0_signed_char;
struct uniqtype *pointer_to___uniqtype__intptr_t;

__attribute__((visibility("hidden")))
FILE *get_stream_err(void)
{
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
	return stream_err;
}

/* We want to be called early, but not too early, because it might not be safe 
 * to open the -uniqtypes.so handle yet. */
int __liballocs_global_init(void) __attribute__((constructor(103),visibility("protected")));
int ( __attribute__((constructor(103))) __liballocs_global_init)(void)
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
	/* Initialize the generic malloc thingy first, because libdl will want to malloc 
	 * when we call it. */
	__generic_malloc_allocator_init();
	__mmap_allocator_init();
	__static_file_allocator_init();
	
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
		if (!__liballocs_rt_uniqtypes_obj)
		{
			const char msg[] = "dlcreate() of uniqtypes DSO failed\n";
			raw_write(2, msg, sizeof msg);
			abort();
		}

		/* Now we can grab our uniqtype pointers, or create them. */
		/* Because the Unix linker is broken (see notes below on uniquing),
		 * we can't have uniqueness of anything defined in a preload,
		 * and from a preload we also can't bind to anything defined elsewhere.
		 * So we use the dynamic linker to work around this mess. */
		pointer_to___uniqtype__void = dlsym(RTLD_DEFAULT, "__uniqtype__void");
	#define SIZE_FOR_NRELATED(n) offsetof(struct uniqtype, related) + (n) * sizeof (struct uniqtype_rel_info)
	#define CREATE(varname, symstr, nrelated, ...) \
			size_t sz = SIZE_FOR_NRELATED(nrelated); \
			pointer_to_ ## varname = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE); \
			if (!pointer_to_ ## varname) abort(); \
			*(struct uniqtype *) pointer_to_ ## varname = (struct uniqtype) __VA_ARGS__; \
			old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;\
			dlbind(__liballocs_rt_uniqtypes_obj, symstr, pointer_to_ ## varname, sz, STT_OBJECT);
		void *reloaded;
		void *old_base;
		if (!pointer_to___uniqtype__void)
		{
			CREATE(__uniqtype__void, "__uniqtype__void", 1, {
				.pos_maxoff = 0,
				.un = { _void: { .kind = VOID } }
			});
		}
		pointer_to___uniqtype____uninterpreted_byte = dlsym(RTLD_DEFAULT, "__uniqtype____uninterpreted_byte");
		if (!pointer_to___uniqtype____uninterpreted_byte)
		{
			CREATE(__uniqtype____uninterpreted_byte, "__uniqtype____uninterpreted_byte", 1, {
				.pos_maxoff = 1,
				.un = { base: { .kind = BASE, .enc = 0 } }
			});
		}
		pointer_to___uniqtype__signed_char = dlsym(RTLD_DEFAULT, "__uniqtype__signed_char$$8");
		if (!pointer_to___uniqtype__signed_char)
		{
			CREATE(__uniqtype__signed_char, "__uniqtype__signed_char$$8", 1, {
				.pos_maxoff = 1,
				.un = { base: { .kind = BASE, .enc = DW_ATE_signed_char } }
			});
		}
		pointer_to___uniqtype__unsigned_char = dlsym(RTLD_DEFAULT, "__uniqtype__unsigned_char$$8");
		if (!pointer_to___uniqtype__unsigned_char)
		{
			CREATE(__uniqtype__unsigned_char, "__uniqtype__unsigned_char$$8", 1, {
				.pos_maxoff = 1,
				.un = { base: { .kind = BASE, .enc = DW_ATE_unsigned_char } }
			});
		}
		pointer_to___uniqtype____uninterpreted_byte = dlsym(RTLD_DEFAULT, "__uniqtype____uninterpreted_byte");
		if (!pointer_to___uniqtype____uninterpreted_byte)
		{
			CREATE(__uniqtype____uninterpreted_byte, "__uniqtype____uninterpreted_byte", 1, {
				.pos_maxoff = 1,
				.un = { base: { .kind = BASE, .enc = 0 } }
			});
		}

		if (!(pointer_to___uniqtype__unsigned_char->related[0].un.t.ptr)) pointer_to___uniqtype__unsigned_char->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__signed_char } } };
		if (!(pointer_to___uniqtype__signed_char->related[0].un.t.ptr)) pointer_to___uniqtype__signed_char->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__unsigned_char } } };
		
		pointer_to___uniqtype__long_unsigned_int = dlsym(RTLD_DEFAULT, "__uniqtype__uint$$64");
		if (!pointer_to___uniqtype__long_unsigned_int)
		{
			CREATE(__uniqtype__long_unsigned_int, "__uniqtype__uint$$64", 1, {
				.pos_maxoff = 8,
				.un = { base: { .kind = BASE, .enc = DW_ATE_unsigned } }
			});
		}
		pointer_to___uniqtype__long_int = dlsym(RTLD_DEFAULT, "__uniqtype__int$$64");
		if (!pointer_to___uniqtype__long_int)
		{
			CREATE(__uniqtype__long_int, "__uniqtype__int$$64", 1, {
				.pos_maxoff = 8,
				.un = { base: { .kind = BASE, .enc = DW_ATE_signed } }
			});
		}

		if (!(pointer_to___uniqtype__long_unsigned_int->related[0].un.t.ptr)) pointer_to___uniqtype__long_unsigned_int->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__long_int } } };
		if (!(pointer_to___uniqtype__long_int->related[0].un.t.ptr)) pointer_to___uniqtype__long_int->related[0] = 
			(struct uniqtype_rel_info) { { t : { pointer_to___uniqtype__long_unsigned_int } } };

		pointer_to___uniqtype____PTR_signed_char = dlsym(RTLD_DEFAULT, "__uniqtype____PTR_signed_char$$8");
		if (!pointer_to___uniqtype____PTR_signed_char)
		{
			CREATE(__uniqtype____PTR_signed_char, "__uniqtype____PTR_signed_char$$8", 1, {
				.pos_maxoff = sizeof (char*),
				.un = { address: { .kind = ADDRESS, .indir_level = 1 } }
			});
			pointer_to___uniqtype____PTR_signed_char->related[0] = (struct uniqtype_rel_info) {
				{ t : { pointer_to___uniqtype__signed_char } }
			};
		}
		pointer_to___uniqtype____PTR___PTR_signed_char = dlsym(RTLD_DEFAULT, "__uniqtype____PTR___PTR_signed_char$$8");
		if (!pointer_to___uniqtype____PTR___PTR_signed_char)
		{
			CREATE(__uniqtype____PTR___PTR_signed_char, "__uniqtype____PTR___PTR_signed_char$$8", 1, {
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
			CREATE(__uniqtype__Elf64_auxv_t, "__uniqtype__Elf64_auxv_t", 2, {
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
		pointer_to___uniqtype____ARR0_signed_char = dlsym(RTLD_DEFAULT, "__uniqtype____ARR0_signed_char$$8");
		if (!pointer_to___uniqtype____ARR0_signed_char)
		{
			CREATE(__uniqtype____ARR0_signed_char, "__uniqtype____ARR0_signed_char", 2, {
				.pos_maxoff = UNIQTYPE_POS_MAXOFF_UNBOUNDED,
				.un = { array: { .is_array = 1, .nelems = UNIQTYPE_ARRAY_LENGTH_UNBOUNDED } }
			});
			pointer_to___uniqtype____ARR0_signed_char->related[0] = (struct uniqtype_rel_info) {
				{ t : { pointer_to___uniqtype__signed_char } }
			};
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
	dlclose(handle); // unbump refcount; it will remain at least 1
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
		struct allocsite_entry *entry = __liballocs_find_allocsite_entry_at(alloc_site);
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
		allocsite_id_t allocsite_id = __liballocs_allocsite_id((const void *) alloc_site_addr);
		if (allocsite_id != (allocsite_id_t) -1)
		{
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
#ifdef __liballocs_get_alloc_base
#undef __liballocs_get_alloc_base
#endif
void *
__liballocs_get_base(void *obj)
{
	const void *out;
	/* Try the cache first. */
	struct __liballocs_memrange_cache_entry_s *hit =
		__liballocs_memrange_cache_lookup_notype(&__liballocs_ool_cache,
			obj, 0);
	/* We only want depth-0 cached memranges, i.e. leaf-level. */
	if (hit && hit->depth == 0) return (void*) hit->obj_base;
	/* No hit, so do the full query. */
	size_t sz = 0;
	struct uniqtype *t = NULL;
	struct allocator *a = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, &a, &out,
		&sz, NULL, NULL);
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return NULL;
	/* We can cache the alloc base and size. */
	if (a && a->is_cacheable) __liballocs_cache_with_type(&__liballocs_ool_cache,
		out, (char*) out + sz, t ? t : pointer_to___uniqtype____uninterpreted_byte,
		0, 1, out);
	return (void*) out;
}
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
struct uniqtype *__liballocs_get_alloc_type(void *obj) __attribute__((alias("__liballocs_get_type")));

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
alloc_get_type(void *obj) __attribute__((alias("__liballocs_get_outermost_type")));

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

void
__liballocs_set_alloc_type(void *obj, const struct uniqtype *type)
{
	struct big_allocation *maybe_the_allocation;
	struct allocator *a = __liballocs_leaf_allocator_for(obj,
		&maybe_the_allocation);
	if (!a || !a->set_type)
	{
		debug_printf(1, "Failed to set type for object at %p", obj);
		return;
	}
	a->set_type(maybe_the_allocation, obj, (struct uniqtype *) type);
	assert(__liballocs_get_alloc_type(obj) == type);
}

const void *
__liballocs_get_alloc_site(void *obj)
{
	const void *alloc_site = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		NULL, NULL, &alloc_site);
	return (void*) alloc_site;
}
const void *
alloc_get_site(void *obj) __attribute__((alias("__liballocs_get_alloc_site")));

unsigned long
__liballocs_get_alloc_size(void *obj)
{
	unsigned long alloc_size;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		&alloc_size, NULL, NULL);
	
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return 0;
	return alloc_size;
}
unsigned long
alloc_get_size(void *obj) __attribute__((alias("__liballocs_get_alloc_size")));

struct allocator *
__liballocs_get_leaf_allocator(void *obj)
{
	struct allocator *a = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, &a, NULL, 
		NULL, NULL, NULL);
	
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return 0;
	
	return a;
}
struct allocator *
alloc_get_allocator(void *obj) __attribute__((alias("__liballocs_get_leaf_allocator")));

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
	struct big_allocation *b = NULL;
	struct allocator *a = __liballocs_leaf_allocator_for(block, &b);
	if (!a) return 1;
	struct uniqtype *old_type = NULL;
	void *base;
	size_t sz;
	/* CARE: the bigalloc 'b' is not necessarily the allocation. It might
	 * be the containing bigalloc (test: b->allocated_by == a). Some calls
	 * want the bigalloc whether or not it's the allocation, and some
	 * calls are happy with NULL and want it only if it *is* the allocation.
	 * get_info really wants the bigalloc. */
	liballocs_err_t err = a->get_info(block, b, &old_type, &base, &sz, NULL);
	if (!old_type) return 2;
	if (old_type->make_precise) old_type = old_type->make_precise(old_type,
		NULL, 0, block, block, sz, __builtin_return_address(0), NULL);
	struct uniqtype *new_type = __liballocs_get_or_create_array_type(t, sz / t->pos_maxoff);
	if (!new_type) return 3;
	struct uniqtype *union_type = __liballocs_get_or_create_union_type(2,
		old_type,
		new_type
	);
	/* set_type is happy with NULL */
	err = a->set_type((b->allocated_by == a) ? b : NULL, block, union_type);
	assert(!err);
	struct uniqtype *got_t = __liballocs_get_alloc_type(block);
	assert(got_t == union_type);
	return 0;
}

/* Ways to walk allocations:
 *
 * - each allocator may provide a walk_allocations function
 *   which walks (exactly) its allocations as contained within
 *   a given containment context (bigalloc, mostly -- see below about uniqtype).
 *      - if there are 'imposed child bigallocs', i.e. child
 *        bigallocs that are not allocated_by that allocator,
 *        it will *not* walk them. These are rare... 'stackframe
 *        within auxv' is probably the only case to date.
 * - the *top-level* walk_allocations function, below, can walk
 *   allocations in any containment context (by delegating to the
 *   appropriate allocator, but also optionally *will* walk imposed
 *   children, if given the right flag.
 * - iterating contained subobjects within a uniqtype is currently
 *   a separate case but should eventually become just another allocator.
 * Given a bigalloc, there are two kinds of allocation to walk:
 * child bigallocs, and suballocator chunks. If it's the suballocator,
 * we need to ask it to walk *its* allocations. The allocator API
 * also uses ALLOC_REFLECTIVE_API so we need the top-level API here
 * to be uniform.
 *
 * Is there an invariant that says we can't have both child allocs
 * and bigallocs? No, actually we CAN because a malloc chunk can be
 * promoted to a bigalloc if it gets suballocated-from. So we may
 * need to walk both.
 *
 * Now think ahead to a near future where we have __uniqtype_allocator.
 * Given a uniqtype, the allocations to walk are its subobjects.
 * There is no bigalloc; there is a uniqtype *and* a base address.
 * So we pass two pointers; in the bigalloc case we pass some flags.
 * Since uniqtypes are always aligned addresses, we ensure all 'flags'
 * have LSB set, and one or more flags is compulsory, so we can
 * disambiguate a bigalloc call even in this top-level function.
 */
int __liballocs_walk_allocations(
	struct alloc_containment_ctxt *cont,
	walk_alloc_cb_t *cb,
	void *arg,
	void *maybe_range_begin,
	void *maybe_range_end
)
{
	/* If we are asked to walk children of a bigalloc,
	 * not of a uniqtype, then
	 *
	 * - the bigalloc may have a type, in which case
	 *    - it must NOT have suballocation
	 *    - it must NOT have child allocations
	 *    - we delegate to the uniqtype walker and that's it
	 *    - FIXME: I don't think we do that right now. Unless
	 *      our bou is a uniqtype... can we represent the context
	 *      as "the whole of this bigalloc"?
	 * - the bigalloc may have suballocations *and* children
	 *    - flags determine which one(s) we walk (can be both)
	 * - the bigalloc may have only children
	 *    - we still honor the flags
	 *
	 * Given just an alloc_containment_ctxt, where do we get
	 * our flags from? We can include flags in the uniqtype
	 * as it is always 8-byte-aligned. */
	assert(cont);
	uintptr_t flags = (cont->bigalloc_or_uniqtype & UNIQTYPE_PTR_MASK_FLAGS);
	/* Currently we
	 * - walk child bigallocs (if asked), then
	 * - walk suballocator allocations (if asked), then
	 * - walk uniqtype substructure.
	 * BUT
	 * - we want a depth-first walk to be possible
	 *   which visits allocations at any depth in increasing address order.
	 * - That means we MAY need to interleave the bigalloc-walking
	 *   with the suballoc-walking.
	 *   One way: accept a range, and walk within that range; use bigalloc start/end to break up.
	 * - SANITY: when do we have a mix of child bigallocs and ordinary allocs?
	 *
	 * The wackiest cases are
	 * - promoted malloc chunks, which may or may not be suballoc-d from
	 * - auxv containing the initial stack, rather
	 *   than the other way around, which was so that stackframe could be
	 *   stack's suballocator.
	 * - packed_sequence instances -- these may have a type, but also have a
	 *   bigalloc that knows more fine-grained types. The allocator may not
	 *   know about them.
	 
	 * From auxv.c:
	 * Don't record the stack allocator as a suballocator; child bigallocs
	 * fill this function for us. Suballocators only make sense at the leaf
	 * level, when you can say "anything smaller than us is managed by this
	 * allocator". Child bigallocs can be sized precisely, leaving our auxv
	 * "crack" modelled with precise bounds, which is exactly what we need 
	 * as the auxv is often less than a whole page. The stack will always be
	 * a bigalloc, and having it as our child is how we carve out this
	 * not-page-boundaried region as the auxv.

	 * So here we have the auxv mostly-covered by a child bigalloc that is
	 * the stack, which is suballocated by the stackframe. If we wanted to
	 * walk the auxv depth-first, what would we need to do?
	 * And let's imagine (falsely) that there is stuff at the end of the auxv
	 * too.
	 * We would need exactly to interleave the walking of child small allocs
	 * with the walking of the child bigalloc. Using the 'range' arguments is
	 * probably the right thing here. Remember that 'walk_allocations' is a
	 * primitive which allocators can reasonably provide, but which client code
	 * is unlikely to call directly - walk_df is much more useful.
	 *
	 * So what about *non*-imposed child bigallocs? We seem to be expecting the
	 * 'promoting' allocator to notice that there's a bigalloc and interleave
	 * that. But is that reasonable? If it promoted the chunk, then fine. But
	 * we seem to have cases where that's not so, e.g. in the ELF elements
	 * allocator. There we try to promote a section simply by creating a new
	 * bigalloc that hangs in the relevant place. But it doesn't show up as
	 * imposed... why not? That would mean
	 * b->suballocator || child->allocated_by != b->suballocator
	 * ... but what is b? it's the ELF file bigalloc, and its suballocator is __elf_elements_allocator
	 * ... and 'child' is the new bigalloc for the section, and allocated_by is ^^ that too.
	 * So it's not considered imposed.
	 */
	int ret = 0;
	void *walked_up_to = maybe_range_begin ?: cont->container_base;
	if (BOU_IS_BIGALLOC(cont->bigalloc_or_uniqtype))
	{
		struct big_allocation *b = BOU_BIGALLOC(cont->bigalloc_or_uniqtype);
		assert(b->begin == cont->container_base);
		struct alloc_containment_ctxt new_cont = {
			.container_base = b->begin,
			.bigalloc_or_uniqtype = (uintptr_t) b /* no flags set */,
			.maybe_containee_coord = 1,
			.encl = cont,
			.encl_depth = cont->encl_depth + 1
		};
		if (flags & ALLOC_WALK_BIGALLOC_IMPOSED_CHILDREN)
		{
			// we are asked to walk the allocations under b in the allocation tree
			/* To walk the imposed children, we need to divide the range up into
			 * chunks for each imposed child. FIXME: this is racy, but imposed
			 * children are rare and come/go/move even more rarely. */
			for (struct big_allocation *child = b->first_child; child;
				walked_up_to = child->end,
				child = child->next_sib,
				++new_cont.maybe_containee_coord)
			{
				// skip any that don't fall within our range
				if ((uintptr_t) child->end <= (uintptr_t) walked_up_to) continue;
				if (maybe_range_end && (uintptr_t) child->begin > (uintptr_t) maybe_range_end) continue;
				if (!b->suballocator || child->allocated_by != b->suballocator)
				{
					// it's an imposed child
					// 1. walk non-i.c. suballocations
					// NOTE: this will override the 'coord' as it calls the cb
					// for its own children; we only pass coords for bigallocs
					// or for uniqtype containeds
					ret = b->suballocator->walk_allocations(&new_cont, cb, arg,
						walked_up_to, child->begin);
					if (ret != 0) return ret;
					// 2. walk the i.c.
					ret = cb(b, b->begin, NULL /* FIXME: type */, NULL /* FIXME: allocsite */,
						&new_cont, arg);
					if (ret != 0) return ret;
				}
			}
		}
		// now there is a range, either from the beginning or from the last i.c.,
		// to the end, that we haven't walked yet and which by definition only contains normal children
		ret = b->suballocator->walk_allocations(&new_cont, cb, arg,
			walked_up_to, maybe_range_end ?: b->end);
		return ret;
	}
	// if we get here, then
	// we're just a thing with a type, and want to walk its substructure
	// eventually: delegate to the uniqtype allocator (more uniform)
	// for now: use UNIQTYPE_FOR_EACH_SUBOBJECT
#if 0
	return __uniqtype_allocator_walk_allocations(...);
#else
	/* We've ruled out the bigalloc case, so we're being asked
	 * to iterate through subobjects given a uniqtype. */
	// for now, use our iteration macro
#define suballoc_thing(_i, _t, _offs) do { \
	cont->maybe_containee_coord = (_i) + 1; \
	void *base = (void*)(((uintptr_t) cont->container_base) + (_offs)); \
	ret = cb(NULL, base, \
	   (_t), \
	   NULL /* allocsite */, \
	   cont, \
	   arg); \
	if (ret != 0) return ret; \
} while (0)
	struct uniqtype *u = BOU_UNIQTYPE(cont->bigalloc_or_uniqtype);
	if (UNIQTYPE_HAS_SUBOBJECTS(u))
	{
		UNIQTYPE_FOR_EACH_SUBOBJECT(u, suballoc_thing);
	}
	return ret;
#endif
}

int
alloc_walk_allocations(struct alloc_containment_ctxt *cont,
	walk_alloc_cb_t *cb,
	void *arg,
	void *maybe_range_begin,
	void *maybe_range_end) __attribute__((alias("__liballocs_walk_allocations")));

struct walk_df_arg
{
	walk_alloc_cb_t *cb;
	void *arg;
};
static int walk_one_df_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
		struct alloc_containment_ctxt *cont, void *walk_df_arg_as_void)
{
	/* As a way to signal "skip this subtree" as distinct from
	 * "terminate the whole walk here", return values mean
	 *     0: carry on
	 *    -1: skip the subtree
	 *  else: return immediately
	 */
	// If the allocating allocator says there's no bigalloc, it doesn't
	// mean there isn't. It just means it doesn't know or care. We do
	// because we don't want to double-walk the substructure (once
	// with uniqtype, once with the bigalloc child structure).
	if (t && BOU_IS_BIGALLOC(cont->bigalloc_or_uniqtype))
	{
		for (struct big_allocation *child = BOU_BIGALLOC(cont->bigalloc_or_uniqtype)->first_child;
			child;
			child = child->next_sib)
		{
			// does this child alloc actually describe the alloc
			// in question? e.g. if it was just hung on there.
			if (child->begin == obj)
			{
				maybe_the_allocation = child;
				// this will force us to pass a BOU_BIGALLOC not a BOU_UNIQTYPE
				// wheren we call __liballocs_walk_allocations below
				break;
			}
		}
	}
	
	struct walk_df_arg *arg = (struct walk_df_arg *) walk_df_arg_as_void;
	// First, we call back for the present thing (i.e. we are pre-order)
	int ret = arg->cb(maybe_the_allocation, obj, t, allocsite, cont, arg->arg);
	if (ret == -1) return 0; // tell the caller to carry on *its* traversal
	if (ret) return ret;     // stop immdiately
	// Now... is this a thing that might contain things?
	if (!maybe_the_allocation && !t) return 0;
	struct alloc_containment_ctxt new_scope = {
		.container_base = obj,
		.bigalloc_or_uniqtype = (uintptr_t)((void*)maybe_the_allocation ?: (void*)t),
		.maybe_containee_coord = 0,
		.encl = cont,
		.encl_depth = cont->encl_depth + 1
	};
	return __liballocs_walk_allocations(&new_scope, walk_one_df_cb, arg, NULL, NULL);
}
int __liballocs_walk_allocations_df(
	struct alloc_containment_ctxt *cont,
	walk_alloc_cb_t *cb,
	void *arg
)
{
	/* We walk the tree rooted at scope 'cont',
	 * by walking the allocations with a callback
	 * that walks deeper. */
	struct walk_df_arg walk_df_arg = {
		.cb = cb,
		.arg = arg
	};
	return __liballocs_walk_allocations(
		cont,
		walk_one_df_cb,
		&walk_df_arg,
		NULL,
		NULL
	);
}

int
__liballocs_walk_refs_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_containment_ctxt *cont, void *walk_refs_state_as_void)
{
	struct walk_refs_state *state = (struct walk_refs_state *) walk_refs_state_as_void;
	/* To walk references, we walk allocations (our caller is doing that) and
	 * - if they are a reference, run our cb on them
	 * - if they might contain references, recursively walk them with the same cb;
	 * - otherwise skip them.
	 */
	// 1. is this a reference?
	if (state->interp->can_interp(obj, t, cont))
	{
		int ret = state->ref_cb(maybe_the_allocation,
			obj, t, allocsite, cont, walk_refs_state_as_void);
		// 'ret' tells us whether or not to keep walking references; non-zero means stop
		if (ret) return ret;
		// if we got 0, we still don't want to "continue" per se; we want to cut off
		// the subtree
		return -1;
	}
	// 2. Is this a thing that might contain references?
	// We really want our interpreter to help us here.
	// Even a simple scalar might be a reference, so we really need help.
	if (!state->interp->may_contain(obj, t, cont)) return -1;

	return 0; // keep going with the depth-first thing
}

int
__liballocs_walk_environ_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_containment_ctxt *cont, void *walk_environ_state_as_void)
{
	struct walk_environ_state *state = (struct walk_environ_state *) walk_environ_state_as_void;
	/* To walk environment info, we walk allocations (our caller is doing that) and
	 * - if they are part of the environment, run our cb on them
	 * - if they might contain environment info, recursively walk them with the same cb;
	 * - otherwise skip them.
	 */
	// 1. is this a reference?
	uintptr_t maybe_environ_key = state->interp->is_environ(obj, t, cont);
	if (maybe_environ_key)
	{
		// we want to pass the key through to our callback; how?
		struct environ_elt_cb_arg arg = {
			.state = state,
			.key = maybe_environ_key
		};
		int ret = state->environ_cb(maybe_the_allocation,
			obj, t, allocsite, cont, &arg);
		// 'ret' tells us whether or not to keep walking environment; non-zero means stop
		if (ret) return ret;
		// if we got 0, we still don't want to "continue" per se; we want to cut off
		// the subtree
		return -1;
	}
	// 2. Is this a thing that might contain references?
	// We really want our interpreter to help us here.
	// Even a simple scalar might be a reference, so we really need help.
	if (!/*state->interp->may_contain(obj, t, cont)*/ 1) return -1;

	return 0; // keep going with the depth-first thing
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

// Weak no-op versions of notification functions to prevent undefined symbols
void __notify_copy(void *dest, const void *src, unsigned long n) __attribute__((weak));
void __notify_copy(void *dest, const void *src, unsigned long n) {}
void __notify_free(void *dest) __attribute__((weak));
void __notify_free(void *dest) {}
