#define _GNU_SOURCE

#include <link.h>
/* Bit of a hack: we don't assume a system-wide 'dwarf.h' and instead vendor
 * our chosen libdwarf. The best way to get at it is still via libdwarfpp. */
#ifndef DWARF_H
#define DWARF_H "dwarf.h"
#endif
#include DWARF_H
#include "relf.h"
#include "systrap.h"
#include "raw-syscalls-defs.h" /* for raw_write() */
#include "liballocs.h"
#include "liballocs_private.h"
#include "dlbind.h"

#define HIDDEN __attribute__((visibility("hidden")))

void *__liballocs_rt_uniqtypes_obj HIDDEN;
ElfW(Sym) *__liballocs_rt_uniqtypes_dynsym HIDDEN;
ElfW(Word) *__liballocs_rt_uniqtypes_gnu_hash HIDDEN;
unsigned char *__liballocs_rt_uniqtypes_dynstr HIDDEN;

struct uniqtype *pointer_to___uniqtype__void HIDDEN;
struct uniqtype *pointer_to___uniqtype____uninterpreted_byte HIDDEN;
struct uniqtype *pointer_to___uniqtype__signed_char HIDDEN;
struct uniqtype *pointer_to___uniqtype__unsigned_char HIDDEN;
struct uniqtype *pointer_to___uniqtype____uninterpreted_byte HIDDEN;
struct uniqtype *pointer_to___uniqtype____PTR_signed_char HIDDEN;
struct uniqtype *pointer_to___uniqtype____PTR___PTR_signed_char HIDDEN;
struct uniqtype *pointer_to___uniqtype__long_unsigned_int HIDDEN;
struct uniqtype *pointer_to___uniqtype__long_int HIDDEN;
struct uniqtype *pointer_to___uniqtype__Elf64_auxv_t HIDDEN;
struct uniqtype *pointer_to___uniqtype____ARR0_signed_char HIDDEN;
struct uniqtype *pointer_to___uniqtype__intptr_t HIDDEN;

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

void init_rt_uniqtypes_obj(void)
{
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
