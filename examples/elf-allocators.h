#ifndef ELF_ALLOCATORS_H_
#define ELF_ALLOCATORS_H_

#include "allocmeta.h"

struct allocated_chunk {}; // FIXME: move this elsewhere
_Static_assert(sizeof (struct allocated_chunk) == 0,
	"struct allocated_chunk's size should be zero");

struct elf_allocated_chunk
{
	struct allocated_chunk empty;
};
_Static_assert(sizeof (struct elf_allocated_chunk) == 0,
	"struct elf_allocated_chunk's size should be zero");

/* How does our code become aware of an mmap'd ELF file?
 * It might do it itself, or
 * it might be given a mapping made externally
 * and expected to 'bless' it as an ELF file, which would
 * involve creating the .
 * Since the 'external blessing' pattern is how most of our
 * current allocators work, we follow that pattern here. */

#define SHDR_IS_MANIFEST(shdr) \
   ((shdr).sh_type != SHT_NOBITS && (shdr).sh_size != 0)

#ifndef stringify
#define stringify(cond) #cond
#endif
// stringify expanded
#ifndef stringifx
#define stringifx(cond) stringify(cond)
#endif

#define GET_UNIQTYPE_PTR(tfrag) ({ \
   void *ret = fake_dlsym(RTLD_DEFAULT, "__uniqtype__" stringifx(tfrag)); \
   if (ret == (void*)-1) ret = NULL; \
   ret; })

#define ElfW_with_data(t) catx(ElfW(t), _with_data)
#define elf_file_data_types(v) \
v(EHDR, ElfW(Ehdr), ElfW(Ehdr), /* is array? */ 0) \
v(SHDRS, ElfW(Shdr), ElfW(Shdr), 1) \
v(PHDRS, ElfW(Phdr), ElfW(Phdr), 1) \
v(NHDR, ElfW(Nhdr), ElfW_with_data(Nhdr), 0) \
v(SYMS, ElfW(Sym), ElfW(Sym), 1) \
v(RELAS, ElfW(Rela), ElfW(Rela), 1) \
v(RELS, ElfW(Rel), ElfW(Rel),  1) \
v(DYNAMICS, ElfW(Dyn), ElfW(Dyn), 1) \
v(FUNPTRVVS, funptr_t, __PTR___FUN_FROM___FUN_TO_void, 1) \
v(BYTES, unsigned char, unsigned_char$$8, 1)

// define an enum -- ignoring the second argument
#define elf_file_data_types_enum_entry(tag, ctype, tfrag, tisarray) \
   ELF_DATA_ ## tag ,
enum elf_file_data_type
{
	ELF_DATA_NONE,
	elf_file_data_types(elf_file_data_types_enum_entry)
	ELF_DATA_NTYPES
};

extern struct uniqtype *elf_file_type_table[ELF_DATA_NTYPES];

extern struct allocator __elf_file_allocator;
extern struct allocator __elf_element_allocator;

struct elf_file_metadata
{
	void *alloc_site;
};

struct elf_elements_metadata
{
	/* With the metavector, what we get is a collection of 'elements'
	 * each with a file offset, a type_idx and a size in bytes.
	 * However, we might want to correlate these back to (especially)
	 * the section headers, so store this too. */
	ElfW(Shdr) *shdrs;
	unsigned nshdr;
	unsigned char *shstrtab_data;
	unsigned metavector_size;
	struct elf_metavector_entry *metavector;
	bitmap_word_t bitmap[];
};

struct big_allocation *elf_adopt_mapping_sequence(void *mapping_start,
	size_t mapping_len,
	size_t trailing_mapping_len);
struct uniqtype *elf_get_type(void *obj);

#endif
