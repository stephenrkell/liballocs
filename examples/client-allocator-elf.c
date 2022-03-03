#define _GNU_SOURCE
#include <elf.h>
#include <string.h>
size_t strlcat(char *dst, const char *src, size_t size);
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <ctype.h>
#include "liballocs.h"
#include "allocmeta.h"
#include "relf.h"
#include "librunt.h"
#include "pageindex.h"

_Bool debug;

/* An ELF file, mapped in memory, consists of
 * a collection of elements that are either
 * headers (or tables thereof)
 * or
 * sections.
 * Can we expose the allocator abstraction over that?
 * alloc/free/resize: these do make sense, although
      hard to implement
 * get type/base/size: these are easier
 *
 * The things I need to do are:
 * transitively explore the file and identify all the allocations
 *  (so I can dump them)
 *  ... can I do this like any other uniqtype BFS search?
 * Am going to follow pointers, so need a way to query arbitrary addresses
 * So need an up-front understanding of the file's allocation structure
 * e.g. a bitmap and type vector!
 * i.e. yes, let's keep it to read-only for now.
 * This seems pretty doable: keep a static-symbol-like view of the file,
 * including bitmap and type metavector.
 * Problem: this won't scale to dynamic operations.
 * For that, what do we need? A free list would be useful.
 * Free list + bitmap + per-obj-start metadata (maybe still in a static array) goes a long way
 * ... but also
 * want
 * A way to get all the incoming pointers(offsets) pointing/referring
 *      into a given range  (so we can rewrite them all).
 * That's tricky. Could iterate pointers on demand.
 * (For all elements. For all references within that element. ...)
 * ... just requires iterating over the bitmap, really. Simples!
 *
 * How do we want to plumb in the interpreter for references? I get that
 * many ELF types have 'offset' fields that need interpreting.
 * We could do it 'in' the types, i.e. fork special types, but
 * that seems wrong... would rather bring the interpreter to the
 * party. Do we want to associate interpreters with bigallocs?
 * There's a notion of 'can_interpret' perhaps.
 * i.e. the ELF file reference interpreter can interpret
 * certain offset fields.
 * Also don't forget that uniqtypes are allocators too.
 * So really the thing we 'can interpret' is an allocation,
 * maybe of a particular type,
 * residing at a particular context (nest) in an allocation tree.
 * Framed that way, we can plumb in the interpreterness separate
 * from the type. Only downside is baking in slow search problems,
 * to dispatch to an interpreter, cf. putting it in the type where
 * it's right there.
 * We could do something gross like using the low bits of a uniqtype ptr
 * to index into a per-bigalloc table of interpreters. So if I wanted
 * to record that ElfW(Ehdr) but with interpreters for the offsets,
 * I could ... hmm, no, doesn't work because of uniqueness of uniqtypes.
 * Better to suppose that as I'm walking a structure and knowing the type
 * of the thing I'm pointing at, I'm also knowing the interpreter(s).
 * Since an ELF offset interpreter needs to know the mapping base,
 * that makes sense.
 * Each interpreter is probably just a function, whose first N
 * arguments are known (so writable with a varargs signature)
 * void *(*interpret)(void *interp_state, void *obj, ...);
 *
 * So let's say we're walking an ELF file and resolving its offsets
 * like they're pointers. We need the ELF file's interp_state,
 * but how do we know which ElfW(Off) fields it can interpret? Just say
 * 'any'? Or say 'only these members'? Or say 'any member matching P'
 * (the nest thing again)?
 *
 * Remember our use case: we're walking the file, in address order,
 * and want to turn offsets into label-and-offset.
 * This is ill-posed if we want to allow editing within an array!
 * e.g. do we want one label for a section header table,
 * or one for each section *header* itself?
 * Again it comes down to uniqtypes themselves being allocations.
 * We want our code to be capable of generating both of these views.
 * Probably 'individually labelled array' is the variation we also need.
 * And remember that section headers themselves embed offsets!
 * So there is nesting of our interpreter to worry about.
 * I think a recursive approach with configurable 'cut-off'
 * is probably right.
 * E.g. we could assume that the uniqtype allocator itself knows
 * how to walk its own substructure and generate assembly that
 * has labelled that substructure (passing arguments for ident prefixing/uniqueness).
 * Then our decision is whether to delegate to it, or to
 * rely on our own (generic?) walker. Hmm. If we have a walker,
 * do we want one? Why not always delegate? Why not generate MAX LABELS?
 * Indeed the simple recursive approach would seem to label everything,
 * including struct fields, ...
 * CUTE IDEA: what about generating our own metavector
 * at the same time? i.e. use pushsection and popsection
 * to maintain somehow-encoded type info. The starts info
 * should be apparent in the symbols already, if we emit .size correctly.
 * We can have overlapping ELf symbols, so what we generate is a superset
 * of what our static-file stuff knows how to consume. That's not ideal.
 * Maybe that's the thing we want to be configurable? i.e. which level
 * in the allocation tree is the "global symbol level"? We can still have
 * the 'local symbol level' below that.
 */

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

static unsigned
count_represented_sections(ElfW(Shdr) *shdrs, unsigned nshdr)
{
	unsigned count = 0;
	for (unsigned i = 1; i < nshdr; ++i)
	{
		if (SHDR_IS_MANIFEST(shdrs[i])) ++count;
	}
	return count;
}

/* We can't use the static-allocator metavector type, because
 * it assumes a parallel symtab (or reloc entries but with no
 * type info). To avoid wasting too much space, we encode the
 * uniqtype as a small integer.
 */

/* To get the array types is a problem, because the actual
 * ElfNN_* typenames are typedefs to an anonymous struct type.
 * In general the symbol named "__ARR_t" will not exist, because
 * the __ARR_ typename will use the _usr_include_elf_h_NNN name
 * that was given to the anonymous underlying definition. We
 * encode the arrayness into the macro args. */

// catx is like '##' but it expands its arguments
#define caty(tok, ...) tok ## __VA_ARGS__
#define catx(tok, ...) caty(tok, __VA_ARGS__)

// we need a typedef to work around funky declarator syntax
typedef void (*funptr_t)(void);

// dummies start here
// HACK: we should be able to autogenerate these using macro magic,
// but life's too short
Elf64_Ehdr ehdr;
Elf64_Shdr shdr[1];
Elf64_Phdr phdr[1];
struct Elf64_Nhdr_with_data {
        Elf64_Nhdr nhdr[1];
        char data[];
} __attribute__((packed)) nhdr_with_data[1];
Elf64_Sym sym[1];
Elf64_Rela rela[1];
Elf64_Rel rel[1];
Elf64_Dyn dyn[1];
void (*fp)(void);
// begin attempt at that macro magic
#if 0
// to ensure our meta-DSO contains the ELF types we need,
// declare a dummy global of each type...
// HMM -- we have uniqtype name fragments not actual C type names.
// Do we want to use 'usedtypes'/'link-used-types'
// or work towards an invariant where only meta-DSOs contain uniqtypes?
// Unclear that this invariant is actually useful...
// or even feasible, e.g. can we link libcrunch-style inlined checks
// when the meta-DSO supplies the uniqtype? No because we'd need a load-time dependency
// on the meta-DSO, even if we move to weak dynamic undefs (CHECK the GitHub issues about this).
// So it seems reasonable that programs can depend on uniqtypes and therefore
// must have them embedded via link-used-types or similar.
// We have to (1) generate a reference to the uniqtype, and
// (2) ensure that its DWARF type is in our DWARF.
#define arrdecl0
#define arrdecl1 [1]
#define arru0
#define arru1 __ARR1_
#define elf_file_data_types_uniqtype_global(tag, ctype, tfrag, tisarray) \
ctype __dummy_ ## tag arrdecl ## tisarray; \
extern struct uniqtype catx(__uniqtype__, arru ## tisarray, caty(tfrag)); \
struct uniqtype * catx(__dummyptr_to___uniqtype__, arru ## tisarray, caty(tfrag)) = \
& catx(__uniqtype__, arru ## tisarray, caty(tfrag));
elf_file_data_types(elf_file_data_types_uniqtype_global)
#endif /* end attempt at macro magic */

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

// define the K-V lookup using the enum as indices into an array
struct uniqtype *elf_file_type_table[ELF_DATA_NTYPES];

__attribute__((constructor))
static void init_elf_file_type_table(void)
{
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

#define elf_file_data_types_table_entry_init(tag, ctype, tfrag, tisarray) { \
	elf_file_type_table[ELF_DATA_ ## tag] = (tisarray) \
	    ? __liballocs_get_or_create_unbounded_array_type( ({ \
	        struct uniqtype *tmp_u = GET_UNIQTYPE_PTR(caty(tfrag)); \
	        tmp_u; }) ) \
	    : GET_UNIQTYPE_PTR(catx(tfrag)); \
	}
	elf_file_data_types(elf_file_data_types_table_entry_init)
}

struct elf_metavector_entry
{
	ElfW(Off) fileoff:38; // maximum 256GB ELF file...
	unsigned type_idx:4;
	unsigned short shndx; // 16 bits
	unsigned long size:38;     // needs to match width of 'fileoff'
	// we are up to 96 bits now... very ugly
} __attribute__((packed));
/* Most entries represent sections. Ideally we want some way to get the
 * shndx for a given metavector entry. The problem is that we may have
 * up to 65536 sections, and they need not be in offset order. So we
 * really have to store the shndx for each element. */

static int compare_elf_metavector_entry(const void *p1, const void *p2)
{
	// being careful about overflow/underflow
	ElfW(Word) o1 = ((struct elf_metavector_entry *) p1)->fileoff;
	ElfW(Word) o2 = ((struct elf_metavector_entry *) p2)->fileoff;
	return (o1 < o2) ? -1 : (o1 == o2) ? 0 : 1;
}
static int compare_elf_metavector_entry_r(const void *p1, const void *p2, void *ignored)
{ return compare_elf_metavector_entry(p1, p2); }

extern struct allocator __elf_file_allocator; // defined below
extern struct allocator __elf_element_allocator; // defined below
/* HMM. There is a tricky distinction between
 * the overall ELF file (a bit like we have __static_file_allocator under
 * a mapping sequence)
 * and
 * the ELF elements within the file.
 * The division of labour between these is not clear. So far, we have
 * a bigalloc under the mapping sequence, allocated by __elf_file_allocator
 * (... what do its base-level and meta-level ops represent?)
 * and where the *suballocator* is recorded as __elf_element_allocator.
 * (... its base-level ops represent operations on/about individual ELF elements)
 *
 * To answer the question about __elf_file_allocator, it seems its base- and
 * meta-level ops always concern the *whole file*,
 * which is somewhat distinct from the mapping sequence underneath it. E.g. it
 * might know how to extend the file mapping, by extending the underlying mapping
 * sequence.
 *
 * This makes sense when we think that __elf_file_allocator only allocates bigallocs.
 * Obviously, each bigalloc is a unique self-contained entity. It's still an allocation,
 * allocated by __elf_file_allocator.
 *
 * So with a function like walk_allocations, which takes a bigalloc specifying what
 * space of allocations to walk, which of the two allocators (allocated_by or
 * suballocated_by) should be delegated to?
 * It should be the allocator that "manages the arena" that is the bigalloc.
 * In our case, the file is the arena but it's the element allocator that manages it.
 * So what should happen?
 * In short, walking allocations is an operation for the suballocator,
 * whose arena is denoted by the file bigalloc. Simples!
 */

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

static void free_elf_elements_metadata(void *elf_elements_metadata_as_void)
{
	struct elf_elements_metadata *m = (struct elf_elements_metadata *) elf_elements_metadata_as_void;
	free(m->metavector);
	free(m);
}

static
struct big_allocation *elf_adopt_mapping_sequence(void *mapping_start,
	size_t mapping_len,
	/* Callers can post-pad with an anonymous mapping into which the
	 * mapped file can be grown. At all times, the ELF file allocation
	 * is contained within the former; if we have to grow it into the
	 * anonymous mapping, we shrink the latter first and then expand
	 * out. We may need to provide some extra entry points in mmap.c
	 * to make this doable. */
	size_t trailing_mapping_len)
{
	// grab the underlying mapping sequence
	struct big_allocation *mseq_b = __lookup_bigalloc_from_root(mapping_start,
		&__mmap_allocator, NULL);
	assert(mseq_b);
	assert(!mseq_b->suballocator);
	assert(!mseq_b->first_child);
	ElfW(Ehdr) *ehdr = mapping_start;
	unsigned metavector_nentries =
			1 /* ehdr */
			+ (ehdr->e_phoff ? 1 : 0)
			+ (ehdr->e_shoff ? 1 : 0)
			+ (ehdr->e_shoff ? count_represented_sections(
					(ElfW(Shdr) *) ((uintptr_t) mapping_start + ehdr->e_shoff),
					ehdr->e_shnum) : 0)
			+ 0 /* FIXME: support the no-shdrs case */;
#define DIV_ROUNDING_UP(m, n) \
      (((m)+((n)-1))/(n))
// FIXME: we're not accounting for the starting address of the range,
// i.e. that it should be aligned to align*BITMAP_WORD_NBITS bytes
#define BITMAP_NWORDS(nbytes_spanned, align) \
	DIV_ROUNDING_UP( \
	   DIV_ROUNDING_UP(nbytes_spanned, align), \
	   BITMAP_WORD_NBITS \
	)
	struct elf_elements_metadata *elf_meta = calloc(1, offsetof(struct elf_elements_metadata, bitmap)
			+ sizeof (bitmap_word_t) * BITMAP_NWORDS(mapping_len + trailing_mapping_len, 1));
	elf_meta->metavector = malloc(metavector_nentries * sizeof *elf_meta->metavector);
	// create the bigalloc
	struct big_allocation *elf_b = __liballocs_new_bigalloc(
		mapping_start, mapping_len + trailing_mapping_len,
		__builtin_return_address(0) /* allocator_private */,
		NULL /* allocator_private_free */,
		mseq_b,
		&__elf_file_allocator);
	assert(elf_b);
	elf_b->suballocator = &__elf_element_allocator;
	elf_b->suballocator_private = elf_meta;
	elf_b->suballocator_private_free = free_elf_elements_metadata;

	// adding in any order for now; we qsort later
	unsigned metavector_ctr = 0;
#define add_allocation_o(offset, thesize, typetag, theshndx) do { \
	elf_meta->metavector[metavector_ctr++] = (struct elf_metavector_entry) {\
	.fileoff = (offset), \
	.size = (thesize), \
	.shndx = (theshndx), \
	.type_idx = ELF_DATA_ ## typetag \
	}; \
	assert(!(bitmap_get_b(elf_meta->bitmap, offset))); \
	bitmap_set_b(elf_meta->bitmap, offset); \
	} while(0)
#define add_allocation_p(addr, size, typetag, theshndx) \
	add_allocation_o((uintptr_t)(addr) - (uintptr_t) mapping_start, size, typetag, theshndx)
	// set up metadata for our ELF file:
	// 1. metavector
	// 2. bitmap
	// 3. free list -- by iterating over metavector and differencing lengths
	add_allocation_p(ehdr, ehdr->e_ehsize, EHDR, 0);
	if (ehdr->e_shoff)
	{
		ElfW(Shdr) *shdrs = (ElfW(Shdr)*)((uintptr_t) ehdr + ehdr->e_shoff);
		add_allocation_p(shdrs, ehdr->e_shnum * ehdr->e_shentsize, SHDRS, 0);
		assert(ehdr->e_shentsize == sizeof (ElfW(Shdr)));
		// remember this stuff in elf_meta
		elf_meta->shdrs = shdrs;
		elf_meta->nshdr = ehdr->e_shnum;
		elf_meta->shstrtab_data = (unsigned char *)((uintptr_t) ehdr + shdrs[ehdr->e_shstrndx].sh_offset);
		// add each as an element
		for (unsigned i = 1; i < ehdr->e_shnum; ++i)
		{
			if (SHDR_IS_MANIFEST(shdrs[i]))
			{
				char *addr = (char*)((uintptr_t) ehdr + shdrs[i].sh_offset);
				switch (shdrs[i].sh_type)
				{
					case SHT_NOTE:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, NHDR, i); // FIXME: not quite right
						break;
					case SHT_DYNSYM:
					case SHT_SYMTAB:
						// also promote these to bigallocs: they are packed_seqs
						// of the nulterm'd-string kind
						/* BIG Q: how do we iterate depth first over
						 * promoted and non-promoted allocations,
						 * while preserivng the property that a depth-first pre-order walk
						 * enumerates (sub)allocations in address order?
						 *
						 * Tentative: bigallocs know that they're promoted, and
						 * we skip those children when walking bigalloc children.
						 * The allocator also has to know about promotion.
						 * GAH. Preserving the depth-first order here is a problem.
						 *
						 * What's the other case? It's things like the auxv/stack
						 * hack perhaps. Remind me why we had that?
						 *
						 * Or it's actual suballocation: not reasonable for the
						 * two allocators to know about each other then. Suballocation
						 * is different from promotion.
						 *
						 * So hmm, are we talking about promotion or suballocation here?
						 * A packed sequence seems like a suballocator to me.
						 *
						 * Currently, bigalloc records can contain an insert, for
						 * the case of promoted heap allocations. This is in a big ugly
						 * union. We really want to remove the 'ins_and_bits' case.
						 * The reason for putting it in the bigalloc was clownshoes,
						 * although clients who do that already have to nonportably
						 * guess the malloc header overhead anyway.
						 * SO
						 * Probably the things to do are:
						 *
						 * - when walking DF, interleave the walk of ordinary allocations
						 *   and child bigallocs (of either kind!)
						 * - distinguish 'promoted [but not suballocated]' from
						 *   'suballocated' in the bigalloc struct. Actually this is
						 *   already the case: "suballocator" may be null.
						 * - promoted chunks' metadata should always be managed
						 *   by the underlying allocator
						 *      - update generic-malloc and generic-small
						 *      - eliminate ins_and_bits
						 * DONE all these.
						 * THEN we can manage packed subsequences as... what? They are
						 * suballocated. See SHT_STRTAB below.
						 */
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, SYMS, i); break;
					case SHT_RELA:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, RELAS, i); break;
					case SHT_DYNAMIC:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, DYNAMICS, i); break;
					case SHT_NOBITS: assert(0 && "nobits should not be manifest");
					case SHT_REL:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, RELS, i); break;
					case SHT_SHLIB: assert(0 && "SHT_SHLIB should not be used");
					case SHT_INIT_ARRAY:
					case SHT_FINI_ARRAY:
					case SHT_PREINIT_ARRAY:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, /*FUNPTRVVS*/ BYTES, i); break;
					case SHT_STRTAB: {
						/* Let's try our packed_sequence thingy. How do we promote one
						 * of our allocations? I guess we just create a bigalloc and
						 * make sure it is allocated_by us. */
						struct big_allocation *seq_b = __liballocs_new_bigalloc(
							(void*)((uintptr_t) elf_b->begin + shdrs[i].sh_offset),
							shdrs[i].sh_size,
							NULL /* allocator_private */,
							NULL /* allocator_private_free */,
							elf_b, /* parent is the ELF file bigalloc? yes */
							&__elf_element_allocator /* allocated by */
						);
						seq_b->suballocator = &__packed_seq_allocator;
						seq_b->suballocator_private = malloc(sizeof (struct packed_sequence));
						seq_b->suballocator_private_free = __packed_seq_free;
						if (!seq_b->suballocator_private) abort();
						*(struct packed_sequence *) seq_b->suballocator_private = (struct packed_sequence) {
							.fam = &__string8_nulterm_packed_sequence,
							.enumerate_fn_arg = NULL,
							.name_fn_arg = NULL,
							.un = { .metavector_any = NULL },
							.metavector_nused = 0,
							.metavector_size = 0,
							.starts_bitmap = NULL,
							.starts_bitmap_nwords = 0,
							.offset_cached_up_to = 0
						};
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, BYTES, i);
					}   break;
					// for now, other sections are just bytes
					case SHT_GROUP:
					case SHT_SYMTAB_SHNDX:
					case SHT_PROGBITS:
					case SHT_HASH:
					default:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, BYTES, i); break;
				}
			}
		}
	}
	if (ehdr->e_phoff)
	{
		assert(ehdr->e_phentsize == sizeof (ElfW(Phdr)));
		add_allocation_o(ehdr->e_phoff, ehdr->e_phnum * ehdr->e_phentsize, PHDRS, 0);
	}
	assert(metavector_nentries == metavector_ctr);
	// now we have a metavector but it isn't sorted.
	qsort(elf_meta->metavector, metavector_nentries, sizeof *elf_meta->metavector,
			compare_elf_metavector_entry);
	// now it's sorted
	elf_meta->metavector_size = metavector_nentries;

	// remember our initial use case:
	// outputting an editable assembly representation of the ELF,
	// with cross-references rendered symbolically.
	// Eventually we'd want code to be output as mnemonics too, taking
	// the assembler dialect/switches from hte ELF headers (which arch?)
	// and our own knowledge of the target assembler.

	// every ELF element is either a section or a header array
	// Remember that not all sections exist in the file... only if
	// non-NOBITS and non-zero-length. (SHF_ALLOC has no bearing)

	// when emitting assembly, one problem is that encoded references
	// need to be expressed in offset-space (i.e. our assmebler symbols work
	// in offset-space), but we will get the intended referent in vaddr-space,
	// and the assembler will *also* , within an instruction, be working in
	// vaddr-space. We may have to us hacks like raw binary output, with a
	// comment showing the mnemonic. This will become clearer.

	// Can we use in-memory uniqtypes to represent on-disk ELF elements?
	// Yes, but there's an endianness issue: for each ELF type there's
	// both a 'this-endianness' variant and an 'other-endianness' variant.
	// We just go with the former for nwo, but check that the file satisfies
	// it. In future we could create uniqtypes to describe the other
	// endianness. For the native endianness we can get the uniqtypes by
	// introspection.

	return elf_b;
}

// we should be able to generate these from macros
// using the metavector/bitmap

struct uniqtype *
get_or_create_elfw_note_data_type(unsigned byte_array_len)
{
	/* Do we already have the actual type we want? */
	const char *imprecise_struct_uniqtype_name = "__uniqtype__" stringifx(ElfW(Nhdr)_with_data);
	char precise_struct_uniqtype_name[4096];
	snprintf(precise_struct_uniqtype_name, sizeof precise_struct_uniqtype_name,
		"%s%u",
		imprecise_struct_uniqtype_name,
		byte_array_len);
	struct uniqtype *found_struct = //get_type_from_symname(precise_uniqtype_name);
		fake_dlsym(RTLD_DEFAULT, precise_struct_uniqtype_name);
	if (found_struct && found_struct != (void*)-1)
	{
		return (struct uniqtype *) found_struct;
	}

	/* Get the char-array type we need. */
	struct uniqtype *found_array_t = __liballocs_get_or_create_array_type(
		GET_UNIQTYPE_PTR(unsigned$20char),
		byte_array_len);
	assert(found_array_t);
	assert(found_array_t != (void*) -1);

	/* Create the struct type and memoise using libdlbind. */
	struct uniqtype *found_unbounded_struct_t =
		fake_dlsym(RTLD_DEFAULT, imprecise_struct_uniqtype_name);
	assert(found_unbounded_struct_t);
	assert(found_unbounded_struct_t != (void*) -1);
	/* We have *three* related fields: two members and a field_names. */
	size_t sz = offsetof(struct uniqtype, related) + 3 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	memcpy(allocated, found_unbounded_struct_t, sz);
	allocated_uniqtype->pos_maxoff = sizeof (ElfW(Nhdr)) + byte_array_len;
	unsigned field_idx = allocated_uniqtype->un.composite.nmemb - 1;
	assert(field_idx == 1);
	allocated_uniqtype->related[field_idx]
	= (struct uniqtype_rel_info) {
		.un = { memb: {
			.ptr = found_array_t,
			.off = sizeof (ElfW(Nhdr))
		} }
	};
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	dlbind(__liballocs_rt_uniqtypes_obj, precise_struct_uniqtype_name,
		allocated_uniqtype, sz, STT_OBJECT);

	return allocated_uniqtype;
}

static
struct uniqtype *elf_precise_type(unsigned idx, unsigned size)
{
	struct uniqtype *u = elf_file_type_table[idx];
	if (UNIQTYPE_SIZE_IN_BYTES(u) == UNIQTYPE_POS_MAXOFF_UNBOUNDED)
	{
		if (UNIQTYPE_IS_ARRAY_TYPE(u)
				&& UNIQTYPE_ARRAY_LENGTH(u) == UNIQTYPE_ARRAY_LENGTH_UNBOUNDED)
		{
			struct uniqtype *elem_t = UNIQTYPE_ARRAY_ELEMENT_TYPE(u);
			assert(elem_t);
			assert(size % UNIQTYPE_SIZE_IN_BYTES(elem_t) == 0);
			unsigned n = size / UNIQTYPE_SIZE_IN_BYTES(elem_t);
			assert(n >= 1);
			struct uniqtype *real_u = __liballocs_get_or_create_array_type(
				elem_t, n);
			return real_u;
		}
		else
		{
			assert(idx == ELF_DATA_NHDR);
			struct uniqtype *u = get_or_create_elfw_note_data_type(/* byte_array_len */
				size - sizeof (ElfW(Nhdr)));
			assert(u);
			return u;
			/* See GitHub issue #53 for the problem we run into with make_precise()
			 * here.  So what do we do for now? We have to handle it as a special case,
			 * some kind of get_or_create_ for the ElfW(Nhdr)_with_data. */
		}
	}
	else return u;
}

/* helper */
static struct elf_metavector_entry *elf_get_metavector_entry(void *obj, struct elf_elements_metadata **out_meta)
{
	struct big_allocation *b = __lookup_bigalloc_from_root(obj,
		&__elf_file_allocator, NULL);
	if (!b) return NULL;
	struct elf_elements_metadata *meta = (struct elf_elements_metadata *) b->suballocator_private;
	uintptr_t target_offset = (uintptr_t) obj - (uintptr_t) b->begin;
	if (out_meta) *out_meta = meta;
#define offset_from_rec(p) (p)->fileoff
	return bsearch_leq_generic(struct elf_metavector_entry, target_offset,
		/* T* */ meta->metavector, meta->metavector_size, offset_from_rec);
}

static
struct uniqtype *elf_get_type(void *obj)
{
	struct elf_metavector_entry *found = elf_get_metavector_entry(obj, NULL);
	if (found) return elf_precise_type(found->type_idx, found->size);
	return NULL;
}

static
void *elf_get_base(void *obj);

static
unsigned long *elf_get_size(void *obj);

/* Getting a name makes sense... sections have names, though
 * header tables don't. One caveat is that section names don't
 * need to be unique. Maybe get_name functions should warn when
 * they generate a non-unique name? Or probably it should be
 * a queryable property of an allocator's contract.
 */
static
const char *elf_get_name(void *obj, char *buf, size_t buflen)
{
	struct elf_elements_metadata *meta = NULL;
	/* To get the name, first we get the type. */
	struct elf_metavector_entry *found = elf_get_metavector_entry(obj, &meta);
	if (found)
	{
		switch (found->type_idx)
		{
			case ELF_DATA_EHDR: return "ehdr";
			case ELF_DATA_SHDRS: return "shdrs";
			case ELF_DATA_PHDRS: return "phdrs";
			default: {
				/* The allocation is a section, so we want the
				 * section name. We have the fileoff, which
				 * should be enough. ELF  But we need the shstrtab. */
				ElfW(Shdr) *found_shdr = meta->shdrs ? &meta->shdrs[found->shndx] : NULL;
				if (found_shdr)
				{
					assert(meta->shstrtab_data);
					const char *shname = (const char *)(&meta->shstrtab_data[found_shdr->sh_name]);
					/* FIXME: we do not handle the case where section names are
					 * not unique. Or at least, we pass that non-uniqueness to
					 * our caller to deal with. */
					int ret = snprintf(buf, buflen, "section%s", shname);
					if (ret >= buflen) buf[buflen - 1] = '\0';
					return buf;
					// FIXME: we are not signalling error on truncation
				}
				break; // we fail
			}
		}
	}
	return NULL;
}


static
struct allocated_chunk *
elf_alloc_zero(size_t sz, size_t align, struct uniqtype *t)
{
	/* If we go with "allocation == section", then this makes sense
	 * but we first may have to realloc the section header table.
	 * And move stuff arond. It's a big operation. Save it until
	 * later, i.e. when we have explicit pointers. */
	return NULL;
}

static
struct allocated_chunk *
elf_alloc_uninit(size_t sz, size_t align, struct uniqtype *t)
{
	return elf_alloc_zero(sz, align, t);
}


static
void
elf_free(struct allocated_chunk * start);

static
_Bool
elf_resize_in_place(struct allocated_chunk *start, size_t new_sz);

static
struct allocated_chunk *
elf_safe_migrate(struct allocated_chunk *start, struct allocator *recipient); // FIXME: needs bigalloc arg

static
struct allocated_chunk *
elf_unsafe_migrate(struct allocated_chunk *start, struct allocator *recipient);  // FIXME: needs bigalloc arg

static
void elf_register_suballoc(struct allocated_chunk *start, struct allocator *suballoc); // is this ensure_big?

static
const void *elf_get_site(void *obj);

static
liballocs_err_t elf_get_info(void *obj, struct big_allocation *maybe_alloc, struct uniqtype **out_type, void **out_base, unsigned long *out_size, const void **out_site);

static struct big_allocation *
elf_ensure_big(void *obj);

static
Dl_info elf_dladdr(void *obj);

static
lifetime_policy_t *elf_get_lifetime(void *obj);

static
addr_discipl_t elf_get_discipl(void *site);

static
_Bool elf_can_issue(void *obj, off_t off);

static
size_t elf_raw_metadata(struct allocated_chunk *start, struct alloc_metadata **buf);

static
liballocs_err_t elf_set_type(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *new_t);

static
liballocs_err_t elf_set_site(struct big_allocation *maybe_the_allocation, void * obj,
		struct uniqtype *new_t);

static liballocs_err_t elf_get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	return &__liballocs_err_unindexed_heap_object; // FIXME
}

static int elf_elements_walk_allocations(struct alloc_tree_pos *scope,
	walk_alloc_cb_t *cb, void *arg, void *maybe_range_begin, void *maybe_range_end)
{
	struct big_allocation *arena = BOU_BIGALLOC(scope->bigalloc_or_uniqtype);
	struct elf_elements_metadata *elements_meta
		 = (struct elf_elements_metadata *) arena->suballocator_private;
	int ret = 0;
	unsigned coord = 1;
	// FIXME: heed maybe_range_begin and maybe_range_end
	/* Do we need to recognise when one of our allocations is also
	 * a bigalloc? Maybe we promoted it, but maybe some other code
	 * decided just to 'hang' the bigalloc there. I think this is
	 * for the depth-first walker to notice. We only walk one level.
	 * The depth-first walker may discard the type we give it, because
	 * there's an essential conflict between saying you have a uniqtype,
	 * and saying you have a suballocator (other than __uniqtype_allocator).
	 * They might have different ways of divvying up the space.
	 */
	for (struct elf_metavector_entry *e = elements_meta->metavector;
			e != elements_meta->metavector + elements_meta->metavector_size;
			++e, ++coord)
	{
		/* We are making a link. And we don't know anything about DF walking.
		 * We pass only a link, and it's up to walk_one_df_cb to maintain the path.
		 *
		 * (LONGER EXPLANATION)
		 * So [how] does the DF walker ensure that if it has to walk ELF elements
		 * lower down the hierarchy, its cb always gets called with a full path
		 * and not a mere link?
		 *
		 * We do DF walking by doing an ordinary walk
		 * and passing the DF callback as the argument.
		 * A WRONG version of this would be if the first thing the callback does is
		 *
		    struct alloc_tree_path *path = (struct alloc_tree_path *) link; // downcast
		 *
		 * i.e. assume it has been give a path, not just a link. That is wron
		 * because it is called by a plain old walker like us, which does not
		 * know about paths.For the DF cb to get its contextual path, it needs
		 * to get it from its own 'arg'.
		 */
		struct alloc_tree_link link = {
			.container = { .base = arena->begin, .bigalloc_or_uniqtype = (uintptr_t) arena },
			.containee_coord = coord
		};
		ret = cb(
			NULL,
			(void*)((uintptr_t) arena->begin + e->fileoff),
			elf_precise_type(e->type_idx, e->size),
			arena->allocator_private /* alloc site */,
			&link,
			arg
		);
		if (ret != 0) return ret;
	}
	return ret;
}

struct allocator __elf_file_allocator = {
	.name = "ELF file",
	.is_cacheable = 1,
};
struct allocator __elf_element_allocator = {
	.name = "ELF element",
	.is_cacheable = 1,
	.get_info = elf_get_info,
	.walk_allocations = elf_elements_walk_allocations,
	.get_name = elf_get_name
};

#if 0

/* To save space, we don't record the size of an allocation explicitly...
 * instead we just use the bitmap to give an upper bound on the size,
 * and then record padding. Even for huge pages, we shouldn't need more
 * than a 20-bit number to record padding... should we?
 *
 * We could also use an indirection table to store the types, because
 * there are only a handful of ELF element types
 * (ElfW(Ehdr), array of ElfW(Shdr), and so on -- though
 * in full generality, any elf.h type might be needed here.
 * That would let us reduce the uniqtype field to a 12-bit offset,
 * getting us back to one-word-per-entry. Or to keep the record the same
 * size and get a full 'size' field. */

#endif

struct emit_asm_ctxt
{
	void *start_address;
	unsigned long emitted_up_to_offset;
	unsigned depth;
	// need to thread through a summary of incoming references,
	// so that we can emit labels as we go along
	struct elf_walk_refs_state *references;
	// to simulate a post-order traversal given only in-order traversal,
	// we queue up post-order output, which gets flushed
	// (1) on output at or below its depth, and
	// (2) at the end of the traversal.
	struct {
		unsigned depth;
		char *output;
	} *queued_end_output;
	unsigned queue_size;
	unsigned queue_nused;
	struct big_allocation *file_bigalloc;
};

static intptr_t can_interp_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link)
{
	_Bool retval = UNIQTYPE_IS_POINTER_TYPE(exp_t);
	assert(!retval);
	return retval;
}
static void *do_interp_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link, intptr_t how)
{
	void *p;
	memcpy(&p, exp, sizeof p);
	return p;
}
static _Bool may_contain_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link)
{
	// FIXME: this is a bit imprecise
	return UNIQTYPE_HAS_SUBOBJECTS(exp_t);
}
static uintptr_t is_environ_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link)
{
	return 0; // i.e. 'no'
}
struct interpreter pointer_resolver = (struct interpreter) {
	.name = "pointer interpreter",
	.can_interp = can_interp_pointer,
	.do_interp = do_interp_pointer,
	.may_contain = may_contain_pointer,
	.is_environ = is_environ_pointer
};

static _Bool is_elf_structure_type(struct uniqtype *t)
{
	// HACK for now
	for (unsigned n = 1; n < ELF_DATA_NTYPES; ++n)
	{
		struct uniqtype *real_t = UNIQTYPE_IS_ARRAY_TYPE(elf_file_type_table[n])
			? UNIQTYPE_ARRAY_ELEMENT_TYPE(elf_file_type_table[n]) : elf_file_type_table[n];
		if (UNIQTYPE_IS_COMPOSITE_TYPE(real_t) &&
			t == real_t) return 1;
	}
	return 0;
}
enum elf_offset_or_pointer_interp
{
	EOP_NONE = 0,
	EOP_POINTER = 1,
	EOP_OFFSET = 2,
	EOP_VADDR = 3,
	EOP_BITS_MASK = 0x7
};
static intptr_t can_interp_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t,
	struct alloc_tree_link *link)
{
	/* Is it the right type to be an ELF file offset, in a context
	 * where we understand what it means (i.e. that it really is one)? */
	if (can_interp_pointer(exp, exp_t, link)) return EOP_POINTER;

	static struct uniqtype *offset_t;
	if (!offset_t)
	{
		offset_t = fake_dlsym(RTLD_DEFAULT, "__uniqtype__" stringifx(ElfW(Off)));
	}
	assert(offset_t);
	assert(offset_t != (void*)-1);
	/* PROBLEM: Elf64_Off is typedef uint64_t, so any 64-bit unsigned integer will
	 * hit this. We really need to capture typedefs. That is tricky when we've
	 * designed that out. But we can do it if we record symidx. Do we want to
	 * go the whole 'spine' way? Is there some nicer way to do this?
	 *
	 * One easier way to do it is to use knowledge of the field name, which we
	 * can get at. We use this below. */

	/* Since we can't pattern-match on strings/tokens, hack something up that turns them
	 * into 64-bit integers. PROBLEM: this doesn't work in gcc (at least up to 8.3):
	 * "case label does not reduce to an integer constant" even though
	 * it's happy to use the same expression as a global initializer.
	 * See GCC bug 89408. For now we use clang for this file (see Makefile).
	 * Compiling as C++ code could work too, modulo other fixes. */
#define atomify4(s) \
    ({ union { uint32_t atom; char buf[4]; } un; \
       bzero(&un, sizeof un); strncpy(un.buf, (s), 4); un.atom; })
#define strip_underscore_and_atomify(s) \
    ({ char *und = memchr((s), '_', strlen(s)); atomify4(und ? und+1 : (s)); })
#define valpair(strcttag, fld) \
 ( ((unsigned long) strip_underscore_and_atomify(strcttag)) | (((unsigned long) strip_underscore_and_atomify(fld))<<32) )
#define lit_atom(str) \
    ( (unsigned)((str)[0]) | ((unsigned)(((str)[1])<<8)) | ((unsigned)(((str)[2])<<16)) | ((unsigned)(((str)[3])<<24)) )
#define litpair(str1, str2) \
    ( ((unsigned long) ( lit_atom(#str1) )) | \
     (((unsigned long) ( lit_atom(#str2) ))<<32) \
    )
	if (!BOU_IS_UNIQTYPE(link->container.bigalloc_or_uniqtype)) return EOP_NONE;
	if (!UNIQTYPE_IS_COMPOSITE_TYPE(LINK_UPPER_UNIQTYPE(link))) return EOP_NONE;
	if (debug)
	{
		fprintf(stderr, "Within a %s, hit field %s\n",
			UNIQTYPE_NAME(LINK_UPPER_UNIQTYPE(link)),
			LINK_UNIQTYPE_FIELD_NAME(link));
	}
	const char *uniqtype_name = UNIQTYPE_NAME(LINK_UPPER_UNIQTYPE(link));
	const char *field_name = LINK_UNIQTYPE_FIELD_NAME(link);
	struct uniqtype *ref_target_type = NULL;
	unsigned long vp = valpair(uniqtype_name, field_name);
	switch (vp)
	{
		// these are offsets
		case litpair(Ehdr, shoff):   ref_target_type = GET_UNIQTYPE_PTR(ElfW(Shdr)); goto return_offset;
		case litpair(Ehdr, phoff):   ref_target_type = GET_UNIQTYPE_PTR(ElfW(Phdr)); goto return_offset;
		case litpair(Shdr, offset):
		case litpair(Phdr, offset):
			return_offset: return EOP_OFFSET | (uintptr_t) ref_target_type;
		/* These are vaddrs. We will need to walk the phdrs and
		 * figure out which one it falls under, then translate
		 * to a file offset using that phdr's translation. */
		case litpair(Ehdr, entry):
		case litpair(Shdr, addr):
		case litpair(Phdr, vaddr):
		case litpair(Phdr, paddr):
		case litpair(Sym, value):
			 return_vaddr: return EOP_VADDR | (uintptr_t) ref_target_type;
		default:
			// we hit something we didn't anticipate
			return EOP_NONE;
	}
}
void *do_interp_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link, intptr_t how)
{
	struct alloc_tree_path *elf_elements_path = (struct alloc_tree_path *) link; // can downcast; we are doing DF
	/* FIXME: searching up the chain like this
	 * on *every* resolve is expensive. It should only
	 * be a short distance, but still. */
	while (!BOU_IS_BIGALLOC(elf_elements_path->to_here.container.bigalloc_or_uniqtype) ||
		BOU_BIGALLOC(elf_elements_path->to_here.container.bigalloc_or_uniqtype)->suballocator !=
				&__elf_element_allocator)
	{
		assert(elf_elements_path->encl);
		elf_elements_path = elf_elements_path->encl;
	}
	void *elf_file_base = BOU_BIGALLOC(elf_elements_path->to_here.container.bigalloc_or_uniqtype)->begin;
	/* Resolve the offset to a pointer within the mapping. */
	assert((how & EOP_BITS_MASK) != EOP_NONE);
	switch (how & EOP_BITS_MASK)
	{
		case EOP_POINTER: return do_interp_pointer(exp, exp_t, link, 1);
		case EOP_OFFSET: {
			ElfW(Off) o;
			memcpy(&o, exp, sizeof o);
			return (void*)((uintptr_t) elf_file_base + o);
		}
		case EOP_VADDR: {
			ElfW(Addr) a;
			memcpy(&a, exp, sizeof a);
			ElfW(Phdr) *phdrs = (ElfW(Phdr) *)(elf_file_base +
					((ElfW(Ehdr) *) elf_file_base)->e_phoff);
			for (unsigned i = 0; i < ((ElfW(Ehdr) *) elf_file_base)->e_phnum; ++i)
			{
				if (phdrs[i].p_type == PT_LOAD &&
						a >= phdrs[i].p_vaddr &&
						a < phdrs[i].p_vaddr + phdrs[i].p_filesz)
				{
					return (void*)((uintptr_t) elf_file_base +
							phdrs[i].p_offset +
							( a - phdrs[i].p_vaddr ));
				}
				// INTERESTING CASE: if it's not within filesz, but it's
				// within memsz. Then it refers to an object which would exist
				// at run time, but does not exist in the mapped file.
				// We could generate a undefined sym representing this area,
				// and output reloc record. But that's straying beyond our remit.
				// We're trying to represent the file, not the memory image that
				// the file itself represents.
			}
			return NULL;
		}
		default: abort();
	}

	/* interpreters have idempotent allocation semantics
	 * (and region/GC reclaim semantics? i.e. we never have to worry about
	 * freeing a result returned by an interpreter?
	 *
	 * can imagine 'weak' and 'non-weak' do_interp functions,
	 * where the no-nweak one will attach a lifetime policy
	 * (analogy: dlopen)
	 *
	 * similarly there are 'get' and 'get_or_create' operations...
	 * 'get' is like dlopen(_, RTLD_NOLOAD).
	 *
	 * a weak get_or_create does make sense, but only if freeing
	 * is manual anyway, i.e. if create'd, the manual policy applies.
	 * Doing 'create' always means attaching *some* policy or other.
	 */
}
_Bool may_contain_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link)
{
	return may_contain_pointer(exp, exp_t, link);
}
uintptr_t is_environ_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t, struct alloc_tree_link *link)
{
	/* The referential 'environment' in a memory-mapped ELF file consists of:
	 *
	 * - all p_vaddr and p_offset fields in a LOAD program header
	 *   (used to map between referenced offsets and file vaddrs)
	 * - FIXME: any relocs and symbols
	 *   (used to map between referenced offsets and more exotic addends that needn't be file vaddrs)
	 */
	static struct uniqtype *phdr_u;
	if (!phdr_u)
	{
		phdr_u = GET_UNIQTYPE_PTR(Elf64_Phdr);
		if (!phdr_u) abort();
	}
	if (BOU_IS_UNIQTYPE(link->container.bigalloc_or_uniqtype)
			&& BOU_UNIQTYPE(link->container.bigalloc_or_uniqtype)
				== phdr_u)
	{
		if (((Elf64_Phdr *) link->container.base)->p_type != PT_LOAD) return 0;
		if (0 == strcmp(LINK_UNIQTYPE_FIELD_NAME(link), "p_offset"))
		{
			return (uintptr_t) "p_offset";
		}
		if (0 == strcmp(LINK_UNIQTYPE_FIELD_NAME(link), "p_vaddr"))
		{
			return (uintptr_t) "p_vaddr";
		}
	}
	return 0; // keep going
}
struct elf_reference
{
	unsigned long source_file_offset;
	struct uniqtype *reference_type;
	unsigned long target_file_offset; // may be -1, in theory (shouldn't be, for us)
	const char *target_alloc_name;
	unsigned target_offset_from_alloc_start;
	struct uniqtype *referenced_type;
	intptr_t interp_how;
	// HMM: more here
};
struct elf_walk_refs_state
{
	struct walk_refs_state ref;
	struct big_allocation *file_bigalloc;
	struct elf_reference *buf; // don't copy this; we need to realloc it
	unsigned buf_capacity;
	unsigned buf_used;
};
#define ELF_WALK_REFS_BUF_INITIAL_CAPACITY 128
int seen_elf_reference_or_pointer_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link_to_here,
	void *elf_walk_refs_state_as_void)
{
	struct elf_walk_refs_state *state = (struct elf_walk_refs_state *)
		elf_walk_refs_state_as_void;
	/* When we see a reference, save it in the buffer. */
	if (state->buf_used == state->buf_capacity)
	{
		unsigned long new_capacity = state->buf_capacity ? state->buf_capacity * 2 : ELF_WALK_REFS_BUF_INITIAL_CAPACITY;
		state->buf = realloc(state->buf, new_capacity * sizeof *state->buf);
		if (!state->buf)
		{
			err(EXIT_FAILURE, "cannot realloc ELF reference buffer");
		}
		state->buf_capacity = new_capacity;
	}
	void *target = do_interp_elf_offset_or_pointer(obj, t, link_to_here, state->ref.seen_how);
	unsigned long target_offset;
	if ((uintptr_t) target >= (uintptr_t) state->file_bigalloc->begin &&
	    (uintptr_t) target <  (uintptr_t) state->file_bigalloc->end)
	{
		// the target is within the mapping bounds
		target_offset = (uintptr_t) target - (uintptr_t) state->file_bigalloc->begin;
	}
	else
	{
		target_offset = (unsigned long) -1;
		// FIXME: set symname based on alloc identity
	}
	struct elf_reference *the_ref = &state->buf[state->buf_used++];
	*the_ref = (struct elf_reference) {
		.source_file_offset = (uintptr_t) obj - (uintptr_t) state->file_bigalloc->begin,
		.reference_type = t,
		.target_file_offset = (target_offset == (unsigned long) -1) ? (unsigned long) -1 : target_offset,
		.referenced_type = UNIQTYPE_IS_POINTER_TYPE(t) ?
				UNIQTYPE_POINTEE_TYPE(t)
				: (struct uniqtype *)(state->ref.seen_how & ~EOP_BITS_MASK)
	};
	unsigned long file_bigallog_sz =
		((uintptr_t) state->file_bigalloc->end - (uintptr_t) state->file_bigalloc->begin);
	assert(the_ref->source_file_offset < file_bigallog_sz);
	printf("Saw a reference within our mapping, at offset 0x%lx, "
		"reference type %s, target offset 0x%lx (absolute: %p)\n",
		(unsigned long) the_ref->source_file_offset,
		UNIQTYPE_NAME(t),
		(unsigned long) the_ref->target_file_offset,
		target);
	return 0;
}
int seen_elf_environ_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link_to_here,
	void *environ_elt_cb_arg_as_void)
{
	struct environ_elt_cb_arg *arg = (struct environ_elt_cb_arg *) environ_elt_cb_arg_as_void;
	struct walk_environ_state *state = arg->state;
	/* When we see an environment element , save it in the buffer. */
	if (state->buf_used == state->buf_capacity)
	{
		unsigned long new_capacity = state->buf_capacity ? state->buf_capacity * 2 : ELF_WALK_REFS_BUF_INITIAL_CAPACITY;
		state->buf = realloc(state->buf, new_capacity * sizeof *state->buf);
		if (!state->buf)
		{
			err(EXIT_FAILURE, "cannot realloc ELF environment buffer");
		}
		state->buf_capacity = new_capacity;
	}
	struct environ_elt *the_elt = &state->buf[state->buf_used++];
	*the_elt = (struct environ_elt) {
		.base = obj,
		.t = t,
		.sz = UNIQTYPE_SIZE_IN_BYTES(t), // FIXME
		.key = arg->key
	};
	printf("Saw an environment element within our mapping, "
		"type %s, key %s\n",
		UNIQTYPE_NAME(t),
		(const char *) arg->key);
	return 0;
}
static int compare_reference_source_address(const void *refent1_as_void, const void *refent2_as_void)
{
	struct elf_reference *r1 = (struct elf_reference *) refent1_as_void;
	struct elf_reference *r2 = (struct elf_reference *) refent2_as_void;
	return (r1->source_file_offset >  r2->source_file_offset) ?
	   1 : (r1->source_file_offset == r2->source_file_offset) ? 0 : -1;
}
static int compare_reference_target_address(const void *refent1_as_void, const void *refent2_as_void)
{
	struct elf_reference *r1 = (struct elf_reference *) refent1_as_void;
	struct elf_reference *r2 = (struct elf_reference *) refent2_as_void;
	return (r1->target_file_offset >  r2->target_file_offset) ?
	   1 : (r1->target_file_offset == r2->target_file_offset) ? 0 : -1;
}
int recursive_print_context_label(char *buf, size_t sz,
	struct alloc_tree_path *path, void *the_alloc,
	struct big_allocation *maybe_the_alloc,
	struct big_allocation *root_empty_name); // forward decl
/* We are walking objects that *might* be reference targets. The reference
 * targets themselves are in a sorted array. */
int __liballocs_name_ref_targets_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link_to_here,
	void *elf_walk_refs_state_as_void)
{
	struct elf_walk_refs_state *state = (struct elf_walk_refs_state *)
		elf_walk_refs_state_as_void;
	uintptr_t our_file_offset = (uintptr_t) obj - (uintptr_t) state->file_bigalloc->begin;
	printf("Checking whether any ref target falls within file offset 0x%lx, type %s\n",
		our_file_offset, UNIQTYPE_NAME(t));
	/* Search the array for a target matching us. What does 'match' mean?
	 * it means we overlap it *and* we match the type. */
	/* HMM. This is a lot of bsearches! for potentially few reference
	 * targets. Is there a better way to record this, maybe as a bitmap?
	 * Let's leave that as an optimisation. */
	// search for the first reference target that is >= us, and examine both
	// it and any later targets that are also >= us
	unsigned our_size = UNIQTYPE_SIZE_IN_BYTES(t);
#define proj(t) (t)->target_file_offset
	// start at the first reference that falls <= our last byte
	struct elf_reference *found_leq = bsearch_leq_generic(struct elf_reference,
		/* target val */ our_file_offset + our_size - 1, /*base */ state->buf, /*n*/ state->buf_used,
		/*proj*/ proj);
#undef proj
	if (found_leq) while (found_leq->target_file_offset >= our_file_offset)
	{
		printf("Considering ref target 0x%lx\n", (unsigned long) found_leq->target_file_offset);
		/* The ref points at or higher than us. Possibly way higher. So test:
		 * do we overlap the ref target? i.e. does the ref fall within our bounds?
		 * If not, skip to the next lower-addressed ref target, which might also
		 * fall within our bounds. */
		if (found_leq->target_file_offset < our_file_offset) break;
		if (found_leq->target_file_offset < our_file_offset + our_size)
		{
			/* OK, we've identified that the reference points within our bounds.
			 * Does the reference expect a thing of our type? */
			if (!found_leq->referenced_type || t == found_leq->referenced_type)
			{
				// OK, we're a match.
				// (What if more than one alloc might match this ref?
				// e.g. if no referenced type is recorded?
				// For now, we free the existing one and replace it, i.e. always
				// choose the lowest nameable thing in the containment tree.
				char buf[4096];
				int ret = recursive_print_context_label(buf, sizeof buf,
					link_to_here, obj, maybe_the_allocation,
					state->file_bigalloc);
				if (ret > 0)
				{
					printf("One of our references is to a thing named %s\n", buf);
					if (found_leq->target_alloc_name)
					{
						printf("Replacing reference target label `%s' with `%s'\n",
							found_leq->target_alloc_name, buf);
						free(found_leq->target_alloc_name);
					}
					found_leq->target_alloc_name = strdup(buf);
				}
				else
				{
					printf("One of our references is to a thing we could not name; offset 0x%lx\n",
						found_leq->target_file_offset);
				}
				// FIXME: use seen_how to get the encoding right
			} else printf("Target type %s does not match ours, %s\n",
				UNIQTYPE_NAME(found_leq->referenced_type), UNIQTYPE_NAME(t));
		}
		// target address gets lower (or equal) each time; don't underrun
		if (found_leq == state->buf) break;
		--found_leq;
	}
	return 0; // keep going
}

static void drain_queued_output(struct emit_asm_ctxt *ctxt, unsigned depth)
{
	for (int i = ctxt->queue_nused - 1; i >= 0; --i)
	{
		if (ctxt->queued_end_output &&
			ctxt->queued_end_output[i].depth >= depth)
		{
			assert(ctxt->queued_end_output[i].output); // should have something here
			puts(ctxt->queued_end_output[i].output);
			free(ctxt->queued_end_output[i].output);
			bzero(&ctxt->queued_end_output[i], sizeof ctxt->queued_end_output[i]);
			--ctxt->queue_nused;
		}
		else break; // queue is in asccending order of depth, so 'one <' means 'all remaining <'
	}
}

static int append_subobject_label(char *buf, size_t sz,
	struct alloc_tree_path *path, void *the_alloc)
{
	assert(path->to_here.containee_coord);
	int nwritten = 0;
	if (UNIQTYPE_IS_COMPOSITE_TYPE(BOU_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype)))
	{
		int ret = strlcat(buf, LINK_UNIQTYPE_FIELD_NAME(&path->to_here), sz);
		assert(ret < sz);
		nwritten += ret;
	}
	else if (UNIQTYPE_IS_ARRAY_TYPE(BOU_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype)))
	{
		int ret = snprintf(buf, sz, "%d", path->to_here.containee_coord - 1);
		assert(ret > 0);
		nwritten += ret;
	}
	else { /* ... */ }
	return nwritten;
}

int recursive_print_context_label(char *buf, size_t sz,
	struct alloc_tree_path *path, void *the_alloc,
	struct big_allocation *maybe_the_alloc,
	struct big_allocation *root_empty_name)
{
	/* Recursively build in 'buf' the label describing
	 * our containment context argument. */
	int nwritten = 0;
	// we are asked to stop at a particular place, which must be a bigalloc
	if (maybe_the_alloc == root_empty_name)
	{
		buf[0] = '\0';
		return 1; // our return value counts the NUL
	}

	if (path->encl)
	{
		int ret = recursive_print_context_label(buf, sz, path->encl, path->to_here.container.base,
			BOU_IS_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype) ?
					BOU_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype)
					: NULL,
			root_empty_name
		);
		if (ret < 0) return ret;
		/* After we do a recursive call, print a dot, sinc we need to do ourselves...
		 * unless the name came back empty */
		assert(ret < sz);
		if (buf[0] != '\0')
		{
			ret = strlcat(buf, ".", sz);
			// now 'ret' is the total length of the combined string with '.' appended
			// where 'length' does not include the NUL
			assert(ret < sz);
			buf = buf + ret;
			sz -= (ret + 1);
			// nwritten DOES include the NUL
			nwritten += (ret+1);
		} else nwritten = ret;
	}
	// now we have 'cont' but not necessary 'cont->encl'
	/* What's the label for our current allocation? */
	// can we get a field name or index #?
	if (BOU_IS_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype))
	{
		nwritten += append_subobject_label(buf, sz, path, the_alloc);
	}
	else
	{
		/* If we're a bona-fide allocation, we may have a name.
		 * We need to ask the allocator. Get it either because
		 * we're also a bigalloc and have allocated_by, or because
		 * our container is a bigalloc that has suballocator. */
		struct big_allocation *containing_bigalloc = BOU_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype);
		struct allocator *a = __liballocs_infer_allocator(the_alloc,
			maybe_the_alloc, containing_bigalloc);
		char namebuf[4096];
		const char *maybe_name = a->get_name ? a->get_name(the_alloc, namebuf, sizeof namebuf)
			: NULL;
		// bail if we hit an allocation with no name -- is this OK?
		if (!maybe_name)
		{
			return -1;
		}
		int ret = snprintf(buf, sz, "%s", maybe_name);
		assert(ret > 0); // empty names not allowed from get_name
		nwritten += ret;
	}
	return nwritten;
}

/* This is called for allocations and subobjects. Always part of a depth-first walk. */
static int emit_memory_asm_cb(struct big_allocation *maybe_the_allocation,
		void *obj, struct uniqtype *t, const void *allocsite,
		struct alloc_tree_link *link_to_here, void *emit_asm_ctxt_as_void)
{
	struct emit_asm_ctxt *ctxt = emit_asm_ctxt_as_void;
	struct alloc_tree_path *path = (struct alloc_tree_path *) link_to_here; // we are doing DF so can downcast
	// -1. flush any queued outputs that are from a depth >= our depth
	drain_queued_output(ctxt, path->encl_depth);
	// 0. pad up to the start
	ptrdiff_t this_obj_offset = (intptr_t) obj - (intptr_t) ctxt->start_address;
	int ret = 0;
	char comment[4096] = "(no comment)"; // FIXME: can change to "allocation" wlog, but not while we're trying to match the diff
	char label[4096] = "";
	char end_label[4096] = "";
	const char *symbolic_ref = NULL;
	// macro for printing into any of the above arrays
#define PRINT_TO_ARRAY(arr, fmt, ...) \
do { int snret = snprintf((arr), sizeof (arr), (fmt) , __VA_ARGS__ ); \
     if (snret >= sizeof (arr)) { (arr)[(sizeof (arr)) - 1] = '\0'; } } while (0)
	// can we get a field name or index #?
	if (BOU_IS_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype))
	{
		if (!path->to_here.containee_coord)
		{
			snprintf(comment, sizeof comment, "BUG: subobj but no coord");
		}
		else
		{
			if (UNIQTYPE_IS_COMPOSITE_TYPE(BOU_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype)))
			{
				PRINT_TO_ARRAY(comment, "field %s", LINK_UNIQTYPE_FIELD_NAME(&path->to_here));
			}
			else if (UNIQTYPE_IS_ARRAY_TYPE(BOU_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype)))
			{
				PRINT_TO_ARRAY(comment, "idx %d", path->to_here.containee_coord - 1);
			}
		}
	}
	// FIXME: this should be cleaner. 'cont' is basically a tree
	// coordinate in memory -- 'maybe_containee_coord' pinpoints
	// a spot within that context -- and what we're doing is simply
	// walking the tree.
	// HACK: we only print a label for arrays or bigallocs
	// or array elements that are themselves composites
	if (BOU_IS_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype)
			|| UNIQTYPE_IS_ARRAY_TYPE(LINK_LOWER_UNIQTYPE(&path->to_here))
			|| (
			    UNIQTYPE_IS_ARRAY_TYPE(LINK_UPPER_UNIQTYPE(&path->to_here))
			    && UNIQTYPE_IS_COMPOSITE_TYPE(LINK_LOWER_UNIQTYPE(&path->to_here)))
		)
	{
		int ret = recursive_print_context_label(label, sizeof label, path,
			obj, maybe_the_allocation, ctxt->file_bigalloc);
		if (ret < 0)
		{
			// HMM. couldn't get the names, so we have no label
			snprintf(label, sizeof label,
				"# could not make a label for the current allocation");
		}
	}

#define indent(n) do { for (int i = 0; i < n+1; ++i) printf(" "); } while (0)
	if (ctxt->emitted_up_to_offset != this_obj_offset)
	{
		ptrdiff_t pad = this_obj_offset - ctxt->emitted_up_to_offset;
		if (pad < 0)
		{
			// union case, so must be a uniqtype; allocs can't overlap
			// (For our hypothetical 'subobjects are another kind of allocation' future:
			// only 'active' subobjects 'are' allocations in a true sense.)
			assert(!BOU_IS_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype));
			struct uniqtype *u = BOU_UNIQTYPE(path->to_here.container.bigalloc_or_uniqtype);
			assert(path->to_here.containee_coord);
			printf("# ASSUMING a union: would need to pad %d bytes for %s of type %s\n",
				(int) pad, comment, UNIQTYPE_NAME(u));
			fflush(stdout);
			// skip this subobject
			ret = 0;
			goto out;
		}
		if (pad > 0)
		{
			indent(path->encl_depth);
			printf(".skip %d # padding before %s of type %s\n",
				(int) pad, comment, UNIQTYPE_NAME(t));
			ctxt->emitted_up_to_offset += pad;
		}
	}
	// We might have a label; if so emit it. We do this before any indentation,
	// so that labels stay flush-left
	if (label[0] != '\0')
	{
		// we have a label
		printf("%s:\n", label);
		// create an end label... will get enqueued as we return
		/* We only emit labels for bigallocs or arrays. NOT 'things
		 * contained in arrays', but really the thing itself.  */
		if (BOU_IS_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype)
				|| UNIQTYPE_IS_ARRAY_TYPE(LINK_LOWER_UNIQTYPE(&path->to_here)) )
		{
			PRINT_TO_ARRAY(end_label, "%s.end", label);
		}
	}

	if (maybe_the_allocation && maybe_the_allocation->suballocator)
	{
		// even if we have a type, we're going to descend further
		// e.g. to a packed_sequence
		ret = 0;
		goto out;
	}

	/* Is this thing a reference? If so, we need to emit it symbolically.
	 * FIXME: feels like we've done this before. We do an up-front walk
	 * of references so that we can emit *referent* labels as we go along. Here we
	 * seem to be emitting the *reference* label. How should this work?
	 * When we did the walk, we gathered a bunch of records:

		struct elf_reference
		{
			unsigned long source_file_offset;
			unsigned long target_file_offset; // may be -1, in theory (shouldn't be, for us)
			const char *target_symname;
			struct uniqtype *referenced_type;
			// HMM: more here
		};

	 * Do those help us emit the reference? Yes I think.
	 * Currently on our walk, we find only three references:

Saw a reference within our mapping, at offset 0x18, type uint$$64, target offset ffffffff
ffffffff (absolute: 0x7f28d7963000, symname (null))
			 -- this is e_entry, which we are failing to resolve because it's a vaddr
			    and not an offset.
Saw a reference within our mapping, at offset 0x20, type uint$$64, target offset 40 (abso
lute: 0x7f28d7562040, symname (null))
			 -- this is e_phoff
Saw a reference within our mapping, at offset 0x28, type uint$$64, target offset 3298 (ab
solute: 0x7f28d7565298, symname (null))
			 -- this is e_shoff

	 * ... but our symname is always null. The easiest way to
	 * compute a symname is using an encl_ chain. So we may need to
	 * (1) gather reference target offsets in one DF walk (when we hit the reference)
	 * (2) gather reference target names in another DF walk (when we hit the referent)
	 * (3) what about references that need to be emitted as a vaddr or some other
	 *     calculation?
	 *     The issue is the dual of interpretation. We need to calculate the representation
	 *     for the reference -- or rather, emit the asm that calculates it. This knowledge is
	 *     in the interpreter. The can_interp() function tells us 'how' the reference has
	 *     been encoded. We need a dual.
	 * This feels conceptually screwy. We are returning an opaque token 'how'
	 * that maps to an encode/decode function. Can we somehow break this out
	 * into something nicer? The fact that we have _or_ in our elf_offset_or_pointer
	 * is a bit of a red flag. Maybe 'how' should just be an index for a single-encoding
	 * function or function pair? Maybe the whole idea of delegateing among interpreters
	 * should be handled by the 'how' and each 'interpreter' proper should handle only
	 * a single encoding?
	 *
	 * What about arguments? E.g. when we have an ELF vaddr, we might be relative to >1
	 * phdr, so we need to say which phdr. In theory there could be an unbounded number
	 * of phdrs, so we can't each to be some reified encoder we can point to. This is an
	 * argument in favour of letting the interpreter control its own 'how'-space.
	 *
	 * What about sizes and lengths? These are references to the end, encoded as offsets
	 * from a start (and maybe with a scale factor for size). Again, *which* start is
	 * significant and belongs in 'how'. Mostly we want to specify a thing in offset-space
	 * (te
	 *
	 * In general the 'environment' stuff seems intended to help us here. Environment
	 * objects can be referenced by their position in the environment buffer, as a more
	 * compact identifier space, if we need this. Also, the idea is that environment
	 * objects can be identified on an up-front depth-first walk, without needing to
	 * resolve any references. Clearly, phdrs count as environment objects because they
	 * are needed to encode vaddrs. But thinking about how 'size' fields are treated as
	 * references, does it mean any random 'size' field requires that the sized thing is
	 * an environment object? Yes, that seems inescapable, since the encoding is relative
	 * to the base of that 'sized' object. I guess it's OK even if every sized object
	 * gets a position in the environment buffer.
	 *
	 * What's our link with reloc recipes R_arch_TAG? These are answers to 'how', too.
	 * In short, reloc records are used when it's not possible to encode the reference,
	 * so we resort to writing a symbolic 'how' in terms of an undefined symbol.
	 *
	 * We can think of a 'how' as a little program, just like a reloc method. But in our
	 * case, we are enumerating those programs, parameterised by a small amount of
	 * argument information that we also encode into the 'how'. Again, like relocs.

+    .quad section.text._start.vaddr # field e_entry

+    .quad initial_segment_base_vaddr + (section.text - ehdr) # field p_vaddr

+    .quad section.text._end - section.text # field p_filesz

+    .quad section.dynamic._end - section.dynamic + section.bss.size # field p_memsz

+   .quad section.text._start.vaddr # field e_entry
+.set section.interp.vaddr, initial_segment_base_vaddr + (section.interp - ehdr)


	 */
	intptr_t interp_how;
	if (0 != (interp_how = can_interp_elf_offset_or_pointer(obj, t, &path->to_here)))
	{
		/* 0. what is it referring to? We've found this before, so find our record. */
#define proj(t) (t)->source_file_offset
		// start at the first reference that falls <= our last byte
		struct elf_reference *found_leq = bsearch_leq_generic(struct elf_reference,
			/* target val */ this_obj_offset,
			/*base */ ctxt->references->buf, /*n*/ ctxt->references->buf_used,
			/*proj*/ proj);
#undef proj
		assert(found_leq);
		while (found_leq->reference_type != t) ++found_leq;
		assert(found_leq && found_leq->source_file_offset == this_obj_offset);
		if (found_leq->target_alloc_name) symbolic_ref = found_leq->target_alloc_name;
		/* For now let's just print the nearest preceding object,
		 * using '+' if we need to create an offset if we need to.
		 * We might need different treatments for:
		 * - when we hit an allocation start but the allocation is not named,
		 *   e.g. a branch into the middle of a packed_seq of instructions:
		 *   instructions aren't named, but rather than writing an
		 *   offset from the section start, which would be fragile,
		 *   we might want to make up an arbitrary name and reference that.
		 * - any more?
		 */
	}

	// we're pre-order; before we descend, print a header
	// FIXME: no postorder so can't easily print an '# end:' comment (or label)
	if (UNIQTYPE_HAS_SUBOBJECTS(t))
	{
		/* We're about to start printing the fields of the present thing */
		indent(path->encl_depth);
		printf("# begin: %s of type %s\n", comment, UNIQTYPE_NAME(t));
		// subobjects get walked separately; we don't have to recurse
	}

	/* handle special-case types */
	/* we use asciiz for top-level char-arrays (sections or other ELF elements)
	 * but not otherwise (e.g. char arrays within a struct). HMM. That's a bit crude.
	 * We check for (roughly) this by testing whether we're directly under a bigalloc.
	 * Ideally we want the ELF section. How can we get the ELF metadata for the
	 * containing allocation? Need to check it's allocated by __elf_element_allocator
	 * and if so, ask it! Ideally we'd have a better way to signal asciizness, since
	 * we want this code one day to work for any memory, not just a mapped ELF binary. */
	if (BOU_IS_BIGALLOC(path->to_here.container.bigalloc_or_uniqtype) &&
			UNIQTYPE_IS_ARRAY_TYPE(t) &&
			(UNIQTYPE_ARRAY_ELEMENT_TYPE(t) == GET_UNIQTYPE_PTR(unsigned_char$$8)
			|| UNIQTYPE_ARRAY_ELEMENT_TYPE(t) == GET_UNIQTYPE_PTR(signed_char$$8)))
	{
		/* split the data on '\0' and write .asciiz, ending in .ascii or .asciiz */
		unsigned off = 0;
		unsigned sz = UNIQTYPE_SIZE_IN_BYTES(t);
		char *found_nul = NULL;
		_Bool indented = 0; // we did this above
		while (off < sz && NULL != (found_nul = memchr(((char*)obj+off), '\0', sz-off)))
		{
			if (!indented) { indent(path->encl_depth); }
			printf(".asciz \"");
			for (char *c = (char*) obj + off; c < found_nul; ++c)
			{
				if (isprint(*c) && *c != '"') putchar(*c);
				else printf("\\%03o", *c);
			}
			printf("\"\n");
			indented = 0;
			off += ((found_nul+1) - (char*) (obj+off));
		}
		// stuff left to do?
		if (!found_nul && off < sz)
		{
			// no nuls left, but ssme chars, so .ascii
			if (!indented) { indent(path->encl_depth); }
			printf(".ascii \"");
			// can't printf (no NUL) so just do a slow but reliable putc loop
			for (char *c = (char*) obj + off; c < (char*) obj + sz; ++c)
			{
				putchar(*c);
			}
			off = sz;
			printf("\"\n");
		}
		ctxt->emitted_up_to_offset += sz;
		ret = -1; // 'cut off this subtree'
		goto out; // finished outputting the thing
	} // we need to AVOID recursing down subobjects

	if (UNIQTYPE_IS_POINTER_TYPE(t))
	{
		// FIXME: need to refer to a label
		/* PROBLEM: */
		printf("# Saw pointer type %s\n", UNIQTYPE_NAME(t));
		fflush(stdout);
		assert(0);
	}
	if (UNIQTYPE_IS_BASE_OR_ENUM_TYPE(t))
	{
		struct uniqtype *b = UNIQTYPE_IS_BASE_TYPE(t) ? t
			: UNIQTYPE_ENUM_BASE_TYPE(t);
		/* TODO: if we're emitting an environment element, don't copy
		 * the data via memcpy; reference it by its assembler symbol,
		 * that we should have (again TODO) created earlier by memcpy. */

		assert(!UNIQTYPE_IS_BIT_GRANULARITY_BASE_TYPE(b));
		_Bool is_signed = UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(b);
#define mkpair(sz, signed) ((sz)<<1 | (signed))
		union {
			__int128_t ss;
			__uint128_t us;
		} literal = { .us = 0 };
		memcpy(&literal, obj, UNIQTYPE_SIZE_IN_BYTES(b));
		indent(path->encl_depth);
		switch (mkpair(UNIQTYPE_SIZE_IN_BYTES(b), is_signed))
		{
			case mkpair(8, 0):
			case mkpair(8, 1):
				printf(".quad "); if (symbolic_ref) printf("%s", symbolic_ref); else printf("%llu", (unsigned long long) literal.us);
				if (!symbolic_ref && is_signed && literal.ss < 0) printf(" # really %lld", (long long) literal.ss);
				ctxt->emitted_up_to_offset += 8;
				break;
			case mkpair(4, 0):
			case mkpair(4, 1):
				printf(".long "); if (symbolic_ref) printf("%s", symbolic_ref); else printf("%lu", (unsigned long) literal.us);
				if (!symbolic_ref && is_signed && literal.ss < 0) printf(" # really %ld", (long) literal.ss);
				ctxt->emitted_up_to_offset += 4;
				break;
			case mkpair(2, 0):
			case mkpair(2, 1):
				printf(".short "); if (symbolic_ref) printf("%s", symbolic_ref); else printf("%hu", (unsigned short) literal.us);
				if (!symbolic_ref && is_signed && literal.ss < 0) printf(" # really %hd", (short) literal.ss);
				ctxt->emitted_up_to_offset += 2;
				break;
			case mkpair(1, 0):
			case mkpair(1, 1):
				printf(".byte "); if (symbolic_ref) printf("%s", symbolic_ref); else printf("%hhu", (unsigned char) literal.us);
				if (!symbolic_ref && is_signed && literal.ss < 0) printf(" # really %hhd", (signed char) literal.ss);
				ctxt->emitted_up_to_offset += 1;
				break;
			default:
				fprintf(stderr, "Saw surprising size: %u\n", (unsigned) UNIQTYPE_SIZE_IN_BYTES(b));
				abort();
		}
		printf(" # %s\n", comment);
#undef mkpair
		/* Integers might be 'pointers' (offsets) too -- it depends on the interpretation
		 * that we're making. How does this work?
		 *
		 * As a built-in liballocs has an "address resolver" that knows how to resolve
		 * pointers to addresses.
		 *
		 * But in our mapped ELF file we can also have an "offset resolver"
		 * that knows how to resolve "fields that are really file offsets"
		 * into their corresponding pointer.
		 * What does this look like? E.g. how do we say "this knows how to
		 * resolve offsets in structures of the following Elf_* types"?
		 */
		// We have
		/*
		      walk_subobjects_spanning
		      walk_subobjects_spanning_rec
		      first_subobject_spanning
		      find_matching_subobject

		   ... what's the relationship between these?

		   Clearly the "spanning" is a search: we home in on only those subobjects
		   that span a particular offset.
		   Is "find_matching" a generalisation of that?
		   Can we maybe macroise so that
		   "spans_offset" is a matching criterion, and
		   "has_type" (or whatever find_matching_subobject cares about) is also one?
		   Also remember that those functions do a binary search over the contained
		   stuff (also accounting for unions, to some extent)
		   whereas 'walk_references' is a linear search.
		 */
	}
out:
	if (end_label[0] != '\0')
	{
		if (ctxt->queue_nused == ctxt->queue_size)
		{
			ctxt->queue_size = (ctxt->queue_size ? 4 * ctxt->queue_size : 4);
			ctxt->queued_end_output = realloc(ctxt->queued_end_output,
				ctxt->queue_size * sizeof (*ctxt->queued_end_output)
			);
			if (!ctxt->queued_end_output) err(EXIT_FAILURE, "could not realloc ctxt->queued_end_output");
		}
		int idx = ctxt->queue_nused++;
		ctxt->queued_end_output[idx].depth = path->encl_depth;
		asprintf(&ctxt->queued_end_output[idx].output, "%s:", end_label); // next line will indent
	}
	return ret;
}

int main(void)
{
	// assert our meta-object has been loaded, since we can't work without it?
	// FIXME: we now link in our usedtypes, but that doesn't help because
	// we didn't finish the macro magic that would make them actually used;
	// instead we still do need the meta-DSO
	debug = getenv("DEBUG");
	assert(NULL != dlopen(__liballocs_meta_libfile_name(__runt_get_exe_realpath()), RTLD_NOW|RTLD_NOLOAD));
	char *path = getenv("ELF_FILE_TEST_DSO");
	if (!path) path = getenv("LIBALLOCS_BUILD");
	assert(path && "test lib should be loaded with ELF_FILE_TEST_DSO or LIBALLOCS_BUILD set");
	int fd = open(path, O_RDONLY);
	assert(fd != -1);
	struct stat s;
	int ret = fstat(fd, &s);
	assert(ret == 0);
	size_t len = ROUND_UP(s.st_size, COMMON_PAGE_SIZE);
	void *mapping = mmap(NULL, len, MAP_SHARED,
		PROT_READ, fd, 0);
	assert((intptr_t) mapping > 0);
	struct big_allocation *b = elf_adopt_mapping_sequence(mapping, len, 0);
	assert(b);
	struct uniqtype *u = elf_get_type(mapping);
	assert(u == elf_file_type_table[ELF_DATA_EHDR]);
	printf("ELF file at %p (%s) has %d allocations\n",
		mapping, path,
		((struct elf_elements_metadata *) b->suballocator_private)->metavector_size
	);
	/* Let's dump the ELF header fieldwise as assembly, just for fun.
	 * How should this work?
	 * In general we want to recursively walk the allocation tree
	 * until we get down to primitives, i.e. we want to walk even
	 * under the uniqtype level. For each primitive, we use an assembly
	 * directive to output its data. */
	uintptr_t asm_cursor_addr = (uintptr_t) mapping;
	/* How can we ensure that __uniqtype__Elf64_Ehdr will be generated and
	 * loaded? For now we have put a hack into lib-test, but we need to
	 * ensure meta-objects have been loaded. */
	struct alloc_tree_pos scope = {
		.base = b->begin,
		.bigalloc_or_uniqtype = (uintptr_t) b
	};
	/* Walk references, to get the pointer targets. We do this using the stock
	 * __liballocs_walk_refs_cb.
	 * For each reference we find, we append a record to our buffer,
	 * recording various things about its source and target. 
	 * Once we have all the targets, we do *another* DF walk, but *not*
	 * walking references, but rather, walking targets. For anything that is a
	 * target, we snarf its name. (Problem: where in the tree counts? Well, we
	 * recorded the type, so that'll do.) */
	struct interpreter elf_offset_or_pointer_resolver = {
		.name = "ELF-offset-or-pointer interpreter",
		.can_interp = can_interp_elf_offset_or_pointer,
		.do_interp = do_interp_elf_offset_or_pointer,
		.may_contain = may_contain_elf_offset_or_pointer,
		.is_environ = is_environ_elf_offset_or_pointer
	};
	struct elf_walk_refs_state reference_state = {
		.ref = (struct walk_refs_state) {
			.interp = &elf_offset_or_pointer_resolver,
			.ref_cb = seen_elf_reference_or_pointer_cb
			/* cb arg is always just the reference state */
		},
		.buf = NULL,
		.buf_capacity = 0,
		.buf_used = 0,
		.file_bigalloc = b
	};
	struct walk_environ_state environ_state = {
		.interp = &elf_offset_or_pointer_resolver,
		.environ_cb = seen_elf_environ_cb,
		.buf = NULL,
		.buf_capacity = 0,
		.buf_used = 0
	};
	// also __liballocs_walk_down_at( ... ) which privately uses an offset-based helper
	/* Gather 'environment' info, i.e. stuff that we need in order to decode
	 * references a.k.a. offsets-or-pointers. Am not entirely sure that this step is sane.
	 * The issue is possibly that we need to emit references *symbolically*,
	 * so we need to gather knowledge that will let us *generate* those symbols (labels *references*). */
	__liballocs_walk_allocations_df(
		&scope,
		__liballocs_walk_environ_cb,
		&environ_state
	);
	printf("Saw %u environment elements on our walk\n", (unsigned) environ_state.buf_used);
	/* Now gather references themselves. The idea is that we need incoming
	 * references so that we can emit label *definitions* as we go along. */
	__liballocs_walk_allocations_df(
		&scope,
		__liballocs_walk_refs_cb, // generic cb takes a struct walk_environ_state * arg, as void
		&reference_state          // ... which our seen_... cb it will get by casting this guy
	);
	printf("Saw %u references on our walk\n", (unsigned) reference_state.buf_used);
	// now sort the refs buffer by its target offset
	qsort(reference_state.buf, reference_state.buf_used, sizeof *reference_state.buf,
		compare_reference_target_address);
	// now look for ref targets
	__liballocs_walk_allocations_df(
		&scope,
		__liballocs_name_ref_targets_cb,
		&reference_state
	);
	/* Now sort the refs buffer by its source offset, so we can find
	 * ourselves as we do another DF walk. */
	qsort(reference_state.buf, reference_state.buf_used, sizeof *reference_state.buf,
		compare_reference_source_address);
	sleep(3);
	/* Walk allocations. */
	struct emit_asm_ctxt ctxt = {
		.start_address = mapping,
		.emitted_up_to_offset = 0,
		//.overall_comment = "ELF element",
		.depth = 0,
		.references = &reference_state, // HMM, we chain ctxts to...
		.file_bigalloc = b
	};
	__liballocs_walk_allocations_df(
		&scope,
		emit_memory_asm_cb,
		&ctxt
	);
	drain_queued_output(&ctxt, 0);
	if (ctxt.queued_end_output) free(ctxt.queued_end_output);
	if (reference_state.buf)
	{
		// FIXME: free anything allocated per-record as well
		for (unsigned i = 0; i < reference_state.buf_used; ++i)
		{
			void *nameptr = reference_state.buf[i].target_alloc_name;
			if (nameptr) free(nameptr);
		}
		free(reference_state.buf);
	}
}
