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

#include "elf-allocators.h"

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
static Elf64_Ehdr ehdr __attribute__((used));
static Elf64_Shdr shdr[1] __attribute__((used));
static Elf64_Phdr phdr[1] __attribute__((used));
static struct Elf64_Nhdr_with_data {
        Elf64_Nhdr nhdr[1];
        char data[];
} __attribute__((packed)) nhdr_with_data[1] __attribute__((used));
static Elf64_Sym sym[1] __attribute__((used));
static Elf64_Rela rela[1] __attribute__((used));
static Elf64_Rel rel[1] __attribute__((used));
static Elf64_Dyn dyn[1] __attribute__((used));
static void (*fp)(void) __attribute__((used));
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

// define the K-V lookup using the enum as indices into an array
struct uniqtype *elf_file_type_table[ELF_DATA_NTYPES];

__attribute__((constructor))
static void init_elf_file_type_table(void)
{
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

static void free_elf_elements_metadata(void *elf_elements_metadata_as_void)
{
	struct elf_elements_metadata *m = (struct elf_elements_metadata *) elf_elements_metadata_as_void;
	free(m->metavector);
	free(m);
}

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
