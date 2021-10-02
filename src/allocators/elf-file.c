#define _GNU_SOURCE
#include <elf.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "liballocs.h"
#include "liballocs_private.h"
#include "allocmeta.h"
#include "relf.h"

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
#define elf_file_data_types(v) \
v(EHDR, ElfW(Ehdr), /* is array? */ 0) \
v(SHDRS, ElfW(Shdr), 1) \
v(PHDRS, ElfW(Phdr), 1) \
v(NHDR, ElfW(Nhdr), 0) \
v(SYMS, ElfW(Sym), 1) \
v(RELAS, ElfW(Rela), 1) \
v(RELS, ElfW(Rel), 1) \
v(DYNAMICS, ElfW(Dyn), 1) \
v(FUNPTRVVS, __PTR___FUN_FROM___FUN_TO_void, 1) \
v(BYTES, unsigned_char$8, 1)

// define an enum -- ignoring the second argument
#define elf_file_data_types_enum_entry(tag, tfrag, tisarray) \
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

#define elf_file_data_types_table_entry_init(tag, tfrag, tisarray) { \
	elf_file_type_table[ELF_DATA_ ## tag] = (tisarray) \
	    ? __liballocs_get_or_create_unbounded_array_type( ({ \
	        struct uniqtype *tmp_u = fake_dlsym(RTLD_DEFAULT, "__uniqtype__" stringifx(tfrag) ); \
	        assert(tmp_u); assert(tmp_u != (void*)-1); tmp_u; }) ) \
	    : fake_dlsym(RTLD_DEFAULT, "__uniqtype__" stringifx(tfrag) ); \
	assert(elf_file_type_table[ELF_DATA_ ## tag]); \
	assert(elf_file_type_table[ELF_DATA_ ## tag] != (void*)-1); \
	}
	elf_file_data_types(elf_file_data_types_table_entry_init)
}

struct elf_metavector_entry
{
	ElfW(Word) fileoff;
	unsigned size:28; // 256MB; too stingy? if so, borrow a few bits from fileoff
	unsigned type_idx:4;
} __attribute__((packed));

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
	unsigned metavector_size;
	struct elf_metavector_entry *metavector;
	bitmap_word_t bitmap[];
};

static void free_elf_elements_metadata(void *elf_elements_metadata_as_void)
{
	struct elf_elements_metadata *m = (struct elf_elements_metadata *) elf_elements_metadata_as_void;
	__private_free(m->metavector);
	__private_free(m);
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
// FIXME: we're not accounting for the starting address of the range.
#define BITMAP_NWORDS(nbytes_spanned, align) \
	DIV_ROUNDING_UP( \
	   DIV_ROUNDING_UP(nbytes_spanned, align), \
	   BITMAP_WORD_NBITS \
	)
	struct meta_info file_info = {
		.what = DATA_PTR,
		.un = { opaque_data: { .data_ptr = __builtin_return_address(0), .free_func = NULL } }
	};
	struct elf_elements_metadata *elf_meta = malloc(offsetof(struct elf_elements_metadata, bitmap)
			+ sizeof (bitmap_word_t) * BITMAP_NWORDS(mapping_len + trailing_mapping_len, 1));
	elf_meta->metavector = __private_malloc(metavector_nentries * sizeof *elf_meta->metavector);
	// create the bigalloc
	struct big_allocation *elf_b = __liballocs_new_bigalloc(
		mapping_start, mapping_len + trailing_mapping_len,
		file_info,
		mseq_b,
		&__elf_file_allocator);
	assert(elf_b);
	elf_b->suballocator = &__elf_element_allocator;
	elf_b->suballocator_private = elf_meta;
	elf_b->suballocator_private_free = free_elf_elements_metadata;
	

	// HMM. We assume we're adding in address order, but I don't think that's the case
	unsigned metavector_ctr = 0;
#define add_allocation_o(offset, thesize, typetag) do { \
	elf_meta->metavector[metavector_ctr++] = (struct elf_metavector_entry) {\
	.fileoff = (offset), \
	.size = (thesize), \
	.type_idx = ELF_DATA_ ## typetag \
	}; \
	assert(!(bitmap_get_b(elf_meta->bitmap, offset))); \
	bitmap_set_b(elf_meta->bitmap, offset); \
	} while(0)
#define add_allocation_p(addr, size, typetag) \
	add_allocation_o((uintptr_t)(addr) - (uintptr_t) mapping_start, size, typetag)
	// set up metadata for our ELF file:
	// 1. metavector
	// 2. bitmap
	// 3. free list -- by iterating over metavector and differencing lengths
	add_allocation_p(ehdr, ehdr->e_ehsize, EHDR);
	if (ehdr->e_shoff)
	{
		ElfW(Shdr) *shdrs = (ElfW(Shdr)*)((uintptr_t) ehdr + ehdr->e_shoff);
		add_allocation_p(shdrs, ehdr->e_shnum * ehdr->e_shentsize, SHDRS);
		assert(ehdr->e_shentsize == sizeof (ElfW(Shdr)));
		for (unsigned i = 1; i < ehdr->e_shnum; ++i)
		{
			if (SHDR_IS_MANIFEST(shdrs[i]))
			{
				char *addr = (char*)((uintptr_t) ehdr + shdrs[i].sh_offset);
				switch (shdrs[i].sh_type)
				{
					case SHT_NOTE:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, NHDR); // FIXME: not quite right
						break;
					case SHT_DYNSYM:
					case SHT_SYMTAB:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, SYMS); break;
					case SHT_RELA:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, RELAS); break;
					case SHT_DYNAMIC:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, DYNAMICS); break;
					case SHT_NOBITS: assert(0 && "nobits should not be manifest");
					case SHT_REL:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, RELS); break;
					case SHT_SHLIB: assert(0 && "SHT_SHLIB should not be used");
					case SHT_INIT_ARRAY:
					case SHT_FINI_ARRAY:
					case SHT_PREINIT_ARRAY:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, FUNPTRVVS); break;
					// for now, other sections are just bytes
					case SHT_GROUP:
					case SHT_SYMTAB_SHNDX:
					case SHT_PROGBITS:
					case SHT_STRTAB:
					case SHT_HASH:
					default:
						add_allocation_o(shdrs[i].sh_offset, shdrs[i].sh_size, BYTES); break;
				}
			}
		}
	}
	if (ehdr->e_phoff)
	{
		assert(ehdr->e_phentsize == sizeof (ElfW(Phdr)));
		add_allocation_o(ehdr->e_phoff, ehdr->e_phnum * ehdr->e_phentsize, PHDRS);
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

static
struct uniqtype *elf_get_type(void *obj)
{
	struct big_allocation *b = __lookup_bigalloc_from_root(obj,
		&__elf_file_allocator, NULL);
	if (!b) return NULL;
	struct elf_elements_metadata *meta = (struct elf_elements_metadata *) b->suballocator_private;
	uintptr_t target_offset = (uintptr_t) obj - (uintptr_t) b->begin;
#define offset_from_rec(p) (p)->fileoff
	struct elf_metavector_entry *found = bsearch_leq_generic(struct elf_metavector_entry, target_offset,
		/* T* */ meta->metavector, meta->metavector_size, offset_from_rec);
	if (found) return elf_file_type_table[found->type_idx];
	return NULL;
}

static
void *elf_get_base(void *obj);

static
unsigned long *elf_get_size(void *obj);

/* Getting a name makes sense... sections have names, though
 * header tables don't. One caveat is that section names don't
 * need to be unique. Maybe get_name functions should warn when
 * they generate a non-unique name?
 */
static
const char *elf_get_name(void *obj);


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

/* */
static int elf_elements_walk_allocations(void *bigalloc_as_void, uintptr_t ignored,
	walk_alloc_cb_t *cb, void *arg)
{
	struct big_allocation *arena = (struct big_allocation *) bigalloc_as_void;
	struct elf_elements_metadata *elements_meta
		 = (struct elf_elements_metadata *) arena->suballocator_private;
	int ret = 0;
	for (struct elf_metavector_entry *e = elements_meta->metavector;
			e != elements_meta->metavector + elements_meta->metavector_size;
			++e)
	{
		ret = cb(
			(void*)((uintptr_t) arena->begin + e->fileoff),
			elf_file_type_table[e->type_idx],
			arena->meta.un.opaque_data.data_ptr /* alloc site */,
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
	.walk_allocations = elf_elements_walk_allocations
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

#ifdef TEST
#ifdef NDEBUG
#error "Must use assertions for test case; turn off -DNDEBUG"
#endif

struct memory_asm_ctxt
{
	const char *overall_comment;
	unsigned depth;
	// FIXME: need to thread through a summary of incoming references,
	// so that we can emit labels as we go along
};

static int emit_memory_asm(void *base, struct uniqtype *t, const void *allocsite, void *memory_asm_ctxt_as_void)
{
	struct memory_asm_ctxt *ctxt = memory_asm_ctxt_as_void;
	// recursive case
#define indent(n) do { for (int i = 0; i < n; ++i) printf(" "); } while (0)
	if (UNIQTYPE_HAS_SUBOBJECTS(t))
	{
		uintptr_t emitted_up_to = (uintptr_t) base;
		indent(ctxt->depth);
		printf("# begin: %s of type %s\n", ctxt->overall_comment, UNIQTYPE_NAME(t));
#define per_subobj_thing(_i, _t, _offs) \
	{ uintptr_t this_subobj_base = (uintptr_t) base + (_offs); \
	 /* We may need to emit some padding. */ \
	 ptrdiff_t pad = this_subobj_base - emitted_up_to; \
	 char *field_name = NULL; \
	 if (UNIQTYPE_IS_ARRAY_TYPE(/*really t!*/t)) asprintf(&field_name, "idx %d", (_i)); \
	 else asprintf(&field_name, "field %s", UNIQTYPE_COMPOSITE_SUBOBJ_NAMES(/*really t!*/(t))[(_i)]); \
	 assert(pad >= 0); \
	 if (pad > 0) { \
	    printf(".skip %d # padding before %s\n", (int) pad, field_name); \
	    emitted_up_to += pad; \
	 } \
	 struct memory_asm_ctxt new_ctxt; memcpy(&new_ctxt, ctxt, sizeof *ctxt); \
	 new_ctxt.overall_comment = field_name; \
	 ++new_ctxt.depth; \
	 emit_memory_asm((void*) this_subobj_base, (_t), allocsite, &new_ctxt); \
	 free(field_name); \
	 emitted_up_to += UNIQTYPE_SIZE_IN_BYTES(_t); }
		/* What if we have an unspecified-length array? We don't need to
		 * make-precise it. Instead we have the length in a side channel. */
		UNIQTYPE_FOR_EACH_SUBOBJECT(t,
			per_subobj_thing);
#undef per_subobj_thing
		indent(ctxt->depth);
		printf("# end: %s\n", ctxt->overall_comment);
		return 0;
	}
	if (UNIQTYPE_IS_POINTER_TYPE(t))
	{
		// FIXME: need to refer to a label
		assert(0);
	}
	else if (UNIQTYPE_IS_BASE_OR_ENUM_TYPE(t))
	{
		struct uniqtype *b = UNIQTYPE_IS_BASE_TYPE(t) ? t
			: UNIQTYPE_ENUM_BASE_TYPE(t);
		assert(!UNIQTYPE_IS_BIT_GRANULARITY_BASE_TYPE(b));
		_Bool is_signed = UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(b);
#define mkpair(sz, signed) ((sz)<<1 | (signed))
		union {
			__int128_t ss;
			__uint128_t us;
		} data = { us: 0 };
		memcpy(&data, base, UNIQTYPE_SIZE_IN_BYTES(b));
		indent(ctxt->depth);
		switch (mkpair(UNIQTYPE_SIZE_IN_BYTES(b), is_signed))
		{
			case mkpair(8, 0):
			case mkpair(8, 1):
				printf(".quad %llu # %s", (unsigned long long) data.us, ctxt->overall_comment);
				if (is_signed && data.ss < 0) printf(" # really %lld\n", (long long) data.ss); else printf("\n");
				break;
			case mkpair(4, 0):
			case mkpair(4, 1):
				printf(".long %lu # %s", (unsigned long) data.us, ctxt->overall_comment);
				if (is_signed && data.ss < 0) printf(" # really %ld\n", (long) data.ss); else printf("\n");
				break;
			case mkpair(2, 0):
			case mkpair(2, 1):
				printf(".short %hu # %s", (unsigned short) data.us, ctxt->overall_comment);
				if (is_signed && data.ss < 0) printf(" # really %hd\n", (short) data.ss); else printf("\n");
				break;
			case mkpair(1, 0):
			case mkpair(1, 1):
				printf(".byte %hhu # %s ", (unsigned char) data.us, ctxt->overall_comment);
				if (is_signed && data.ss < 0) printf(" # really %hhd\n", (signed char) data.ss); else printf("\n");
				break;
			default:
				debug_printf(0, "Saw surprising size: %u\n", (unsigned) UNIQTYPE_SIZE_IN_BYTES(b));
				abort();
		}
#undef mkpair
		/* FIXME: these might be 'pointers' (offsets) too -- it depends on the interpretation
		 * that we're making. How does this work?
		 *
		 * Recall: a resolver is an interpreter of naming languages, which are
		 * distinguished from computational languages only by the computational
		 * complexity ("linear in the length of the name"). A resolver is also an
		 * idempotent allocator, i.e. it creates the name's denotation in memory,
		 * only if it is not already available in memory (fsvo 'available').
		 *
		 * As a built-in we have an "address resolver" that knows how to resolve
		 * pointers to addresses.
		 *
		 * But in our mapped ELF file we can also have an "offset resolver"
		 * that knows how to resolve "fields that are really file offsets"
		 * into their corresponding pointer.
		 * What does this look like? E.g. how do we say "this knows how to
		 * resolve offsets in structures of the following Elf_* types"?
		 *
		 * Am imagining a
		 *
		 *        can_resolve( p, type, containment_ctxt )
		 *
		 * and a
		 *
		 *        do_resolve(p, type, containment_ctxt )
		 *
		 * and also something that can walk references stored within any allocation...
		 * maybe that is the best way to conceptualise the resolver first of all.
		 *
		 * A walkable allocation is either a bigalloc or a typealloc.
		 * If it's a bigalloc, we walk it using per-allocator operations.
		 * If it's a typealloc, in theory the same operations will do once we have an
		 *   "allocator view" of uniqtypes. But maybe let's split the cases here for now.
		 *
		 *        walk_references( p, type, resolver )
		 *
		 * To represent a typealloc we need a pair of pointers: the object, and
		 * the uniqtype describing that object (perhaps deep in a nest, but containment
		 * isn't a recursive relation).
		 */
#if 0
		struct interpreter pointer_resolver = (struct interpreter) {
			.can_interpret = ,
			.do_interpret = 
		};

		walk_references(mapping, type_or_bigalloc, elf_offset_resolver)
#endif
		// HMM. What are we calling this "walk_references" method on?
		// It seems to be a generic function over an arbitrary piece of
		// memory. Maybe that is right?
		// We haven't said what to do when we find a reference. Maybe a
		// callback?
		// I guess walk_references, in the typealloc case, is a recursive
		// function very much like what we're doing now, which is walking
		// 'physical data'. We're just looking for different things.
		// For any subobject, the first thing we do is ask whether our
		// resolver can resolve it. If it can, we cut off the exploration
		// there.
		// We need to thread through the containment context, because our
		// resolver needs it.
		// Is a pointer to a 'struct related' enough context? No, we need
		// the containing uniqtype pointer too.
		// Still want a core "enumerate subobjects". Is our macro good
		// enough? Not quite, because it doesn't know about the resolver.
		// PULL in our liballocs inlines for walking subobjects, somehow.
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
	else
	{
		debug_printf(0, "Saw strange uniqtype: %s\n", UNIQTYPE_NAME(t));
		abort();
	}
	return 0;
}

__attribute__((constructor))
static void init(void)
{
	char *path = getenv("LIBALLOCS_BUILD");
	assert(path && "test lib should be loaded with LIBALLOCS_BUILD set");
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
	__static_file_allocator_init();
	struct memory_asm_ctxt initial_ctxt = { .overall_comment = "ELF element", .depth = 0 };
	/* Walk allocations. */
	__liballocs_walk_allocations(
		b,
		ALLOC_WALK_SUBALLOCS,
		emit_memory_asm,
		&initial_ctxt
	);
}

#endif
