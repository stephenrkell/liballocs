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
#include "elf-refs.h"

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
	EOP_BITS_MASK = 0x7 /* all bits that we might use to encode the 'how' */
};
intptr_t can_interp_elf_offset_or_pointer(void *exp, struct uniqtype *exp_t,
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
	if (/*debug*/ 1)
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
