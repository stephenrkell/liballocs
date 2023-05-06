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
#include "emit-asm.h"

int compare_reference_source_address(const void *refent1_as_void, const void *refent2_as_void)
{
	struct elf_reference *r1 = (struct elf_reference *) refent1_as_void;
	struct elf_reference *r2 = (struct elf_reference *) refent2_as_void;
	return (r1->source_file_offset >  r2->source_file_offset) ?
	   1 : (r1->source_file_offset == r2->source_file_offset) ? 0 : -1;
}
int compare_reference_target_address(const void *refent1_as_void, const void *refent2_as_void)
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

void drain_queued_output(struct emit_asm_ctxt *ctxt, unsigned depth)
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
int emit_memory_asm_cb(struct big_allocation *maybe_the_allocation,
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
	 * (in seen_elf_reference_or_pointer_cb)

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

	 * ... but our symname is always null. (The symname has now been removed.)
	 * We don't currently know how to emit a symbolic name for the target.
	 *
	 * The easiest way to compute a symname is using an encl_ chain. So we may need to
	 * (1) gather reference target offsets in one DF walk (when we hit the reference)
	 *       -- we do this currently I think
	 * (2) gather reference target names in another DF walk (when we hit the referent)
	 *       -- we don't do this yet -- OR maybe we do? __liballocs_name_ref_targets_cb
	 *       -- by 'gather', what do we do about storing this information?
	 *       -- since we will have the encl_ chain at the point of reaching the referent,
	 *          we could compute a name as we go, but where would we put it?
	 * (3) what about references that need to be emitted as a vaddr or some other
	 *     calculation?
	 *     i.e. "something about how the reference is [to be] encoded".
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

