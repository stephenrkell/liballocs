/*
This is the license for uniqtype.h, part of a definition of 
run-time type information for compiled code.

Copyright 2011--16, Stephen Kell <stephen.kell@cl.cam.ac.uk>

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both the copyright notice and this permission notice and warranty
disclaimer appear in supporting documentation, and that the name of
the above copyright holders, or their entities, not be used in
advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

The above copyright holders disclaim all warranties with regard to
this software, including all implied warranties of merchantability and
fitness. In no event shall the above copyright holders be liable for
any special, indirect or consequential damages or any damages
whatsoever resulting from loss of use, data or profits, whether in an
action of contract, negligence or other tortious action, arising out
of or in connection with the use or performance of this software.
*/

#ifndef UNIQTYPE_H_
#define UNIQTYPE_H_

#include "uniqtype-defs.h"

#include <elf.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

// #include "dlbind.h"
void *dlcreate(const char *libname);
void *dlreload(void *handle);
void *dlalloc(void *l, size_t sz, unsigned flags);
void *dlbind(void *lib, const char *symname, void *obj, size_t len, Elf64_Word type);

/* We want this inline to be COMDAT'd and global-overridden to a unique run-time instance.
 * But HMM, we will get the same problem as with uniqtypes: between the preloaded library
 * and the executable, we won't get uniquing. I think this is okay.
 * 
 * HMM. This function relies on elf.h, liballocs, libdlbind, libdl and libc.
 * How to deal with the includes? And with supplying the dependencies at link time? 
 * It's not silly to link -ldl -ldlbind -lallocs, passing the .so files for each.
 * 
 * We instantiate this function (using "extern inline") in any typeobj. Do we? 
 *
 * NOTE also that this code needs to be C++-clean, because we include this header
 * in uniqtypes.cpp. */

extern void *__liballocs_rt_uniqtypes_obj __attribute__((weak));

inline
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
	
	/* Does such a type exist? */
	void *found = NULL;
	if (NULL != (found = dlsym(NULL, precise_uniqtype_name)))
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
		void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
			allocated, sz, STT_OBJECT);
		assert(reloaded);
		
		return allocated_uniqtype;
	}
}

inline 
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

	/* Some notes on make_precise:
	 *
	 * We can generate the make_precise function in specific DWARF contexts that require
	 * it. For example, if a DW_TAG_subrange_type has a DW_AT_upper_bound that refers 
	 * to an in-scope DW_TAG_member, we can use this to generate a function from
	 * the member to the precise subrange type's bounds.
	 * 
	 * QUESTION: how are dynamically-generated uniqtypes garbage-collected?
	 * Here we seem to compute them on-demand, writing them into caller-supplied
	 * memory. Do we want to memoise this? That would change the signature a bit.
	 * 
	 * make_precise is a direct refinement of the C model, in which an object is either
	 * "incomplete" (implicitly possibly data-dependent) 
	 * or "complete" (completely manifest). 
	 * A continuum is defined by how much context is necessary to decode the structure.
	 * The current make_precise prototype assumes the object memory itself, combined with the
	 * machine registers in mcontext, are good enough to bootstrap context discovery. 
	 * This isn't always good enough: an XOR-doubly-linked-list would require "reached-from" 
	 * context, and it's intractable to recover that in general.)
	 * 
	 * Everything in dyn_* is a transcoding of something expressed declaratively
	 * in (hypothetically-extended-)DWARF. So we need not view them as arbitrary programs.
	 * E.g. we could ensure they have no backward branches (perhaps), do not access
	 * memory outside the object's footprint (ditto), etc..
	 * We could even express them in some dependently-typed formalism.
	 * We just choose native instructions as the run-time representation within uniqtypes, because
	 * we can be fairly confident that those instructions are understood at runtime
	 * (even in an out-of-process debugger, which likely has an instruction emulator).
	 * 
	 * We're currently lacking a strong notion of read- or write- validity (outside of unions,
	 * which have read-validity). 
	 * We can perhaps borrow a notion of allocations as framing here.
	 * If I have a char[], say, that is supposed to be NUL-terminated,
	 * we can say it's terminated 
	 * *either* by the extent of its containing allocation 
	 * *or* by NUL, whichever comes first.
	 * This generalises to a "proper nesting": an object never extends beyond 
	 * its containing allocation.
	 * So what should "make_precise" tell us?
	 * Presumably it needs to tell us that
	 * the first n, up to the NUL, are readable
	 * and the whole m, up to the bounds of the allocation, are writable.
	 * 
	 * A similar story comes up with updates.
	 * Suppose we have a uniqtype representing ELF auxv as a record.
	 * We can have make_precise tell us which members are present.
	 * But how can the uniqtype helps us change the value, to include a new key (say)?
	 * We need some kind of "metavalue", or interpreted representation of values,
	 * that can be plonked down into the concrete representation, i.e. a "semantic copy",
	 * perhaps using a near-dual operation of make_precise ("synthesize_rep", say).
	 * So far I have mentally been using (uniqtype, void*, len) triples as metavalues.
	 * Is that good enough?
	 * Perhaps; "synthesize_rep" might just be a transcode request, i.e. semantic copy: 
	 * transcode this abstract content into this representation.
	 * The "abstract content" is what we get by interpreting the uniqtype at a high level, 
	 * i.e. as a sequence (structs, arrays), a mathematical number (base types), etc..
	 *
	 * A question about register locals in stack frames:
	 * Given a struct mcontext, we can represent the "address" of a register local
	 * as its address within the mcontext.
	 * This means a query via mcontext entails copying out the whole uniqtype,
	 * and doesn't really make explicit the register assignment.
	 * In fact, since fields are represented as offsets rather than addresses,
	 * we're already in difficulty. 
	 * (We could compute a 64-bit offset from the base, but that's nasty.)
	 * Seems we need a story on "noncontiguous fields", or on the "fragment" versus "object"
	 * distinction.
	 * If we adopt the "same object, different fragments" view of register locals, 
	 * we might want make_precise to tell us about the other fragments of that object.
	 * We might want uniqtypes to know about fragments.
	 * Or we might want to keep the "object" (not fragment) model as a wholly separate layer.
	 * I do rather favour the latter.
	 * 
	 * What about DW_OP_piece? Does that have consequences for uniqtypes?
	 * It's mostly used in register locals, so it's the same problem,
	 * EXCEPT that one field (i.e. uniqtype element) might span multiple fragments (pieces).
	 * That might be an argument in favour of baking together fragments with uniqtypes/allocations.
	 * 
	 * Another example of fragments is C++ virtual inheritance: usually it's
	 * the same chunk of memory, but plumbed together with internal pointers. Could imagine
	 * different chunks of memory, though.
	 * 
	 * Can say that dynamically made-precise uniqtypes can reference 
	 * allocation-external pieces.
	 * HMM: doesn't solve the pieces thing. One field might have >1 address!
	 * i.e. part in register, part in memory.
	 * Need to describe the pieces -- no avoiding it.
	 * Could compile the DWARF into a reader/writer function pair, but that's very opaque.
	 */

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
