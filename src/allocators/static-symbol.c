#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <link.h>
#include "relf.h"
#include "liballocs_private.h"
#include "pageindex.h"
#include "raw-syscalls-defs.h"
#include "allocmeta-defs.h"
#include "allocmeta.h"

static _Bool trying_to_initialize;
static _Bool initialized;
void ( __attribute__((constructor(102))) __static_symbol_allocator_init)(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__mmap_allocator_init();
		__static_segment_allocator_init();
		__static_section_allocator_init();
		initialized = 1;
		trying_to_initialize = 0;
	}
}

/* How to make our new static allocs work.
 * 
 * - write the bitmap-generating code (in metavector is fine)
 * - make the metavector per-segment
 * - make the metavector dump tool print out a nice summary
 * - make the startup code below also print out a nice summary, and *test*-compare them
 * - write a segment-level query function -- WHAT TO DO about intervening sections?
 * - compute per-section offsets and have the section metadata point at the bitmaps
 * - write the section metadata query functions
 
 * - now that allocsmt is gone, we need packed arrays for allocsites and frametypes
 * - ... check the allocsites code that already exists!
 */


/* Three other cases: 
   (1) not-in-dynsym symbols that are in an available .symtab ("statsyms")
   (2) not-in-dynsym symbols that are only as static alloc recs ("extrasyms")
   (3) rodata covers address ranges but is not marked by any symbol.
   For (1), we map .symtab if we can and use that.
   For (2), make static alloc recs look like symtabs, with types on the side
   For (3), we fall back to the section allocator.
        Rodata is probably best modelled as uninterpreted bytes, for now.
        -- Doing better: look for references to it from code, and correlate with code's DWARF.
     HMM. If we really model all sections, then each section that contains
     symbols will have to become a bigalloc. Too many?
         NO, in a finally linked binary there are not that many sections.
         And this structure is useful for tools, e.g. trap-syscalls. Do it!

   So we have a vector of symbol entries in address order.
   And we have a scaled index of the bitmap, one entry per
         smallish interval, holding the index# at that interval start.
         Aligned 64-byte intervals seem good. One two-byte index entry per such interval.
         Maximum 64K symbols per segment -- is that okay? Could make it a 4-byte entry even.
   So we can count set bits in the word, back to the interval start, and add to the index#.

   To add type information to syms, we need a uniqtype pointer.
   We could use a parallel vector. Or save space by combining vectors somehow perhaps.
      Probably we should borrow the low-order zero bits of the uniqtype pointer,
      giving us three extra bits, i.e. 44 bits for the uniqtype, 20 for the rest.
   The static alloc table then becomes this vector + the bitmap.
   No more need for prev/next.
   (Also get rid of heap allocsite table's prev/next? MEASURE performance change.)
   
   To make the bitmap-based lookup fast, we keep a vector of the initial
   span index value for the Nth [B-byte-sized] chunk of the bitmap.
   Then we only have to scan back to a B-byte boundary, count the # of set bits,
   and add that to the vector's value.
   So if the bitmap is 1MB say (covering an 8MB segment),
   and our span index a 16-bit number
   and we have a max scan of 8 bitmap words (512 bits)
   then we need 2 bytes of index vector per 512 bytes of segment.
   Even a single-word scan would give us 2 per 64, which is fine.

	 * What was I doing previously with the allocsmt? That was a
	 * memtable where the bucket contained all statics starting
	 * within a 512-byte region. That relied on the metadata
	 * storing explicitly its own start address. We could do
	 * that too, at least in the symtab/dynsym/extrasym cases; rela
	 * requires more gymnastics, but could still be OK... we
	 * should still write the code.
	 *
	 * So the bitmap uses 12.5% (1/8) overhead, but has shorter metadata
	 * records. The memtable use 8bytes per 512bytes overhead (1/64)
	 * but has larger per-metadata-record cost (must embed address
	 * *and* linked list pointers for the memtable bucket structure,
	 * so an extra 3 words per static entity). The breakeven point comes
	 * where 3 words times N (the number of symbols) equals 7/64 of the
	 * segment size M.
	 *
	 *   24N == 7M / 64   =>  219N = M
	 *
	 * i.e. if symbols occur every 219 bytes or fewer, we have a
	 * good trade.
	 * In my system's glibc, 
	 */
	 //   while read line; do total=$(( $total + $line )); done <<<"$( readelf -WS /lib/x86_64-linux-gnu/libc.so.6 | sed 's/^[[:blank:]]*//' | sed -r 's/^(\[)[[:blank:]]+/\1/' | column -t | egrep '\[.*[[:blank:]]+[WATXI]*A[WATXI]*[[:blank:]]' | tr -s '[:blank:]' '\t' | cut -f6 | sed 's/.*/0x&/' )"; echo "$total"
	/*
	 * suggests that allocated sections make up 1807987 bytes,
	 * while there are only about 2334 dynsyms
	 * but a bunch of others owing to DWARF/relocs/... how many?
	 * Running extrasyms suggests there are another 2326 syms,
	 * and that does not include relocs.
	 * Still, that gets us an average inter-sym distance of 387
	 * bytes, so technically the bitmap wastes space.
	 * SHOULD I be using MTBDDs here too?
	 * We simply map addresses to a <static alloc record, base addr> pair.
	 * This feels less good... symbols don't recur across address intervals.
	 *
	 * Another potential benefit of the bitmap is uniformity, if
	 * lots of allocators are using bitmaps. 
	 * 
	 * Also, is this reasonable time-wise? If we initially have a
	 * pointer to the base of the allocation, the bitmap hits
	 * straight away. But we still have to popcount some fixed
	 * number of words, to reach the type info.
	 *
	 * For size info, we could scan forwards in the bitmap...
	 * not clear if it's better to do that or just get the
	 * meta record and use the size info from that. Actually
	 * scanning forwards doesn't give us a precise size (we'd
	 * need an "ends" bitmap) so we have to do the former.
	 *
	 * A quick fix might be to (1) put the address in the metadata,
	 * either in-line or in a parallel vector of 32-bit vaddrs;
	 * (2) reinstate the memtable and measure the difference in perf
	 * versus bitmap-based backward search?
	 *
   Some kind of hybrid solution like "2 bits for every 4 bytes" might
   be a better space trade -- 00 for nothing, 01 for single object
   starting at the 4-byte boundary, 10 for something else
   ... then need a way to describe the "something else" in a side
   table. Can we abuse the same mechanisms? Not easily, because
   we were using popcount to identify the index into the metavector.
   That fails if the count of allocations becomes ambiguous.
   
   HMM. Still this seems worth doing. In my glibc binary, there are *no*
   symbols that are not at least 4-byte-aligned.
   
   One trick that might work is if we pad the metavector. So in our 2-bits
   bitmap, if we see 
                     00 it means 0 objects start here,
                     01    means 1 object starts here,
                     10    means 2 objects start here
                     11    means 4 objects start here
   and we handle the 3 case by inserting a dummy entry in the metavector
   ("not really an object; move along"). This would happen rarely.
   Does this all still check out? How do we get the actual offset of the
   object start?
   Presum that needs to be another common case, so
                     00    means 0 objects start here,
                     01    means 1 object starts here *and is 4-byte-aligned*,
                     11    means "all other cases; assume 4 slots and use metavector for starts"?
   All this will *only* work if metavector items also contain their addresses.
   For symtab/dynsym/extrasym this is available one level of indirection away.
   For relocs, how does it work? Need to (1) use precomputed spine to get the reloc section+idx,
        (2) decode the r_info to get the target section/symbol + addend,
        (3) get the symbol/section's address and do the add.
   One solution would be to generate extrasyms for all of these, so that we
   don't have to worry about the precomputed spine. Do syms make sense? 24 bytes each.
   By definition we are talking about nameless/typeless quantities; size could be guessed.
   Is it useful to have the relocs around in reloc form?
   (An Elf64_Rela is also 24 bytes, fwiw.)

   We could just forget the bitmap and do a binary search of the
   metavector, since we can compute the address of each entry. Let's
   do that for now.
   
   ALSO note that instead of the reloc section spine and so on, we can
   exploit the fact that since relocs never have type info, we have
   ~62 bits spare in the metavector entry. Just encode the position (32 bits)
   and size directly? Keeping reloc sections around seems like a waste
   of space. (Perhaps we also want it for pointer maps etc.? Though no,
   I think we will just postprocess that away too.)

   So I'm thinking
   - try without bitmaps for now
   - bitmaps   can have common_align and min_align; if not equal,
   there is a secondary bitmap where there is a 1 iff that slot is
   not a straightforward case         (takes the space overhead down to 6.25%)
   - for relocs, ditch the spine and just encode the address+size directly
   (size can be in units of common alignment, I think)

 */


// nasty hack
_Bool __lookup_static_allocation_by_name(struct link_map *l, const char *name,
	void **out_addr, size_t *out_len)
{
	for (struct link_map *inner_l = _r_debug.r_map; inner_l; inner_l = inner_l->l_next)
	{
		if (is_meta_object_for_lib(inner_l, l)) /* HACK: we shouldn't need this... or should we? */
		{
			ElfW(Sym) *statics_sym = symbol_lookup_in_object(inner_l, "statics");
			if (!statics_sym) abort();
#if 0
			struct static_allocsite_entry *statics = sym_to_addr(statics_sym);
			for (struct static_allocsite_entry *cur_ent = statics;
					!STATIC_ALLOCSITE_IS_NULL(cur_ent);
					cur_ent++)
			{
				if (cur_ent->name && 0 == strcmp(cur_ent->name, name))
				{
					// found it! it'd better not be the last in the table...
					if (!(cur_ent + 1)->entry.allocsite) abort();
					void *this_static = cur_ent->entry.allocsite;
					void *next_static = (char*) (cur_ent + 1)->entry.allocsite;
					*out_addr = this_static;
					*out_len = (char*) next_static - (char*) this_static;
					return 1;
				}
			}
			// didn't find the symbol we were looking for -- oh well
#endif
			return 0;
		}
	}	
	return 0;
}

// FIXME: we're getting rid of the memtable, in favour of
// -- per-segment symbol/reloc sorted vectors
// -- the allocation sites table we've already implemented (another sorted array)
// -- something for stack frames
/*          WHAT?  we could do an abstract type for each stack frame
               and a make-precise function that compiles the interval switch/test
            That's a bit elaborate. What else?
            Also how would it be keyed onto the function address?
 */
#if 0

#define NOOP1(x) (void*)0
DEFINE_META_VEC_FUNCS(sym, SYM, sym_or_reloc_rec, /* raw record -- ignored */ sym_or_reloc_rec,
	/*log2_align*/ 0, /*log2_max*/ 32, /*log2_shortcut_scale*/ 8,
	/* addr_from_rawptr */ addr_from_rec, /* addr_from_rawptr_arg */ NULL /* ? */,
	/* metaval_from_raw -- ignored */ NOOP1,
	/* addr_from_metaptr */ addr_from_rec, /* addr_from_metaptr_arg */ NULL)
#endif
static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_static_case;
	/* Search backwards in the bitmap for the first bit set
	 * -- bounded by the biggest static object (can we do better?).
	 * Then count backwards for bits set, down to a shortcut vector
	 * boundary.
	 * The index in the metavector is the shortcut vector element
	 * plus the number of bits set. ROUGHLY! Care about boundary
	 * conditions. The meaning of the shortcut vector element
	 * is critical. In metavec.h I wrote "it gives us the idx of
	 * the first entry whose address is >= the base address of its range."
	 *
	 * My metavec.h sketch used 2*8 as the shortcut scale, i.e.
	 * one shortcut vector element for every 256 alignment units (bytes).
	 * That means we would popcount at most 4 words to get the
	 * metavector index.
	 */
	
	/* If we have a bigalloc, it's either a sym (promoted to bigalloc)
	 * or a thing that allocates syms (section or segment). Whatever
	 * it is, it should define the bitmap we want, and also a shortcut
	 * vector. */
	// FIXME: not supposed to use pageindex directly
	// FIXME: in the section case, shortcut vector needs an offset
	maybe_bigalloc = maybe_bigalloc ? maybe_bigalloc : &big_allocations[PAGENUM(obj)];
	struct big_allocation *b =
		(maybe_bigalloc->allocated_by == &__static_symbol_allocator) ?
		maybe_bigalloc : maybe_bigalloc->parent;
	assert(b->allocated_by == &__static_section_allocator
			|| b->allocated_by == &__static_segment_allocator);
	struct big_allocation *segment_bigalloc
	 = (b->allocated_by == &__static_section_allocator) ? b->parent
			: b;
	struct segment_metadata *segment = segment_bigalloc->meta.un.opaque_data.data_ptr;

	uintptr_t obj_addr = (uintptr_t) obj;
	struct allocs_file_metadata *file = segment_bigalloc->parent->meta.un.opaque_data.data_ptr;
	uintptr_t file_load_addr = file->m.l->l_addr;
	/* Do a binary search in the metavector,
	 * for the highest-placed symbol starting <=
	 * our target vaddr. */
	uintptr_t target_vaddr = obj_addr - file_load_addr;
	unsigned metavector_nrecs = segment->metavector_size / sizeof (union sym_or_reloc_rec);
#define proj(p) vaddr_from_rec(p, file)
	union sym_or_reloc_rec *found = bsearch_leq_generic(
		union sym_or_reloc_rec, target_vaddr,
		/*  T*  */ segment->metavector, /* unsigned */ metavector_nrecs,
		proj);
#undef proj
	if (found && found != segment->metavector + metavector_nrecs)
	{
		uintptr_t found_base_vaddr = vaddr_from_rec(found, file);
		uintptr_t found_limit_vaddr;
		struct uniqtype *found_type = NULL;
		ElfW(Sym) *symtab;
		if (found->is_reloc)
		{
			found_limit_vaddr = found_base_vaddr + found->reloc.size;
			found_type = pointer_to___uniqtype____uninterpreted_byte;
		}
		else switch (found->sym.kind)
		{
			case REC_DYNSYM:   symtab = file->m.dynsym; goto sym;
			case REC_SYMTAB:   symtab = file->m.symtab; goto sym;
			case REC_EXTRASYM: symtab = file->extrasym; goto sym;
			sym:
				found_limit_vaddr = found_base_vaddr + symtab[found->sym.idx].st_size;
				// FIXME: there should be a macro in allocmeta-defs.h for this
				found_type = (struct uniqtype *)(((uintptr_t) found->sym.uniqtype_ptr_bits_no_lowbits) << 3);
				break;
			default: // the default case's `found+1' trick is cute, but not necessary
#if 0
				/* the limit is either the next start address, or the
				 * end of the segment */
				if (unlikely(found == segment->metavector + metavector_nrecs - 1))
				{
					found_limit_vaddr = (uintptr_t) segment_bigalloc->end
						- file_load_addr;
				} else found_limit_vaddr = vaddr_from_rec(found+1, file);
#else
				abort();
#endif
		}
		if (target_vaddr > found_limit_vaddr) goto fail;
		// else we can go ahead
		if (out_base) *out_base = (void*)(file_load_addr + found_base_vaddr);
		if (out_site) *out_site = file->m.load_site;
		if (out_size) *out_size = found_limit_vaddr - found_base_vaddr;
		if (out_type) *out_type = found_type;
		return NULL;
	}
fail:
	++__liballocs_aborted_static;
	return &__liballocs_err_unrecognised_static_object;
}

liballocs_err_t __static_symbol_allocator_get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	return get_info(obj, maybe_bigalloc, out_type, out_base, out_size, out_site);
}

DEFAULT_GET_TYPE

struct allocator __static_symbol_allocator = {
	.name = "static-symbol",
	.is_cacheable = 1,
	.get_info = __static_symbol_allocator_get_info,
	.get_type = get_type
};
