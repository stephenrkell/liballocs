#ifndef LIBALLOCS_ALLOCSITES_H_
#define LIBALLOCS_ALLOCSITES_H_

#include "allocmeta.h"

/* Each allocation site has a metadata record generated for it
 * by our toolchain extensions.
 * These come out in one big array, so naturally a given record
 * has some index within that array.
 * To create a global identifier, we just remember a "start" value
 * for each loaded object. The global index of an allocation site
 * is its per-object index plus that object's "start" value.
 *
 * If we want to look up an alloc site's address by its index,
 * we get the base index for its object
 * and then add its offset.
 *
 * We can also look up an alloc site by its address.
 * Since each object's allocation site metadata records are also
 * sorted by the site address within that object, we simply
 * have to identify the object and then binary-search within
 * that object's sorted vector of allocation site records.
 *
 * FIXME: this is a bit too separate from the bigalloc stuff for my liking.
 * Is "allocation site" a central concept? Arguably so.
 *
 * FIXME: what if we want to redefine a given function / move its allocsites / insert a new one?
 * If we split the id into segment#, per-segment-id#, is that workable?
 * Suppose we use 10 bits for segment. Then we have 6 bits. So no. Even 8-8 is no-go.
 * (Arguably 16 bits for the id is not enough. But it's only for callers
 * of malloc/similar, remember.)
 * Maybe on updating some code, a global rewrite of allocsite ids could
 * be done. This is all academic for now. Much of the other static metadata stuff,
 * i.e. the sorted meta-vector, is also per-file or per-segment.
 *
 * FIXME: this should probably be part of the extrasyms or at least the
 * sorted meta-vector. Remember we have
 *
 * alloc sites (heap)   <-- we're thinking about these
 * static alloc sites (being replaced by sorted meta vec)
 * frame alloc sites  (like heap alloc sites but one extra field)
 *
 * and for the static alloc sites, we add type info *and* link back to
 * a symbol (or a spent reloc record? No; the meta-info is about the *target*
 * of the reloc, which may be the target of *many* reloc records; unclear
 * what it would mean to pick one... I think that field should just be 0).
 
	struct sym_or_reloc_rec
	{
		unsigned kind:2; // an instance of sym_or_reloc_kind
		unsigned idx:18; // i.e. at most 256K symbols of each kind, per file
		unsigned long uniqtype_ptr_bits:44; // i.e. the low-order 3 bits are 0
	} *sorted_meta_vec; // addr-sorted list of relevant dynsym/symtab/extrasym/reloc entries

 * Note that the sorted meta vec entry doesn't store the address of the
 * object it describes -- for that we have to indirect into the symtab
 * or to use the 'starts' bitmap.
 *
 * These patterns -- spines, sorted arrays, bitmaps and "next index" shortcut
 * arrays -- seem to be popping up in a few places. It would be good to have
 * one implementation of them.
 * Our plan for the starts bitmap was 
 * for that.
 * So in the case of relocs, we have to encode the section/symbol *and*
 * (perhaps) addend that gives us the target address.
 *
 *
 * We could make this *sorted_meta_vec[N_META_KINDS]
 * and allow additional per-file metadata kinds, of which heap allocsites
 * would naturally be one, and frame allocsites would naturally be another.

 * 
 */


/* This is effectively a "spine" linking all the per-file
 * allocsite metadata vectors. */
struct allocsites_vectors_by_base_id_entry
{
	allocsite_id_t start_id;
	allocsite_id_t count;
	uintptr_t file_base_addr;
	struct allocsite_entry *ptr;
};
#define ALLOCSITES_INDEX_SIZE 256 /* i.e. up to 256 objects with allocsite metadata */
extern struct allocsites_vectors_by_base_id_entry
allocsites_vectors_by_base_id[ALLOCSITES_INDEX_SIZE] __attribute__((visibility("hidden")));
extern unsigned short
allocsites_id_entry_slot_next_free __attribute__((visibility("hidden")));

void
init_allocsites_info(struct file_metadata *file) __attribute__((visibility("hidden")));

#endif
