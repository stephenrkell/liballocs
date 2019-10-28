#ifndef LIBALLOCS_METAVEC_H_
#define LIBALLOCS_METAVEC_H_

#include <string.h>
#include <stdlib.h>
#include "bitmap.h"

/* Certain patterns -- spines, sorted arrays, bitmaps and "next index" shortcut
 * arrays -- seem to be popping up in a few places. It would be good to have
 * one implementation of them.
 *
 * They're a bit of a complement to bucketed
 * memtables. Memtables are a way of doing the sparse-to-dense part of the
 * lookup really fast, in hardware. We instead rely on binary search in
 * software. But we tend only to use them when we've already narrowed to a
 * dense area... i.e. one metavec is one big bucket.
 *
 * Memtables are also good for handling population that change at run time,
 * at least when using a suitably dynamic bucket structure (e.g. a linked list
 * or a binary tree)... whereas these are for pretty static things, so our
 * buckets are arrays. Since we can use binary search, we can scale to fairly
 * large buckets.
 *
 * Our pageindex + meta-vector structure can be thought of as a memtable, with
 * the pageindex doing the sparse part and each per-file metadata array being
 * a bucket.
 *
 * Let's consider a segment.
 * For a given segment, we might have
 *
 * - the raw symbol/reloc metadata, not in any order we care about
 * - an address-sorted metadata vector    (sorted by address, but doesn't store the addr)
 *       -- whose job is to logically address-sort the raw metadata
 *       -- if the raw metadata is already address-sorted, we might not have a "raw" vector
 *       -- if we do have a raw vector, we must be able to find the element in it which
 *             corresponds to the meta element.
 * - a starts bitmap for it
 *       -- one set bit is one object
 * - optionally an "ends" bitmap?
 * - a scaled "shortcut vector" for it
 *       -- this is an array where each element corresponds to a range of addresses, but
 *             much coarser-grained than the bitmap. It records the index, in the meta-vector,
 *             of the first entry therein which falls within the given address range.
 */

// parameters of an instance of these:
// address of offset 0        (used as a fixed displacement, e.g. segment start 0xc000 => address 0xc001 == offset 0x1)
// alignment of object starts (used as a scale factor in the bitmap)
// maximum # of entries       (used to size the shortcut vector element type; specify as log2 i.e. 8 => 25, 16 => 65536, etc)
// shortcut vector scale factor (speed/memory trade-off; one shortcut entry element per 2^n bytes of memory)
// typename of the raw data

// operations we require:
// map the raw data to an address

static inline void *round_addr_down_to(unsigned m, void *addr)
{
	/* The actual zero address of the first bit in the bitmap is */
	/* rounded down from addr_at_0. It needs to be a multiple of */
	/* whatever size of address range is covered by a word-of-bits.*/
	/* This is           (8*sizeof(unsigned)) << log2_align      */
	/* and to round down n to a multiple of m, we do             */
	/* m*(n/m) */
	uintptr_t lower_addr = m * ((uintptr_t) addr / m);
	return (void*) lower_addr;
}
static inline void *round_addr_up_to(unsigned m, void *addr)
{
	/* To round up n to a multiple of m, we do             */
	/* m*((n+(m-1))/m) */
	uintptr_t higher_addr = m * (((uintptr_t) addr + m - 1) / m);
	return (void*) higher_addr;
}

// operations:
// generate the sorted meta vector from the raw data  (optional; we might already have this)

#define DEFINE_META_VEC_FUNCS(tag, TAG, meta, raw, log2_align, log2_max, \
    log2_shortcut_scale, addr_from_rawptr, addr_from_rawptr_arg, meta_from_rawptr, \
    addr_from_metaptr, addr_from_metaptr_arg) \
static int tag ## _compare(const void *arg1, const void *arg2) \
{ \
	return addr_from_rawptr( (raw *) arg1 )  - addr_from_rawptr( (raw *) arg2 );\
} \
static int tag ## _ptrcompare(const void *arg1, const void *arg2) \
{ \
	return addr_from_rawptr( *(raw **) arg1 )  - addr_from_rawptr( *(raw **) arg2 );\
} \
/* How many bytes are covered by one word of bitmap? */ \
static const unsigned TAG ## _BITMAP_UNIT = (8*sizeof(bitmap_word_t)) << (log2_align); \
/* How many bytes are covered by one entry in the shortcut array? */ \
static const unsigned TAG ## _SHORTCUT_UNIT = (8*sizeof(bitmap_word_t)) << (log2_align); \
size_t tag ## _shortcut_vec_size_bytes(void *addr_at_0, size_t addr_range_sz) \
{ \
	unsigned long nents = \
		(  round_addr_up_to(TAG ## _SHORTCUT_UNIT, (char*) addr_at_0 + addr_range_sz) \
		 - round_addr_down_to(TAG ## _SHORTCUT_UNIT, addr_at_0)) \
	>> log2_shortcut_scale; \
	return sizeof (uint ## log2_max ## _t) * nents; \
} \
size_t tag ## _bitmap_size_bytes(void *addr_at_0, size_t addr_range_sz) \
{ \
	unsigned long nbits = \
		(  round_addr_up_to(TAG ## _BITMAP_UNIT, (char*) addr_at_0 + addr_range_sz) \
		 - round_addr_down_to(TAG ## _BITMAP_UNIT, addr_at_0)) \
	>> log2_align; \
	return (nbits + 7) / 8; \
} \
static inline void \
tag ## _set_bit_for_addr(void *addr_at_0, size_t addr_range_sz, \
    bitmap_word_t *outbuf_bitmap, void *addr) \
{ \
	/* The actual zero address of the first bit in the bitmap is */ \
	/* rounded down from addr_at_0. It needs to be a multiple of */ \
	/* whatever size of address range is covered by a word-of-bits.*/ \
	/* This is           (8*sizeof(unsigned)) << log2_align      */ \
	/* and to round down n to a multiple of m, we do             */ \
	/* m*(n/m) */\
	uintptr_t zero_addr = ((8*sizeof(unsigned)) << (log2_align)) * \
	   ((uintptr_t) addr_at_0 / ((8*sizeof(unsigned)) << (log2_align))); \
	unsigned bit_n = (((uintptr_t) addr) - ((uintptr_t) zero_addr)) >> (log2_align); \
	/* REMEMBER that our bitmap.h is suboptimal for the "reverse find first set" case */ \
	/* because it chooses an ordering convention (MSB == highest-addressed bit) */ \
	/* that is not quite so good for processing the first word quickly */ \
	/* (the opposite convention allows a single "<" test to rule it out). */ \
	/* In our case, we're searching/counting forwards, so a "<" test can tell us */ \
	/* whether any bits higher (more significant; higher-address) are set. That's */ \
	/* what we want, so the convention is good for us. */ \
	bitmap_set_l(outbuf_bitmap, bit_n); \
} \
static inline meta * \
tag ## _generate_meta(void *addr_at_0, size_t addr_range_sz, \
    meta *outbuf, unsigned outbuf_n, \
    bitmap_word_t *out_bitmap, uint ## log2_max ## _t *outshortcut, \
    raw *inbuf, raw *inbuf_end) \
{ \
	/* Copy the raw input. Sort it. Walk it, outputting the meta. */ \
	/* We output all three kinds of metadata in the same call:    */ \
	/* the transformed metadata records, the bitmap data          */ \
	/* and the shortcut values. */ \
	unsigned inbuf_n = inbuf_end - inbuf; \
	raw *tmpbuf[inbuf_n]; \
	raw **tmpbuf_end = &tmpbuf[inbuf_n]; \
	for (unsigned i = 0; i < inbuf_n; ++i) { tmpbuf[i] = &inbuf[i]; } \
	qsort(tmpbuf, ((inbuf_end) - (inbuf)), sizeof (raw *), tag ## _ptrcompare); \
	unsigned outidx = 0; \
	unsigned last_used_tmpbuf_idx = (unsigned) -1; \
	unsigned last_written_shortcut_idx = (unsigned) -1; \
	unsigned i = 0; \
	for (; i < inbuf_n && outidx < outbuf_n; ++i) \
	{ \
		if (!(addr_from_rawptr(tmpbuf[i]))) continue; /* skip null-addr entries */ \
		outbuf[outidx++] = meta_from_rawptr(tmpbuf[i]); \
		tag ## _set_bit_for_addr(addr_at_0, addr_range_sz, out_bitmap, addr_from_rawptr(tmpbuf[i])); \
		/* if that record marks the first in a new shortcut-granularity-sized address range... */ \
		if (outidx == 1 || \
		      (((uintptr_t) (addr_from_rawptr(tmpbuf[last_used_tmpbuf_idx])) >> log2_shortcut_scale) \
		   !=  (((uintptr_t) (addr_from_rawptr(tmpbuf[i])) >> log2_shortcut_scale)))) \
		{   /* write the shortcut idx */ \
			unsigned first_unwritten_sidx = (outidx == 1) ? 0 : \
			                       (1 + (((uintptr_t) (addr_from_rawptr(tmpbuf[last_used_tmpbuf_idx]))) >> log2_shortcut_scale) \
			                        - (((uintptr_t)  addr_at_0) >> log2_shortcut_scale)); \
			unsigned last_unwritten_sidx =  (((uintptr_t) (addr_from_rawptr(tmpbuf[i]))) >> log2_shortcut_scale) \
			                        - (((uintptr_t)  addr_at_0) >> log2_shortcut_scale); \
			assert(last_unwritten_sidx >= first_unwritten_sidx); \
			for (unsigned sidx  = first_unwritten_sidx; \
			              sidx <= last_unwritten_sidx; \
			              ++sidx) \
			{ \
				outshortcut[ sidx ] = outidx - 1; \
			} \
			last_written_shortcut_idx = last_unwritten_sidx; \
		} \
		last_used_tmpbuf_idx = i; \
	} \
	/* fill in any remaining shortcut vector entries with a maximum/sentinel value. */ \
	for (unsigned sidx = (last_written_shortcut_idx == (unsigned) -1) ? 0 : last_written_shortcut_idx + 1; \
			sidx < (((uintptr_t) addr_range_sz) >> log2_shortcut_scale); \
			++sidx) \
	{ \
		outshortcut[sidx] = (uint ## log2_max ## _t) -1; \
	} \
	return outbuf + outidx; \
} \
static inline unsigned tag ## _meta_idx_le_addr(void *addr, void *addr_at_0, size_t addr_range_sz, \
	meta *metavec, bitmap_word_t *bitmap, uint ## log2_max ## _t *shortcut) \
{ \
	/* We want the highest-addressed meta entry whose start address <= addr. */ \
	/* First use the shortcut vector to get us an underapproximating idx_u. */ \
	/* More precisely, it gives us the idx of the first entry whose address is */ \
	/* >= the base address of its range. So if it's not underapproximating, */ \
	/* we can return immediately (with idx-1 or with failure if idx==0). */ \
	/* Then count the bits set between bit (addr(idx)+1) and bit target_addr inclusive. */ \
	/* That's the number of with-meta objects starting after the shortcut entry... */\
	/* ... and at or before the target address. */\
	unsigned sidx = (((uintptr_t) addr >> log2_shortcut_scale)) - \
			             (((uintptr_t) addr_at_0) >> log2_shortcut_scale); \
	if (sidx == (uint ## log2_max ## _t) -1) return (unsigned) -1;  \
	unsigned startidx = shortcut[ sidx ]; \
	void *shortcut_entry_addr = addr_from_metaptr(&metavec[startidx], addr_from_metaptr_arg); \
	if ((char*) shortcut_entry_addr >= (char*) addr && startidx == 0) return (unsigned) -1; /* give up now */ \
	else if ((char*) shortcut_entry_addr > (char*) addr) return startidx - 1; \
	else if ((char*) shortcut_entry_addr == (char*) addr) return startidx; \
	void *bitmap_base_addr = round_addr_down_to(TAG ## _BITMAP_UNIT, addr_at_0); \
	unsigned count = bitmap_count_set_l(bitmap, (bitmap_word_t *) ((char*) bitmap + tag ## _bitmap_size_bytes(addr_at_0, addr_range_size)), \
		(char*) shortcut_entry_addr - (char*) bitmap_base_addr + 1 /* start at +1 i.e. excluding the shortcut entry itself */, \
		(char*) addr - (char*) bitmap_base_addr + 1 /* search up to +1 i.e. up to and including the test addr */); \
	return startidx + count; \
}

// generate the starts bitmap and shortcut vector from sorted meta vector the raw data
// lookup by address
// lookup by idx?

#endif /* LIBALLOCS_METAVEC_H_ */

#ifdef UNIT_TEST
#include <assert.h>
#include <link.h>
#include <dlfcn.h>
#include "relf.h"

/* Example? How about our dynsym as returned by relf.h?
 * We filter to select only non-zero-length non-ifunc symbols that don't overlap
 * a previously seen span. FIXME: how do we filter overlaps? */
struct meta
{
	unsigned symind;
};

/* _metaval_from_raw builds the meta-vector value given a raw pointer.
 * For us, a raw pointer is a pointer to an Elf64_Sym structure */
#define test_metaval_from_raw(p) \
	((struct meta) { p - dynsym })
// how map back from metadata to address
#define test_addr_from_raw(rawp) \
	sym_to_addr_in_obj(rawp, exe_link_map)
#define test_addr_from_metaptr(metap, dynsym) \
	sym_to_addr_in_obj(&dynsym[(metap)->symind], exe_link_map)

const uintptr_t addr_at_0 = 0x400000;
const size_t addr_range_size = 0x300000; // 3MB
struct link_map *exe_link_map;
ElfW(Sym) *dynsym;

DEFINE_META_VEC_FUNCS(test, TEST, struct meta, ElfW(Sym),
	/*log2_align*/ 0, /*log2_max*/ 16, /*log2_shortcut_scale*/ 8,
	/* addr_from_rawptr */ test_addr_from_raw, /* addr_from_rawptr_arg */ dynsym,
	test_metaval_from_raw,
	test_addr_from_metaptr, dynsym)

int main(void)
{
	exe_link_map = get_exe_handle();
	dynsym = get_dynsym(exe_link_map);
	unsigned nsym = dynamic_symbol_count(exe_link_map->l_ld, exe_link_map);
	/* calloc the bitmap, the shortcuts and the meta vector */
	uint16_t *shortcut_vec = calloc(1,
		test_shortcut_vec_size_bytes((void*) addr_at_0, addr_range_size));
	bitmap_word_t *bitmap = calloc(1, test_bitmap_size_bytes((void*) addr_at_0, addr_range_size));
	struct meta *meta_vec = calloc(nsym /* overestimate of # meta records */, sizeof meta_vec);
	struct meta *meta_vec_end = test_generate_meta((void*) addr_at_0, addr_range_size,
		meta_vec, nsym, bitmap, shortcut_vec, dynsym, dynsym + nsym);
	struct meta *new_meta_vec = realloc(meta_vec, sizeof (struct meta) * (meta_vec_end - meta_vec));
	assert(new_meta_vec == meta_vec); /* it was an in-place realloc */

	/* OK, we've filled in the metavec and bitmap and shortcut vec with some stuff.
	 * How do we check whether it's right? Use it to look up some things we
	 * know, like the address of main, and check we get the right value. */
	unsigned found_main_idx = test_meta_idx_le_addr(main, (void*) addr_at_0, addr_range_size,
		meta_vec, bitmap, shortcut_vec);
	assert(found_main_idx != (unsigned) -1);
	assert(test_addr_from_metaptr(&meta_vec[found_main_idx], dynsym) == main);

	free(new_meta_vec);
	free(bitmap);
	free(shortcut_vec);
	return 0;
}

#endif /* UNIT_TEST */
