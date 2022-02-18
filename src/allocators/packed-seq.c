#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <err.h>
#include "vas.h" /* for rounding and dividing macros */
#include "bitmap.h"
#include "liballocs_private.h"
#include "relf.h"

static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_the_allocation,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site);

DEFAULT_GET_TYPE

/* This is starting to look suspiciously like a composite uniqtype,
 * where the metavector simply describes the layout with a uniqtype
 * for each member. However, here the metavector is *per instance*.
 * Each packed sequence is potentially different! That means we risk
 * creating a large volume of metadata per unit data. So let's regroup.
 *
 * There are three levels of abstraction going on here:
 * - the concept of packed sequences in the general sense
 * - a specific family of packed sequences, e.g. "x86 instruction streams" or "string tables"
 * - a specific packed sequence.
 * We roughly want at most a 'one word per entry' metadata overhead,
 * ideally less.
 *
 * We can do this with the starts bitmap plus a *small* metavector
 * record.
 * In general, we need to keep sizes alongside uniqtypes. However,
 * many uniqtypes record a precise size that is the size we want.
 * In general also, there can be padding / dead space before the
 * next item in the sequence. Or can there? Perhaps the whole point
 * of a packed sequence is that there isn't? This is the reason why
 * instruction streams get padded with nops; formally there is no
 * padding, and the stream wouldn't be decodable. On the other hand,
 * sometimes we have an almost-as-'packed' bunch of stuff like a data
 * segment, where there can be dead space and you do need to know the
 * alignment of the *next* thing. These can't be decoded linearly, so
 * are quite different. But I think we need to cover this case anyway.
 * Also, if we have only 'size' we might *also* need the padding!
 *
 * HMM. I think there is a better way to think of this.
 * - If we don't have a size in the type, it means it's an array
 * so has a repeated internal structure.
 * - OR what if it's itself a packed sequence?
 * - our 'string table' example seems relevant
 */
struct packed_sequence_metavector_rec32
{
	unsigned type_idx:10; /* at most 1024 distinct uniqtypes allocated within this family of seqs */
	unsigned size_nalign:18; /* # alignment units to next entry FIXME: just use bitmap? */
	unsigned size_delta_nbytes:4; /* actual size can be up to 15 bytes smaller */
};
struct packed_sequence_metavector_rec16
{
	unsigned type_idx:4; /* at most 16 distinct uniqtypes allocated within this family of seqs */
	unsigned size_nalign:9; /* # alignment units to the next entry FIXME: just use bitmap? */
	unsigned size_delta_nbytes:3; /* actual size can be up to 7 bytes smaller */
};
/* The enumerate function: given a start position,
 * return the size (and type, and gap-to-next).
 * The type's size doesn't suffice because our entry might
 * be, say, an array of char. */
typedef size_t enumerate_fn(void *pos, void *end, struct uniqtype **out_u, unsigned *out_size_delta_nbytes, void *arg);
typedef const char *name_fn(void *pos, struct uniqtype *maybe_u, void *arg);

/* This is the 'uniqtype equivalent'. We could rejig it into a case of
 * uniqtype quite easily, actually.
 * Remember that the key difference between a packed sequence and a structure type
 * is that sequences of the same 'type 'are self-delimiting and don't have to have the
 * same substructure instance-to-instance. So we optionally cache their substructure,
 * which makes no sense for structs. TODO: .. it could for unions, i.e.  maybe this should
 * be stored/managed the same way as the union shadow? We don't currently implement the union
 * shadow so there's an opportunity. */
struct packed_sequence_family
{
	enumerate_fn *enumerate;
	name_fn *name;
	unsigned log2_align:3; // what's the minimum entry alignment, in bytes, for this sequence?
	unsigned one_plus_log2_metavector_entry_size_bytes:4; // 0 means no metavector; maximum entry size 2^14 bytes (!)
	unsigned ntypes:12;

	struct uniqtype *types_table[]; // flexible... "related"
};
static size_t enumerate_string8_nulterm(void *pos, void *end, struct uniqtype **out_u,
		unsigned *out_size_delta_nbytes, void *arg)
{
	/* 'pos' points at a sequence element; we need to get the next one.  */
	unsigned char *cpos = pos;
	if (cpos == end) return (size_t) -1;
	while (cpos != end && *cpos++);
	if (out_size_delta_nbytes) *out_size_delta_nbytes = 0u;
	if (out_u) *out_u = pointer_to___uniqtype____ARR0_signed_char;
	return cpos - (unsigned char *) pos;
}
/* FIXME: this is a sensible choice for things like strtabs
 * where the strings are uniqued/interned, but it will give
 * us non-unique names in other cases. Since allocation names
 * don't have to be unique, this is OK... we need a way for
 * allocators to declare stuff like this, and for clients to
 * say something like "only give me unique names". */
const char *name_for_string8_nulterm(void *s, struct uniqtype *maybe_u, void *arg)
{
	return (const char*) s;
}
struct packed_sequence_family __string8_nulterm_packed_sequence = {
	.enumerate = enumerate_string8_nulterm,
	.name = name_for_string8_nulterm,
	.log2_align = 0,
	.one_plus_log2_metavector_entry_size_bytes = 0, /* we don't need a metavector */
	.ntypes = 1,
	.types_table = { NULL /* init'd below in constructor */ }
};
__attribute__((constructor))
static void init(void)
{
	__string8_nulterm_packed_sequence.types_table[0] = pointer_to___uniqtype____ARR0_signed_char;
	assert(__string8_nulterm_packed_sequence.types_table[0]);
	assert(__string8_nulterm_packed_sequence.types_table[0] != (void*) -1);
	assert(UNIQTYPE_ARRAY_LENGTH(__string8_nulterm_packed_sequence.types_table[0])
		== UNIQTYPE_ARRAY_LENGTH_UNBOUNDED);
}
/* This is the per-sequence metadata. */
struct packed_sequence; // in allocmeta.h

void __packed_seq_free(void *arg)
{
	struct packed_sequence *seq = arg;
	if (seq->starts_bitmap) free(seq->starts_bitmap);
	if (seq->un.metavector_any) free(seq->un.metavector_any);
	free(arg);
}

static const char *get_name(void *obj, char *namebuf, size_t buflen)
{
	/* Do our allocations have names? It depends on the family. */
	void *start = NULL;
	struct big_allocation *b = __lookup_bigalloc_from_root_by_suballocator(obj, &__packed_seq_allocator, &start);
	assert(b);
	struct packed_sequence *seq = b->suballocator_private;
	assert(seq);
	if (seq->fam->name)
	{
		const char *n = seq->fam->name(obj, /* HACK: */ NULL, seq->name_fn_arg);
		// HACK: empty name is no name
		if (n && *n) return n;
	}
	return NULL;
}

#define METAVECTOR_ENTRY_SIZE_BYTES(seq) \
 ((seq)->fam->one_plus_log2_metavector_entry_size_bytes ? \
  (1u << ((seq)->fam->one_plus_log2_metavector_entry_size_bytes - 1)) \
  : 0)
#define INITIAL_METAVECTOR_SIZE 8

/* Can we macroise a polymorphic access to 'ent', in a flexible way?
 * Specifically, can I write a pair of macros that
 * - share a main body (i.e. only one of them does the work)
 * - one accepts a higher-order expandable macro
 * - the other accepts varargs tokens?
 * This is to cater to (complex) cases where we want the type of the
 * record to be expanded within the tokens, and (simpler)
 * cases where we just want a bunch of tokens. In the former case,
 * the client has to define a macro which gets passed higher-orderwise
 * to WITH_ENT_MAC, whereas WITH_ENT just takes some tokens.
 * The following is the solution... use of 'gobble' is the key trick.
 */

#define WITH_ENT_MAC(_ent, seq, toksmac) \
    switch ((seq)->fam->one_plus_log2_metavector_entry_size_bytes) \
	{ \
		case 0: break; \
		case 2: { struct packed_sequence_metavector_rec16 *ent = _ent; toksmac(struct packed_sequence_metavector_rec16 ) ; break; } \
		case 3: { struct packed_sequence_metavector_rec32 *ent = _ent; toksmac(struct packed_sequence_metavector_rec32 ) ; break; } \
		default: assert(0); break; \
	}

/* If we want the above macro but just inserting a bunch of tokens
 * (for 'toksmac') and not caring about the type (its argument), can
 * use a simpler form that just bungs the tokens in the argument list.
 * The 'gobble' at the end is used to erase the type argument supplied
 * to the macro above. */
#define gobble(toks...)
#define WITH_ENT(_ent, seq, toks...) \
    WITH_ENT_MAC(_ent, seq, toks gobble)

static int walk_allocations(struct alloc_tree_pos *scope,
			walk_alloc_cb_t *cb, void *arg, void *maybe_range_begin,
			void *maybe_range_end);

struct allocator __packed_seq_allocator = {
	.name = "packed sequence",
	.is_cacheable = 1,
	.get_info = get_info,
	.get_type = get_type,
	.get_name = get_name,
	.walk_allocations = walk_allocations
};

/* How do we get from a sequence to its state?
 * If the sequence is a bigalloc, it's easy. */

/* Now let's define the operations. */

static unsigned find_idx(struct uniqtype *u, struct packed_sequence_family *fam)
{
	for (unsigned i = 0; i < fam->ntypes; ++i)
	{
		if (fam->types_table[i] == u) return i;
	}
	return (unsigned) -1;
}

#ifndef MIN
#define MIN(a, b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a, b) ((a)>(b)?(a):(b))
#endif

#ifndef unlikely
#define unlikely(cond) __builtin_expect( (cond), 0 )
#endif
static void ensure_cached_up_to(struct big_allocation *b, struct packed_sequence *seq, unsigned offset)
{
	if (seq->offset_cached_up_to < offset)
	{
		uintptr_t bitmap_base_addr = ROUND_DOWN(b->begin, 1u<<(seq->fam->log2_align));
		void *addr_to_cache_up_to = (void*)((uintptr_t) b->begin + offset);
		void *cur = (void*)((uintptr_t) b->begin + seq->offset_cached_up_to);
		/* If we're going to bother, let's make it worth our while.
		 * Plan to cache at least twice as much stuff as we already have,
		 * unless we run out of stuff. HMM: is this wise? */
		unsigned target_offset = MIN((uintptr_t) b->end - (uintptr_t) b->begin,
			MAX(2 * seq->offset_cached_up_to, offset));
		uintptr_t target_addr = (uintptr_t) b->begin + target_offset;
		unsigned long bitmap_naddrs = target_addr + 1 - bitmap_base_addr;
		unsigned long bitmap_nbits = DIVIDE_ROUNDING_UP(bitmap_naddrs, 1u<<seq->fam->log2_align);
		unsigned long bitmap_nwords = DIVIDE_ROUNDING_UP(bitmap_nbits, BITMAP_WORD_NBITS);
		if (unlikely(seq->starts_bitmap_nwords < bitmap_nwords))
		{
			unsigned long old_bitmap_nwords = seq->starts_bitmap_nwords;
			seq->starts_bitmap_nwords = bitmap_nwords;
			seq->starts_bitmap = realloc(
				seq->starts_bitmap,
				seq->starts_bitmap_nwords * sizeof (bitmap_word_t)
			);
			if (!seq->starts_bitmap) err(EXIT_FAILURE, "allocating memory");
			// bzero the new space
			bzero((char*) seq->starts_bitmap + old_bitmap_nwords * sizeof (bitmap_word_t),
				sizeof (bitmap_word_t) * (bitmap_nwords - old_bitmap_nwords));
		}
		size_t cur_sz;
		unsigned size_delta_nbytes = 0u;
		struct uniqtype *u = NULL;
		while ((size_t)-1 != (cur_sz = seq->fam->enumerate(cur, b->end, &u, &size_delta_nbytes, seq->enumerate_fn_arg)))
		{
			/* Invariant: our 'cached_up_to' should always be the start of an
			 * element in the sequence, so we know where to resume iterating from.
			 * It means that *cur* is the object we have *not* yet cached.
			 * So what is the 'type' we have been given? Also the object
			 * at 'cur'. This is correct. */
			uintptr_t cur_end = (uintptr_t) cur + cur_sz;
			uintptr_t cur_next_start = ROUND_UP(cur_end, 1u<<seq->fam->log2_align);
			if (unlikely(seq->fam->one_plus_log2_metavector_entry_size_bytes != 0 &&
					seq->metavector_nused == seq->metavector_size))
			{
				seq->metavector_size = seq->metavector_size ? 2 * seq->metavector_size
						: INITIAL_METAVECTOR_SIZE;
				seq->un.metavector_any = realloc(
					seq->un.metavector_any,
					seq->metavector_size * METAVECTOR_ENTRY_SIZE_BYTES(seq)
				);
				if (!seq->un.metavector_any) err(EXIT_FAILURE, "allocating memory");
			}
			if (likely(seq->fam->one_plus_log2_metavector_entry_size_bytes != 0))
			{
				// calculate the next free metavector entry address, in integer-space
				void *ent_as_void = (void*)(((uintptr_t) seq->un.metavector_any) +
						(seq->metavector_nused++ * METAVECTOR_ENTRY_SIZE_BYTES(seq)));
				// gen the case-splitting code that initializes the entry
				WITH_ENT(ent_as_void, seq, {
					ent->type_idx = find_idx(u, seq->fam);
					ent->size_nalign = ((uintptr_t) cur_next_start - (uintptr_t) cur) >> seq->fam->log2_align;
					ent->size_delta_nbytes = (uintptr_t) cur_next_start - (uintptr_t) cur_end;
				});
			}
			bitmap_set_l(seq->starts_bitmap, ((uintptr_t) cur - bitmap_base_addr) >>
				seq->fam->log2_align);
			seq->offset_cached_up_to = (uintptr_t) cur_next_start - (uintptr_t) b->begin;
			if ((uintptr_t) cur_end == (uintptr_t) b->begin + target_offset) break;
			if ((uintptr_t) cur_end > (uintptr_t) b->begin + target_offset)
			{
				// we've overshot our target offset -- is that a problem?
				break;
			}
			cur = (void*) cur_next_start;
		}
	}
	assert(seq->offset_cached_up_to >= offset);
}

static liballocs_err_t get_info(void *obj,
	struct big_allocation *maybe_the_allocation,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	/* We know that 'obj' is somewhere within a bigalloc that we suballocate.
	 * However, we don't know the bigalloc. HMM. Or do we? What is 'maybe_the_allocation'
	 * really? In __liballocs_leaf_allocator_for,
	 * it's the deepest bigalloc found. So, hmm, er, it probably is what we want.
	 * See the comment in pageindex.h for what's really wrong with that function. */

	assert(maybe_the_allocation->suballocator == &__packed_seq_allocator);
	struct big_allocation *b = maybe_the_allocation; // better name for it
	struct packed_sequence *seq = (struct packed_sequence *) maybe_the_allocation->suballocator_private;
	/* We ensure we're cached up to at least this byte. */
	unsigned target_offset = (uintptr_t) obj - (uintptr_t) b->begin;
	ensure_cached_up_to(b, seq, target_offset + 1);

	/* Now we know we have the thing cached (i.e. in our metavector),
	 * we can bsearch_leq for it.
	 *
	 * AH. Our metavector entries don't include offsets, because we're imagining
	 * also having a bitmap. So we can't do bsearch_leq; we have instead to
	 * scan the bitmap and popcount it backwards, then index the metavector
	 * at the corresponding location. That's fine but potentially slow. We
	 * might want to use either way to index our structures. Can we code this up
	 * generically?
	 *
	 * (This is what shortcut vectors are for. Instead of popcounting all the way
	 * backwards, you popcount a bounded amount, to a shortcut-chunk boundary,
	 * then add that popcount to the shortcut total. We have been skipping shortcut
	 * vectors by just including the offset in each metavector entry.
	 *
	 * We really want to compare these structures against the classics and more:
	 *
	 * splay tree
	 * bitmap + in-band metadata (like for malloc)
	 * threaded memtable + in-band metadata (less space overhead than bitmap?)
	 * bitmap + OOB metavector-with-offsets
	 * bitmap + OOB metavector(no offsets) + shortcut vector
	 * bitmap + OOB metavector(no offsets) full countback (no shortcut vector)
	 * the layered thing I came up with for generic_small
	 *
	 * The basic idea is to avoid pointer-chasing (the splay-tree case),
	 * instead preserving locality of access,
	 * while still allowing range queries (hence why a hash table is no good).
	 */

	//void *found = bsearch_leq_generic(struct , (uintptr_t) obj - (uintptr_t) b->begin,
	//	seq->un.meta_, seq->metavector_size, 
	//#define offset_from_rec(p) (p)->fileoff
	//return bsearch_leq_generic(struct elf_metavector_entry, target_offset,
	//	/* T* */ meta->metavector, meta->metavector_size, offset_from_rec);
	// 1. use the bitmap to find the first
	uintptr_t bitmap_base = ROUND_DOWN(b->begin, 1u<<seq->fam->log2_align);
	// what's the bitmap idx of our offset? remember, bitmap base may differ
	unsigned long query_idx = (((uintptr_t) b->begin + target_offset) - bitmap_base) >> (seq->fam->log2_align);
	unsigned long found_idx = bitmap_rfind_first_set_leq_l(
			seq->starts_bitmap,
			seq->starts_bitmap + seq->starts_bitmap_nwords,
			query_idx, NULL
	);
	if (found_idx != (unsigned long) -1)
	{
		// found something at <= our query address
		// so what's its index in the metavector?
		// FIXME: use a shortcut vector
		unsigned long count_before = bitmap_count_set_l(seq->starts_bitmap, seq->starts_bitmap + seq->starts_bitmap_nwords,
			/* start_idx_ge */ 0,
			found_idx
		);
		// it's at count_before in the metavector, e.g. if there's 0 earlier bits set it's at idx 0
		void *metavector_found = (void*)((uintptr_t)seq->un.metavector_any +
			(count_before)*(1u<<(seq->fam->one_plus_log2_metavector_entry_size_bytes - 1)));
		struct uniqtype *found_t;
		size_t sz;
		void *base;
		WITH_ENT(metavector_found, seq, { \
			found_t = seq->fam->types_table[ent->type_idx];
			sz = (ent->size_nalign << seq->fam->log2_align) - ent->size_delta_nbytes;
			base = (void*)(bitmap_base + (found_idx << seq->fam->log2_align));
		});
		/* HACK: do a make_precise for arrays. This will go away eventually,
		 * i.e. it will be the caller's responsibility to grok the size of
		 * an array. */
#define FIXUP_T(t, sz) \
 ((t) && UNIQTYPE_IS_ARRAY_TYPE(t) && UNIQTYPE_ARRAY_LENGTH(t) == UNIQTYPE_ARRAY_LENGTH_UNBOUNDED) \
 ? __liballocs_get_or_create_array_type(UNIQTYPE_ARRAY_ELEMENT_TYPE(t), \
				(sz) / UNIQTYPE_ARRAY_ELEMENT_TYPE(t)->pos_maxoff) \
 : (t)
		if (out_type) *out_type = FIXUP_T(found_t, sz);
		if (out_size) *out_size = sz;
		if (out_base) *out_base = base;
		if (out_site) *out_site = NULL;
		return NULL; // no error
	}

	return &__liballocs_err_unrecognised_static_object;
}

static int walk_allocations(struct alloc_tree_pos *pos,
			walk_alloc_cb_t *cb, void *arg, void *maybe_range_begin,
			void *maybe_range_end)
{
	assert(BOU_IS_BIGALLOC(pos->bigalloc_or_uniqtype));
	struct big_allocation *b = BOU_BIGALLOC(pos->bigalloc_or_uniqtype);
	struct packed_sequence *seq = b->suballocator_private;
	ensure_cached_up_to(b, seq, (uintptr_t) (maybe_range_end ?: b->end) - (uintptr_t) b->begin);
	/* Use the bitmap, not the metavector (which we may not have). */
	uintptr_t bitmap_base_addr = ROUND_DOWN(b->begin, 1u<<(seq->fam->log2_align));
	unsigned bitmap_start_idx = ((uintptr_t) (maybe_range_begin ?: b->begin)
			- (uintptr_t) bitmap_base_addr) >> seq->fam->log2_align;
	unsigned bitmap_pre_count = bitmap_count_set_l(seq->starts_bitmap,
		seq->starts_bitmap + seq->starts_bitmap_nwords,
		0, bitmap_start_idx);
	unsigned long n = bitmap_pre_count;
	unsigned long cur_bit_idx;
	unsigned long next_bit_idx = bitmap_start_idx;
	/* Iterate over set bits. */
	unsigned long found;
	bitmap_word_t test_bit;
	int ret = 0;
	struct alloc_tree_link link = {
		.container = { pos->base, pos->bigalloc_or_uniqtype },
		.containee_coord = bitmap_pre_count // will pre-increment; CARE! it should be idx+1
	};
	while ((unsigned long)-1 != (cur_bit_idx = next_bit_idx))
	{
		/* Caller gives us a 'pos' ("walk under here"), and
		 * this loop generates a series of 'link's. */
		// tell the cb the idx of the sequence element -- must be 1-based
		++link.containee_coord;
		// have we exhausted our range?
		void *obj = (char*) bitmap_base_addr + (cur_bit_idx << seq->fam->log2_align);
		if (maybe_range_end && (uintptr_t) maybe_range_end <= (uintptr_t) obj) break;
		/* To get the size, use the bitmap. */
		next_bit_idx = bitmap_find_first_set1_geq_l(
			seq->starts_bitmap, seq->starts_bitmap + seq->starts_bitmap_nwords,
			cur_bit_idx + 1, NULL);
		assert(next_bit_idx == (unsigned long) -1 ||
			next_bit_idx > cur_bit_idx);
		size_t padded_sz = (next_bit_idx == (unsigned long) -1) ?
			(uintptr_t) b->end - (uintptr_t) obj :
			((next_bit_idx - cur_bit_idx) << seq->fam->log2_align);
		void *ent = (char*) seq->un.metavector_any + n * METAVECTOR_ENTRY_SIZE_BYTES(seq);
		size_t actual_sz;
		struct uniqtype *t;
		// NOTE that we might not have a metavector, i.e. sz might be 0
		if (METAVECTOR_ENTRY_SIZE_BYTES(seq) > 0)
		{
			WITH_ENT(ent, seq, { \
				t = seq->fam->types_table[ent->type_idx];
				actual_sz = padded_sz - ent->size_delta_nbytes;
			});
		}
		else
		{
			t = seq->fam->types_table[0];
			actual_sz = padded_sz;
		}
		ret = cb(NULL, obj, FIXUP_T(t, actual_sz), /* allocsite */ NULL, &link, arg);
		if (ret) return ret;
	}
	return ret;
}
