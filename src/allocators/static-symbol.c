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
#include "raw-syscalls.h"

static _Bool trying_to_initialize;
static _Bool initialized;
void __static_symbol_allocator_init(void) __attribute__((constructor(102)));
void __static_symbol_allocator_init(void)
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

/* FIXME: invalidate cache entries on dlclose(). */
#ifndef DLADDR_CACHE_SIZE
#define DLADDR_CACHE_SIZE 16
#endif
struct dladdr_cache_rec { const void *addr; Dl_info info; };
static struct dladdr_cache_rec dladdr_cache[DLADDR_CACHE_SIZE];
static unsigned dladdr_cache_next_free;

Dl_info dladdr_with_cache(const void *addr); // __attribute__((visibility("protected")));
Dl_info dladdr_with_cache(const void *addr)
{
	for (unsigned i = 0; i < DLADDR_CACHE_SIZE; ++i)
	{
		if (dladdr_cache[i].addr)
		{
			if (dladdr_cache[i].addr == addr)
			{
				/* This entry is useful, so maximise #misses before we recycle it. */
				dladdr_cache_next_free = (i + 1) % DLADDR_CACHE_SIZE;
				return dladdr_cache[i].info;
			}
		}
	}
	Dl_info info;
	int ret = dladdr(addr, &info);
	assert(ret != 0);

	/* always cache the dladdr result */
	dladdr_cache[dladdr_cache_next_free++] = (struct dladdr_cache_rec) { addr, info };
	if (dladdr_cache_next_free == DLADDR_CACHE_SIZE)
	{
		debug_printf(5, "dladdr cache wrapped around\n");
		dladdr_cache_next_free = 0;
	}
	return info;
}

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
//           *** OR were they per-file? CHECK. per-segment seems to make more sense
// -- the allocation sites table we've already implemented (another sorted array)
// -- something for stack frames
/*          WHAT?  we could do an abstract type for each stack frame
               and a make-precise function that compiles the interval switch/test
            That's a bit elaborate. What else?
            Also how would it be keyed onto the function address?
 */
#define maximum_static_obj_size (256*1024) // HACK
struct uniqtype *
static_addr_to_uniqtype(const void *static_addr, void **out_object_start)
{
#if 0
	assert(__liballocs_allocsmt != NULL);
	if (!static_addr) return NULL;
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)static_addr | (0x800000000000ul<<1)));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= static_addr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > static_addr)) 
			{
				/* This is the next-lower record, but does it span the address?
				 * Note that subprograms have length 0, i.e. known length. */
				if (p->uniqtype && UNIQTYPE_HAS_KNOWN_LENGTH(p->uniqtype) &&
						p->uniqtype->pos_maxoff >= ((char*) static_addr - (char*) p->allocsite))
				{
					if (out_object_start) *out_object_start = p->allocsite;
					return p->uniqtype;
				} else return NULL;
			}
			might_start_in_lower_bucket &= (p->allocsite > static_addr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_static_obj_size);
#endif
	return NULL;
}
#undef maximum_vaddr_range_size

static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	++__liballocs_hit_static_case;
	void *object_start;
	struct uniqtype *alloc_uniqtype = static_addr_to_uniqtype(obj, &object_start);
	if (out_type) *out_type = alloc_uniqtype;
	if (!alloc_uniqtype)
	{
		++__liballocs_aborted_static;
		return &__liballocs_err_unrecognised_static_object;
	}

	// else we can go ahead
	if (out_base) *out_base = object_start;
	if (out_site) *out_site = object_start;
	if (out_size) *out_size = alloc_uniqtype->pos_maxoff;
	return NULL;
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
