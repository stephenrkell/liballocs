/*
This is the license for uniqtype-defs.h, part of a definition of 
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

#ifndef UNIQTYPE_DEFS_H_
#define UNIQTYPE_DEFS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
/* Don't include any inline functions before we've defined *our* inlines,
 * or they'll get instrumented by CIL passes and create lots of implicit-declaration
 * problems. Since our inline function needs some includes, we put them at the bottom. */

struct uniqtype;
const char *(__attribute__((pure,weak)) __liballocs_uniqtype_name)(const struct uniqtype *u);

/* The uniqtype cache word is basically representing the same thing
 * as a memrange cache entry.
	unsigned offset_to_t; // at this offset within any period, we have a t
	struct uniqtype *t:48;
 * ... but where "offset_to_t" is in "bits" and "t" is in "addr" (fields
 * of the alloc_addr_info struct, which we are repurposing here).
 */
#define UNIQTYPE_DECLS \
/* CARE with bit allocation: we want the first bit (is_array) to be set only in */ \
/* the ARRAY value. The placement of bitfields is ABI-determined, but on x86-64 */ \
/* we get a leading 1-bit bitfield coming out as the LSB, and a leading 3-bit   */ \
/* bitfield coming out internally LE, i.e. the leading bit is the low bit. SO...*/ \
/* make ARRAY equal 1, and the others use even numbers.                         */ \
enum uniqtype_kind { VOID, ARRAY = 0x1, BASE = 0x2, ENUMERATION = 0x4, COMPOSITE = 0x6, \
    ADDRESS = 0x8, SUBPROGRAM = 0xa, SUBRANGE = 0xc }; \
struct alloc_addr_info \
{ \
	unsigned long addr:47; \
	unsigned flag:1; \
	unsigned bits:16; \
}; \
/* For a struct, we have at least three fields: name, offset, type. 	 */ \
/* In fact we might want *more* than that: a flag to say whether it's an */ \
/* offset or an absolute address (to encode the mcontext case). HMM.	 */ \
/* To avoid storing loads of pointers to close-by strings, each needing  */ \
/* relocation, we point to a names *vector* from a separate related[] entry. */ \
struct uniqtype_rel_info \
{ \
   union { \
	   struct { \
		   struct uniqtype *ptr; \
	   } t; \
	   struct { \
		   unsigned long val; \
		   /* const char *name; might as well? NO, to save on relocations */ \
	   } enumerator; \
	   /* For struct members, the main complexity is modelling stack frames  */ \
	   /* in the same formalism. Do we want to model locals that are in fact */ \
	   /* not stored in a manifest (type-directed) rep but are recoverable   */ \
	   /* (this is DW_OP_stack_value)? What about not stored at all?         */ \
	   /* We could do "stored (in frame, stable rep) (i.e .the good case)",  */ \
	   /* "stored (in register or static storage, stable rep) (common)",     */ \
	   /* "recoverable" (getter/setter), "absent"?                           */ \
	   struct { \
		   struct uniqtype *ptr; \
		   unsigned long off:56; \
		   unsigned long is_absolute_address:1; \
		   unsigned long may_be_invalid:1; \
	   } memb; \
	   struct { \
		   const char **n; /* names vector */ \
	   } memb_names; \
   } un; \
}; \
struct mcontext; /* for #include contexts that lack it */ \
/* "make_precise" func for encoding dynamic / data-dependent reps (e.g. stack frame, hash table) */ \
typedef struct uniqtype *make_precise_fn_t(struct uniqtype *in, \
   struct uniqtype *out, unsigned long out_len, \
   void *obj, void *alloc_base, unsigned long alloc_sz, void *ip, struct mcontext *ctxt); \
struct uniqtype \
{ \
   struct alloc_addr_info cache_word; \
   unsigned pos_maxoff; /* positive size in bytes, or UINT_MAX for unbounded/unrep'able */ \
   union { \
       struct { \
           unsigned kind:4; \
           unsigned unused_:28; \
       } info; \
       struct { \
           unsigned kind:4; \
       } _void; \
       struct { \
           unsigned kind:4; \
           unsigned enc:6; /* i.e. up to 64 distinct encodings */ \
           unsigned one_plus_log_bit_size_delta:4; /* i.e. up to 15 i.e. delta of up to 2^14 less than implied bit size (8 * byte size) */ \
             signed bit_size_delta_delta:8; /* i.e. vary the delta +/- 127 bits */ \
             signed bit_off:10; /* i.e. bit offsets up to 2^9 *from either end* */ \
       } base; /* related[0] is signedness complement; could also do same-twice-as-big, same-twice-as-small? */ \
       struct { \
           unsigned kind:4; \
           unsigned is_contiguous:1; /* idea */ \
           unsigned is_log_spaced:1; /* idea (inefficiency: implies not is_contiguous) */ \
           unsigned nenum:26; /* HMM */ \
       } enumeration; /* related[0] is base type; use related[1..nenum] for enumerators? Or hmm, just use a separate name/value mapping, like member_names? These are like meta_enum, meta_struct, etc.. */ \
       struct { /* same-offset subobjects should be sorted in increasing size (unions, stackframes) */\
           unsigned kind:4; \
           unsigned nmemb:20; /* 1M members should be enough */ \
           unsigned not_simultaneous:1; /* i.e. whether any member may be invalid */ \
       } composite; /* related[nmemb] is names ptr; could also do "refines" i.e. templatey relations? Or does that seem to be a predicate that belongs outside uniqtypes...? */ \
       struct { \
           unsigned kind:4; \
           unsigned indir_level:5; /* contractually, after how many valid derefs might we get a non-address? valid only if genericity == 0 */ \
           unsigned genericity:1; /* I wrote "we need this when deciding whether or not to overwrite" -- talking about libcrunch's treatment of writes through generic ptrs, I think */ \
           unsigned log_min_align:6; /* useful? just an idea */ \
       } address; /* related[0] is immediate pointee type; related[1] is ultimate non-pointer type, if indir_level > 1 */ \
       struct { \
           unsigned kind:4; \
           unsigned narg:10; /* 1023 arguments is quite a lot */ \
           unsigned nret:10; /* sim. return values */ \
           unsigned is_va:1; /* is variadic */ \
           unsigned cc:7;    /* calling convention */ \
       } subprogram; /* related[0..nret] are return types; contained[nret..nret+narg] are args */ \
       struct { \
           unsigned kind:4; \
           unsigned min:14; \
           unsigned max:14; \
       } subrange; /* related[0] is host type */ \
       struct { \
           unsigned is_array:1; /* because ARRAY is 8, i.e. top bit set */ \
           unsigned nelems:31; /* for consistency with pos_maxoff, use -1 for unbounded/unknown */ \
       } array; /* related[0] is element type */ \
       unsigned as_word; /* for funky optimizations, e.g. "== -1" to test for unbounded array */ \
   } un; \
   make_precise_fn_t *make_precise; /* NULL means identity function AND that we're concrete */ \
   struct uniqtype_rel_info related[]; \
}; \
struct mcontext; \
const char *(__attribute__((pure,weak)) __liballocs_uniqtype_name)(const struct uniqtype *u); \
const char *(__attribute__((pure,weak)) __liballocs_uniqtype_symbol_name)(const struct uniqtype *u); \
struct uniqtype *(__attribute__((weak)) __liballocs_make_array_precise_with_memory_bounds)(struct uniqtype *in, \
   struct uniqtype *out, unsigned long out_len, \
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt); \
struct uniqtype *(__attribute__((weak)) __liballocs_make_precise_identity)(struct uniqtype *in, \
   struct uniqtype *out, unsigned long out_len, \
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt); \
struct uniqtype *(__attribute__((pure,weak)) __liballocs_get_or_create_array_type)(struct uniqtype *element_t, unsigned array_len);

#define UNIQTYPE_POS_MAXOFF_UNBOUNDED ((1ul << (8*sizeof(unsigned int)))-1) /* UINT_MAX */
#define UNIQTYPE_SIZE_UNBOUNDED UNIQTYPE_POS_MAXOFF_UNBOUNDED
#define UNIQTYPE_ARRAY_LENGTH_UNBOUNDED ((1u<<31)-1)

UNIQTYPE_DECLS

/* Idea: to encode parametrically polymorphic contract within a uniqtype, 
 * can use otherwise-invalid "t" pointer values as type variables. So
 * (struct uniqtype *) 0x1 is 'a,
 * (struct uniqtype *) 0x2 is 'b,
 * and so on.
 * 
 * This would allow a swap() function, say, to declare that it can swap
 * any two things.
 * 
 * BUT what about "pointers to any two things"? Seems hard to encode
 * without nesting a local uniqtype, or something like one, within ourselves somehow.
 * 
 * OR a sort() function: need to type the comparison function in terms of the 
 * array elements.
 * 
 * or (to give an example that's not functions)
 * a list of records holding pointers to functions
 * where those functions share a common (parametric) type?
 * 
 * I have so far been saying "these things don't need uniqtypes; define your own
 * relations on uniqtypes, like __like_a, to express these abstraction familial
 * relationships".
 * 
 * Perhaps this is right? In OCaml, a generic swap() function really is just
 * generic in 'a, and works via void*s, so describing it as (void*, void*)-
 * 
 * Still feels like modelling existential voids is useful, to distinguish different
 * contracts. Coining type variables therefore still seems valuable.
 * 
 * YES. Want a way to consume a uniqtype s.t. can query it: "if I give you a T, 
 * what will you give me back?".
 * 
 * Is this something that make_precise can deal with? i.e. we can say to it, 
 * in the case of function types, "fix the context s.t. the argument is a T; 
 * now make yourself precise".
 * 
 * Idea for a HACK: support "infinitely many" addresses for __uniqtype____PTR_void.
 * That way, different "void"s can be distinguished, but we bake in "genericity via pointers".
 * 
 * BETTER hack: let a uniqtype say how many existentials it's defining,
 * then reference them as it would another uniqtype.
 * i.e. all existentials are pointed-to a.k.a. indirect? seems sane.
 * 
 * Very simple example: a polymorphic tuple.
 * ('a * 'b * 'c) and ('a * 'a * 'a) are very different.
 * Can we represent this difference in uniqtypes?
 * PERHAPS when we introduce an existential, we specify what it erases to.
 * i.e. any uniqtype can introduce existentials among its "related" types;
 * each one supplies a pointer to the uniqtype it erases to, e.g. __uniqtype___PTR_void.
 * SO, yes, polymorphic tuples:
 * 
 * - define a tuple whose member types are
 *     -- "erase to" __uniqtype___PTR_void
 *     -- HMM -- hard to encode
 *        BUT we probably can do it -- stuff some extra fields in the 'related' thing
 *             i.e. related is (1) what the type erases to; (2) 
 * 
 * - Stephen D says
   
   > -- "layout returned by function f, for argument layouts [...]"
   > (application) -- this follows from the type of the function and
   > its args' layouts;

   This is not the case. A function result's layout need not be
   determined by its input's layout.

 * ... and I think he might mean "closure" for "function", i.e. 
 * if I do (f 2) h
 * 
 *        and f has type 'a -> 'b -> 'a

 * then the application to 2 has given us a closure
 * which we can then give some unrelated type (the type of h)
 * 
 * Can I have a top-level function of type int -> 'a ?   It seems odd.
 * 
 * So my tentative plan is that generic uniqtypes are actually "uniqtype schemes"
 * consisting of 
 * 
 * - an erasure (the base uniqtype);
 * - constraints on how this may be specialized (instantiation of voids).
 * 
 * When generic definitions are instantiated/activated, we specialize-and-memoise:
 * generate a specialized uniqtype, but memoize it so that future 
 * invocations/instantiations of the same specialization get the same identity.
 * The specialization should also include a back-link to the scheme that generated it,
 * and something about the point where it was generated (and maybe any other points
 * where its memoized self was re-used).
 * 
 */

/* Need to nail down the lower/upper bounds that an imprecise uniqtype denotes.
 * I think it's like this:
 * 
 * - array (length): 
 *    -- if imprecise bound is not -1, it is the precise lower and upper bound
 *    -- if imprecise bound is -1, lower bound is 0 and no upper bound
 *    -- this is quite inexpressive! e.g. can't represent hard lower and imprecise upper (common)
 *           except via make_precise, i.e. making both hard
 *           ... could borrow negative numbers for this, i.e. 0 means "at least 0, no upper"
 *                                                           -1 means "at least 1, no upper"
 * 
 * - subobjects (presence):
 *    -- may_be_invalid_first5 and may_be_invalid_rest 
 *           encode fields' guaranteed presence / possible absence
 *    -- can't currently express possible presence / guaranteed absence
 *           except via make_precise
 *    -- I think this is okay
 */

/* Question: can struct uniqtype describe its own structure? 
 * This means: 
 * 
 * - describing which union arm is valid at which time 
 * - describing how long the "related" array is. 
 * 
 * Because of the unions, we probably have to write a make_precise function.
 * That said, we could use __libcrunch_get_valid_union_member if we were
 * happy to crunch-compile all clients of liballocs (we're not, obviously).
 * Bugs could make this get inconsistent with the discriminants, but hey ho.
 * More seriously, ".un.info" is always valid, so needs some simultaneity
 * bit.
 * 
 * The length of the related[] array also requires a make_precise function.
 * It's harder to see how to get around that. Oh, but we can just use the
 * allocation size information: each uniqtype's array is bounded by the end
 * of its containing allocation.
 *
 * This hints at a generic, recursive make_precise function for composites: 
 * for any union member, call its make_precise which will delegate to libcrunch's
 * union tracker; for any array member, *if* it is bounded by the containing allocation, 
 * use liballocs to probe where that is. 
 * 
 * To infer that this allocation-bounding is sound, maybe the uniqtype needs a 
 * "no_arrays" flag? Perhaps having pos_maxoff == (unsigned long) -1 is good enough.
 * That still feels like a leap (C-specific?).
 */


#define UNIQTYPE_STRINGIFY(...) #__VA_ARGS__
#define UNIQTYPE_XSTRINGIFY(...) UNIQTYPE_STRINGIFY( __VA_ARGS__ )
#define UNIQTYPE_DECLSTR UNIQTYPE_XSTRINGIFY(UNIQTYPE_DECLS)

/* At present, these are created in each dumptypes run. Probably
 * they should simply be dynamically created by liballocs. */
extern struct uniqtype __uniqtype__void __attribute__((weak));
extern struct uniqtype __uniqtype____EXISTS1__1 __attribute__((weak)); // 'a, the arbitrary abstract type
extern struct uniqtype __uniqtype____EXISTS1___PTR__1 __attribute__((weak)); // pointer to 'a
extern struct uniqtype __uniqtype____uninterpreted_byte __attribute__((weak)); // byte

#ifdef __cplusplus
#define NULL_UNIQTYPE 0
#else
#define NULL_UNIQTYPE (void*)0
#endif

#define UNIQTYPE_SIZE_IN_BYTES(u)        ((u)->pos_maxoff)
#define UNIQTYPE_IS_SUBPROGRAM_TYPE(u)   ((u)->un.info.kind == SUBPROGRAM)
#define UNIQTYPE_SUBPROGRAM_ARG_COUNT(u) ((u)->un.subprogram.narg)
#define UNIQTYPE_IS_POINTER_TYPE(u)      ((u)->un.info.kind == ADDRESS)
#define UNIQTYPE_POINTEE_TYPE(u)         (UNIQTYPE_IS_POINTER_TYPE(u) ? (u)->related[0].un.t.ptr : NULL_UNIQTYPE)
#define UNIQTYPE_ULTIMATE_POINTEE_TYPE(u)(UNIQTYPE_IS_POINTER_TYPE(u) ? ((u)->un.info.address.indir_level > 1) ? (u)->related[1].un.t.ptr : (u)->related[0].un.t.ptr : NULL_UNIQTYPE)
#define UNIQTYPE_IS_ARRAY_TYPE(u)        ((u)->un.array.is_array)
#define UNIQTYPE_IS_COMPOSITE_TYPE(u)    ((u)->un.info.kind == COMPOSITE)
#define UNIQTYPE_HAS_SUBOBJECTS(u)       (UNIQTYPE_IS_COMPOSITE_TYPE(u) || UNIQTYPE_IS_ARRAY_TYPE(u))
#define UNIQTYPE_HAS_KNOWN_LENGTH(u)     ((u)->pos_maxoff != UINT_MAX)
#define UNIQTYPE_IS_BASE_TYPE(u)         ((u)->un.info.kind == BASE)
#define UNIQTYPE_IS_ENUM_TYPE(u)         ((u)->un.info.kind == ENUMERATION)
#define UNIQTYPE_IS_BASE_OR_ENUM_TYPE(u) (UNIQTYPE_IS_BASE_TYPE(u) || UNIQTYPE_IS_ENUM_TYPE(u))
#define UNIQTYPE_ARRAY_LENGTH(u)         (UNIQTYPE_IS_ARRAY_TYPE(u) ? (u)->un.array.nelems : -1)
#define UNIQTYPE_ARRAY_ELEMENT_TYPE(u)   (UNIQTYPE_IS_ARRAY_TYPE(u) ? (u)->related[0].un.t.ptr : NULL_UNIQTYPE)
#define UNIQTYPE_SUBOBJECT_TYPE(u, r) \
   (UNIQTYPE_IS_ARRAY_TYPE(u) ? (r)->un.t.ptr : \
   UNIQTYPE_IS_COMPOSITE_TYPE(u) ? (r)->un.memb.ptr : NULL_UNIQTYPE)
#define UNIQTYPE_SUBOBJECT_OFFSET(u, r, spanned_offset) \
   (UNIQTYPE_IS_ARRAY_TYPE(u) ? /* round down */ \
       (UNIQTYPE_SUBOBJECT_TYPE(u, r)->pos_maxoff * ((spanned_offset) / UNIQTYPE_SUBOBJECT_TYPE(u, r)->pos_maxoff)) \
       : UNIQTYPE_IS_COMPOSITE_TYPE(u) ? (r)->un.memb.off : (unsigned)-1 )
#define UNIQTYPE_COMPOSITE_MEMBER_COUNT(u) (UNIQTYPE_IS_COMPOSITE_TYPE(u) ? (u)->un.composite.nmemb : 0)
#define UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(u) \
   ((u)->un.info.kind == BASE && (u)->un.base.enc == 0x5 /*DW_ATE_signed */)
#define UNIQTYPE_BASE_TYPE_SIGNEDNESS_COMPLEMENT(u) \
   (((u)->un.info.kind == BASE && \
       ((u)->un.base.enc == 0x5 /* DW_ATE_signed */ || ((u)->un.base.enc == 0x7 /* DW_ATE_unsigned */))) ? \
	    (u)->related[0].un.t.ptr : NULL_UNIQTYPE)
#define UNIQTYPE_NAME(u) __liballocs_uniqtype_name(u) /* helper in liballocs.c */
#define UNIQTYPE_SYMBOL_NAME(u) __liballocs_uniqtype_symbol_name(u) /* helper in liballocs.c */
#define UNIQTYPE_IS_SANE(u) ( \
	((u)->un.array.is_array && ((u)->un.array.nelems == 0 || (u)->pos_maxoff > 0)) \
	|| ((u)->un.info.kind == VOID && (u)->pos_maxoff == 0) \
	|| ((u)->un.info.kind == BASE && (u)->un.base.enc != 0) \
	|| ((u)->un.info.kind == ENUMERATION && 1 /* FIXME */) \
	|| ((u)->un.info.kind == COMPOSITE && ((u)->pos_maxoff <= 1 || (u)->un.composite.nmemb > 0)) \
	|| ((u)->un.info.kind == ADDRESS && 1 /* FIXME */) \
	|| ((u)->un.info.kind == SUBRANGE && 1 /* FIXME */) \
	|| ((u)->un.info.kind == SUBPROGRAM && (u)->related[0].un.t.ptr != NULL) \
	)
#define UNIQTYPE_IS_ABSTRACT(u) ((u)->make_precise)
#define NAME_FOR_UNIQTYPE(u) UNIQTYPE_NAME(u)
#define UNIQTYPE_BASE_TYPE_BIT_SIZE(u)         (((u)->un.info.kind != BASE) ? 0 : \
                                                   8*(u)->pos_maxoff - ( \
                                                  ( (u)->un.base.one_plus_log_bit_size_delta ? \
                                                    1ul<<((u)->un.base.one_plus_log_bit_size_delta - 1) \
                                                    : 0 ) + (u)->un.base.bit_size_delta_delta \
                                                  ) )
#define UNIQTYPE_BASE_TYPE_BIT_OFFSET(u)         (((((u)->un.info.kind != BASE) ? 0 : \
                                           (((u)->un.base.bit_off) < 0) ? \
                                                    (8*((u)->pos_maxoff) - (-((u)->un.base.bit_off))) \
                                                       : (u)->un.base.bit_off)))

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
