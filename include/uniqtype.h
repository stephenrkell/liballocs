#ifndef UNIQTYPE_H_
#define UNIQTYPE_H_

#define UNIQTYPE_DECLS \
struct uniqtype_cache_word \
{ \
	unsigned long addr:47; \
	unsigned flag:1; \
	unsigned bits:16; \
}; \
struct contained { \
	signed offset; \
	struct uniqtype *ptr; \
}; \
struct uniqtype \
{ \
	struct uniqtype_cache_word cache_word; \
	const char *name; \
	unsigned short pos_maxoff; /* 16 bits */ \
	unsigned short neg_maxoff; /* 16 bits */ \
	unsigned nmemb:12;         /* 12 bits -- number of `contained's (always 1 if array) */ \
	unsigned is_array:1;       /* 1 bit */ \
	unsigned array_len:19;     /* 19 bits; 0 means undetermined length */ \
	struct contained contained[]; /* there's always at least one of these, even if nmemb == 0 */ \
}; 

UNIQTYPE_DECLS
		
#define UNIQTYPE_STRINGIFY(s) #s
#define UNIQTYPE_XSTRINGIFY(s) UNIQTYPE_STRINGIFY(s)
#define UNIQTYPE_DECLSTR UNIQTYPE_XSTRINGIFY(UNIQTYPE_DECLS)

/* Tentative redesign for uniqtype

	struct uniqtype_cache_word cache_word;
	const char *name;
	unsigned short pos_maxoff; // 16 bits
	unsigned short neg_maxoff; // 16 bits
	// 32 bits to describe the details
	enum t { BASE, ENUMERATION, ARRAY, WITH_SUBOBJS, ADDRESS, SUBPROGRAM };
	unsigned what:4; // or is_array, to allow 2^31-sized arrays?
	unsigned bits:24 // actually we have 28 bits to play with
		// BASE:        { enc, log_bit_size, log_bit_off } 8 bits each; contained[0] is compl
		// ENUMERATION: hmm                                           ; contained[0] is base?
		// ARRAY:       { nelems } 24 bits                            ; contained[0] is elem_t
		// WITH_SUBOBJS:{ nmembs } 24 bits? "refines" i.e. templatey relations?
		// ADDRESS:     hmm; indirection level? YES, and also genericity -- we need this when deciding whether or not to overwrite
		// SUBPROGRAM:  { is_va, nargs } 1 bit, 23 bits?              ; contained[0] is return_t, contained[1..] args_ts
	;
	// variable-length part to instantiate relations 
	// (containedness, complement, pointee, ... what else?)
	struct contained contained[];

*/
		
extern struct uniqtype __uniqtype__void __attribute__((weak));

#define UNIQTYPE_IS_SUBPROGRAM(u) \
(((u) != (struct uniqtype *) &__uniqtype__void) && \
((u)->pos_maxoff == 0) && \
((u)->neg_maxoff == 0) && !(u)->is_array)

#define UNIQTYPE_SUBPROGRAM_ARG_COUNT(u) (u)->array_len

#define MAGIC_LENGTH_POINTER ((1u << 19) - 1u)
#define UNIQTYPE_IS_POINTER_TYPE(u) \
(!((u)->is_array) && (u)->array_len == MAGIC_LENGTH_POINTER)
#define UNIQTYPE_POINTEE_TYPE(u) \
(UNIQTYPE_IS_POINTER_TYPE(u) ? (u)->contained[0].ptr : NULL)

#define UNIQTYPE_HAS_SUBOBJECTS(u) \
(!UNIQTYPE_IS_SUBPROGRAM(u) && \
((u)->is_array || (u)->nmemb > 0))

#define UNIQTYPE_IS_ARRAY(u) \
(UNIQTYPE_HAS_SUBOBJECTS(u) && (u)->is_array)

#define UNIQTYPE_HAS_DATA_MEMBERS(u) \
(UNIQTYPE_HAS_SUBOBJECTS(u) && !(u)->is_array)

#define UNIQTYPE_HAS_KNOWN_LENGTH(u) \
((u)-> pos_maxoff != ((unsigned short) -1))

#define UNIQTYPE_IS_BASE_OR_ENUM_TYPE(u) \
(((u) != (struct uniqtype *) &__uniqtype__void) && \
((u)->pos_maxoff > 0) && \
((u)->neg_maxoff == 0) && !(u)->is_array && (u)->nmemb == 0)

/* FIXME: does anybody use this one? it used to enumerate all the builtin base types,
 * but now define it to the proper thing. Except (FIXME) it also matches enums! */
// #define UNIQTYPE_IS_BASE(u) UNIQTYPE_IS_BASE_TYPE(u)

/* HACK HACK HACK! */
#define UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(u) \
(UNIQTYPE_IS_BASE_OR_ENUM_TYPE(u) && (u) != (struct uniqtype *) &__uniqtype__float && \
(u) != (struct uniqtype *) &__uniqtype__double)

	/* Tentative improvement:
	 * as we have pos_maxoff, neg_maxoff and (for structs) contained[],
	 * also  have pos_dynoff, neg_dynoff and dyn_contained_fn.
	 * These are functions from the object state to precise descriptions.
	 * The manifest pos_maxoff, neg_maxoff and contained are to be seen as 
	 * *conservative*: recording overapproximations of extent
	 * and underapproximations of the set of members
	 * (specifically, only those members guaranteed to be present at a fixed offset).
	 * 
	 * Perhaps a dyn_decode fun that just gives you back another uniqtype, but *precise*?
	 * The default one just does memcpy!  (Or make it NULL? YES, probably better;
	 * a helper/macro can substitute memcpy for clients who really expect a decoder.)
	 * 
	 * void (*dyn_decode)(struct uniqtype *out, const struct uniqtype *this_uniqtype, size_t outlen, const void *obj, ...);
	 * 
	 * We can generate the dyn_decode function in specific DWARF contexts that require
	 * it. For example, if a DW_TAG_subrange_type has a DW_AT_upper_bound that refers 
	 * to an in-scope DW_TAG_member, we can use this to generate a function from
	 * the member to the precise subrange type's bounds.
	 * 
	 * QUESTION: how are dynamically-generated uniqtypes garbage-collected?
	 * Here we seem to compute them on-demand, writing them into caller-supplied
	 * memory. Do we want to memoise this? That would change the signature a bit.
	 * 
	 * This is a direct refinement of the C model, in which an object is either
	 * "incomplete" (implicitly possibly data-dependent) 
	 * or "complete" (completely manifest). 
	 * A continuum is defined by how much context is necessary to decode the structure.
	 * The dyn* extensions assume that the object memory itself provides sufficient context.
	 * (By contrast, an XOR-doubly-linked-list would require "reached-from" context also.)
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
	 * We can also import a notion of allocations as framing:
	 * if I have a char[], say, that is supposed to be NUL-terminated,
	 * we can say it's terminated 
	 * *either* by the extent of its containing allocation 
	 * *or* by NUL, whichever comes first.
	 * This generalises to a "proper nesting": an object never extends beyond 
	 * its containing allocation.
	 
	 
	 // encode key-value or hashtable-like representations
 typedef struct uniqtype *make_precise_fn_t(struct uniqtype *out, 
     struct uniqtype *in, void *obj, void *ip, // struct mcontext *ctxt, ...
  );
     // can return `out' or another preexisting uniqtype, as it chooses
 
 struct uniqtype {
     // common fields
     const char *name;            // friendly name 
     unsigned pos_size, neg_size; // bound on extent forward/back from start address
                                  // (unsigned) -1 means "no bound"
     
     // discriminated union
     enum tag { BASE, ARRAY, ENUMERATION, ADDRESS, WITH_SUBOBJS, SUBPROGRAM };
     unsigned tag:4;
     union
     {
         struct //BASE
          {   unsigned encoding:7;  // 2's complement, IEEE 754, ...
             unsigned bit_size:10: // allows 31-bit integers, etc..
             unsigned bit_off:9;   // ... needn't start at 0th bit.
         } base;
         struct //ARRAY
          {   unsigned nmemb:28;
         } array;
         struct // ENUMERATION, ADDRESS, WITH_SUBOBJS, SUBPROGRAM
         {  // ...
         }  // ...;
     } u;
     
     // mapping to a dynamically precise type
     make_precise_fn_t *make_precise_fn;
     
     // links to related types: element type, pointee type, 
     // arg/return types, member types, signedness-complement, ...
     struct related_types {
         struct uniqtype *ptr;
		 union
		 {
             intptr_t info;        // offset, field name, ... 
			 struct // BASE
			 {
			 }
			 struct // ARRAY
			 {
				 
			 }
		 } u;
     } rel[];

 */


#endif
