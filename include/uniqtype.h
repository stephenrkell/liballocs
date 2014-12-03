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
	union
	{
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
	}
	// variable-length part to instantiate relations 
	// (containedness, complement, 
	struct contained contained[];

*/

#define UNIQTYPE_IS_SUBPROGRAM(u) \
(((u) != (struct uniqtype *) &__uniqtype__void) && \
((u)->pos_maxoff == 0) && \
((u)->neg_maxoff == 0) && !(u)->is_array)

#define MAGIC_LENGTH_POINTER ((1u << 19) - 1u)
#define UNIQTYPE_IS_POINTER_TYPE(u) \
(!((u)->is_array) && (u)->array_len == MAGIC_LENGTH_POINTER)
#define UNIQTYPE_POINTEE_TYPE(u) \
(UNIQTYPE_IS_POINTER_TYPE(u) ? (u)->contained[0].ptr : NULL)


#endif
