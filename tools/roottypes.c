#include "uniqtype-defs.h"

/* uniqtype for void */
const char *__uniqtype__void_subobj_names[]  __attribute__((section (".data.__uniqtype__void, \"awG\", @progbits, __uniqtype__void, comdat#")))= { (void*)0 };
struct uniqtype __uniqtype__void __attribute__((section (".data.__uniqtype__void, \"awG\", @progbits, __uniqtype__void, comdat#"))) = {
	{ 0, 0, 0 },
	0 /* pos_maxoff */,
	{ _void: { VOID } },
	/* make_precise */ (void*)0, /* related */ {
		{ { t: { (void*) 0 } } }
	}
};

/* uniqtype for generic pointers */
const char *__uniqtype____EXISTS1___PTR__1_subobj_names[]  __attribute__((section (".data.__uniqtype____EXISTS1___PTR__1, \"awG\", @progbits, __uniqtype____EXISTS1___PTR__1, comdat#")))= { (void*)0 };
struct uniqtype __uniqtype____EXISTS1___PTR__1 __attribute__((section (".data.__uniqtype____EXISTS1___PTR__1, \"awG\", @progbits, __uniqtype____EXISTS1___PTR__1, comdat#"))) = {
	{ 0, 0, 0 },
	8 /* pos_maxoff */,
	{ address: { .kind = ADDRESS, .genericity = 1, .indir_level = 1 } },
	/* make_precise */ __liballocs_make_precise_identity, /* related */ {
		{ { t: { (void*) 0 } } }
	}
};

/* uniqtype for uninterpreted bytes */
const char *__uniqtype____uninterpreted_byte_subobj_names[]  __attribute__((section (".data.__uniqtype____uninterpreted_byte, \"awG\", @progbits, __uniqtype____uninterpreted_byte, comdat#")))= { (void*)0 };
struct uniqtype __uniqtype____uninterpreted_byte __attribute__((section (".data.__uniqtype____uninterpreted_byte, \"awG\", @progbits, __uniqtype____uninterpreted_byte, comdat#"))) = {
	{ 0, 0, 0 },
	1 /* pos_maxoff */,
	{ base: { .kind = BASE, .enc = 0 /* no encoding */ } },
	/* make_precise */ (void*)0, /* related */ {
		{ { t: { (void*) 0 } } }
	}
};
