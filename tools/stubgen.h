#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#if 0
#include "relf.h" /* for fake_dlsym, used by callee wrappers, but they are also ifdef'd out just now */
#endif

#ifndef CURRENT_ALLOC_VARS_QUALIFIERS
#define CURRENT_ALLOC_VARS_QUALIFIERS extern __thread
#define CURRENT_ALLOC_VARS_QUALIFIERS_POST  /* __attribute__((weak)) */
#endif
CURRENT_ALLOC_VARS_QUALIFIERS void *__current_allocsite CURRENT_ALLOC_VARS_QUALIFIERS_POST;
CURRENT_ALLOC_VARS_QUALIFIERS void *__current_allocfn CURRENT_ALLOC_VARS_QUALIFIERS_POST;
CURRENT_ALLOC_VARS_QUALIFIERS size_t __current_allocsz CURRENT_ALLOC_VARS_QUALIFIERS_POST;
CURRENT_ALLOC_VARS_QUALIFIERS int __currently_freeing CURRENT_ALLOC_VARS_QUALIFIERS_POST;
CURRENT_ALLOC_VARS_QUALIFIERS int __currently_allocating CURRENT_ALLOC_VARS_QUALIFIERS_POST;

/* these are our per-allocfn caller wrappers */

#define type_for_argchar_z size_t
#define type_for_argchar_Z size_t

#define type_for_argchar_p void*
#define type_for_argchar_P void*

#define type_for_argchar_i int
#define type_for_argchar_I int

#define cap_arg_z(n)
#define cap_arg_Z(n) arg ## n

#define cap_arg_p(n)
#define cap_arg_P(n) arg ## n

#define cap_arg_i(n)
#define cap_arg_I(n) arg ## n

#include <boost/preprocessor/repetition.hpp>
#include <boost/preprocessor/tuple.hpp>
#include <boost/preprocessor/seq.hpp>
#include <boost/preprocessor/arithmetic/sub.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>

/* FIXME: delete these? */
#define make_argdecl(num, c) \
	type_for_argchar_ ## c arg ## num
#define make_argname(num, c) \
	arg ## num
#define make_argtype(num, c) \
	type_for_argchar_ ## c

/* New versions using boost-pp */
#define make_argdecl4(r, n, i, c) \
	BOOST_PP_CAT(type_for_argchar_, c) arg ## i \
    BOOST_PP_COMMA_IF(BOOST_PP_LESS(BOOST_PP_ADD(i,1),n))
#define make_argname4(r, n, i, c) \
	arg ## i \
    BOOST_PP_COMMA_IF(BOOST_PP_LESS(BOOST_PP_ADD(i,1),n))

#define make_argdecls(tup) \
	BOOST_PP_SEQ_FOR_EACH_I( \
	   make_argdecl4, \
	   /* data = n */ BOOST_PP_SEQ_SIZE(BOOST_PP_TUPLE_TO_SEQ(tup)), \
	   BOOST_PP_TUPLE_TO_SEQ(tup) \
	)

#define make_argnames(tup) \
	BOOST_PP_SEQ_FOR_EACH_I( \
	   make_argname4, \
	   /* data = n */ BOOST_PP_SEQ_SIZE(BOOST_PP_TUPLE_TO_SEQ(tup)), \
	   BOOST_PP_TUPLE_TO_SEQ(tup) \
	)

#define map_over_argtup_nocomma(tup, f) \
    BOOST_PP_SEQ_FOR_EACH_I(f, nothing, BOOST_PP_TUPLE_TO_SEQ(tup))
#define map_over_argtup_nocomma_rev(tup, f) \
    BOOST_PP_SEQ_FOR_EACH_I(f, \
	   nothing, \
	   BOOST_PP_TUPLE_TO_SEQ(BOOST_PP_TUPLE_REVERSE(tup)) \
	)

#define cap_test_one_arg4(r, n, i, c) \
    BOOST_PP_CAT(cap_arg_, c)(i)

#define cap_arg(tup) \
	BOOST_PP_SEQ_FOR_EACH_I(cap_test_one_arg4, nothing, BOOST_PP_TUPLE_TO_SEQ(tup))

#define pre_realarg(num, c) \
	pre_realarg_ ## c (arg ## num)

#define post_realarg(num, c) \
	post_realarg_ ## c (arg ## num)

#define pre_realarg4(r, data, i, elem) \
	pre_realarg(i, elem)

#define post_realarg4(r, data, i, elem) \
	post_realarg(i, elem)

#ifndef do_caller_wrapper_init
#define do_caller_wrapper_init(name)
#endif

#ifndef do_arginit_z
#define do_arginit_z(argname)
#endif
#ifndef do_arginit_Z
#define do_arginit_Z(argname)
#endif
#ifndef do_arginit_p
#define do_arginit_p(argname)
#endif
#ifndef do_arginit_P
#define do_arginit_P(argname)
#endif
#ifndef do_arginit_i
#define do_arginit_i(argname)
#endif
#ifndef do_arginit_I
#define do_arginit_I(argname)
#endif

#ifndef pre_realarg_z
#define pre_realarg_z(argname)
#endif
#ifndef pre_realarg_Z
#define pre_realarg_Z(argname)
#endif
#ifndef pre_realarg_p
#define pre_realarg_p(argname)
#endif
#ifndef pre_realarg_P
#define pre_realarg_P(argname)
#endif
#ifndef pre_realarg_i
#define pre_realarg_i(argname)
#endif
#ifndef pre_realarg_I
#define pre_realarg_I(argname)
#endif

#ifndef pre_realcall
#define pre_realcall(callee, ...)
#endif

#ifndef post_realcall
#define post_realcall(callee, ...)
#endif

#ifndef post_realarg_z
#define post_realarg_z(argname)
#endif
#ifndef post_realarg_Z
#define post_realarg_Z(argname)
#endif
#ifndef post_realarg_p
#define post_realarg_p(argname)
#endif
#ifndef post_realarg_P
#define post_realarg_P(argname)
#endif
#ifndef post_realarg_i
#define post_realarg_i(argname)
#endif
#ifndef post_realarg_I
#define post_realarg_I(argname)
#endif

#ifndef do_caller_wrapper_fini
#define do_caller_wrapper_fini(name)
#endif

#ifndef do_ret_z
#define do_ret_z(name)
#endif
#ifndef do_ret_Z
#define do_ret_Z(name)
#endif
#ifndef do_ret_p
#define do_ret_p(name)
#endif
#ifndef do_ret_P
#define do_ret_P(name)
#endif
#ifndef do_ret_i
#define do_ret_i(name)
#endif
#ifndef do_ret_I
#define do_ret_I(name)
#endif
#ifndef do_ret_void
#define do_ret_void(name)
#endif

#ifndef do_arginit
#define do_arginit(num, c) do_arginit_ ## c ( arg ## num )
#endif

#define do_arginit4(r, data, i, elem) do_arginit(i, elem)

/* FIXME: everything here really belongs in allocstubs.c. 
 * The stuff above is customisable so that e.g. under libcrunch's shadow stack
 * instrumentation we can generate appropriate instrumented code.
 * (Could we instead just CIL-instrument the allocstubs.i file?
 * Probably not, because allocation functions are assumed not to be
 * instrumented themselves, so we wouldn't get the bounds back.
 * In other words, the instrumentation we do at the macro level is different; it's
 * specialized to the generated code also being a bounds-wrapper function.) */

#define make_caller_wrapper(wrapname, realname, basename, argtup, retchar, leave_size_set) \
	type_for_argchar_ ## retchar realname ( make_argdecls(argtup) ); \
	type_for_argchar_ ## retchar wrapname( make_argdecls(argtup) ) \
	{ \
		do_caller_wrapper_init(basename) \
		map_over_argtup_nocomma(argtup, do_arginit4) \
		type_for_argchar_ ## retchar real_retval; \
		_Bool set_currently_allocating = 0; \
		_Bool do_setting = 0; \
		if (&__current_allocfn && !__current_allocfn) do_setting = 1; \
		if (do_setting) \
		{ \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			/* only set the site if we don't have one already */ \
			if (!__current_allocsite) __current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &realname; \
			__current_allocsz = cap_arg(argtup); \
		} \
		map_over_argtup_nocomma_rev(argtup, pre_realarg4) \
		pre_realcall( realname, make_argnames(argtup) ) \
		type_for_argchar_ ## retchar retval = realname( make_argnames(argtup) ); \
		post_realcall ( realname, make_argnames(argtup) ) \
		map_over_argtup_nocomma(argtup, post_realarg4) \
		if (do_setting) \
		{ \
			/* __current_alloclevel = 0; */ \
			/* zero the site now the alloc action is completed, even if it was already set */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			if (!leave_size_set) __current_allocsz = 0; \
			if (set_currently_allocating) __currently_allocating = 0; \
		} \
		real_retval = retval; \
		do_caller_wrapper_fini(basename) \
		do_ret_ ## retchar (basename) \
		return real_retval; \
	}

/* This is like the normal alloc caller wrapper but we allow for the fact that 
 * we're a nested allocator. We want to factor out the nested case by splitting off
 * the callee-side logic. How best to split it off?
 * We have both caller and callee parts in one.
 * The callee parts are the setting of *_alloclevel and the call to
 * __index_small_alloc. (The *_alloclevel thing is just a sanity check
 * that for a given function, we always end up indexing at the same level
 * in the allocation tree.)
 * The setting of __current_allocfn could be done as a caller or callee thing,
 * i.e. it could be useful for ordinary caller-side wrappers too.
 * If this was just a caller-side wrapper that called __real_ggc_alloc (say),
 * how would we slip in the __index stuff?
 * Could we do the same thing we do with 'malloc'? Before outputting the caller stub, do
     #define __real_ggc_alloc __wrap___real_ggc_alloc
 * so that the caller stub actually calls __wrap___real_malloc,
 * and define that. For malloc the __wrap___real_* are defined by [user2hook.c, hook2event.c]
 * and dispatched to [terminal-indirect-dlsym.c] which we ensure dlsyms the 'real real' function.
 * For a custom allocator it could be simpler...
 * maybe we could just generate the __wrap___real_* right here underneath the __wrap*?
 * Problem: how would it call the 'real real' function?
 * Tentative solution: we'd need to #undef __real_ggc_alloc,
 * or use some additional parameterisation perhaps:
 * YES, if we make the following take 'wrapname' and 'realname' args.
 * Used this approach to eliminate the separate caller_ functions; see allocstubs.c.
 * */

#define make_free_wrapper(wrapname, realname, basename, argtup) /* HACK: assume void-returning for now */ \
	void realname( make_argdecls(argtup) ); \
	void wrapname( make_argdecls(argtup) ) \
	{ \
		do_caller_wrapper_init(basename) \
		map_over_argtup_nocomma(argtup, do_arginit4) \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		map_over_argtup_nocomma_rev(argtup, pre_realarg4) \
		pre_realcall( realname, make_argnames(argtup) ) \
		realname( make_argnames(argtup) ); \
		post_realcall ( realname, make_argnames(argtup) ) \
		map_over_argtup_nocomma(argtup, post_realarg4) \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
		do_caller_wrapper_fini(basename) \
		do_ret_void(basename) \
	}

#define make_caller_alloc_wrapper(sym, argtup, retchar) \
	make_caller_wrapper(__wrap_ ## sym, __real_ ## sym, sym, argtup, retchar, /* leave sz set? */ 0)

#define make_caller_free_wrapper(sym, argtup, retchar) \
	make_free_wrapper(__wrap_ ## sym, __real_ ## sym, sym, argtup)

#define make_caller_sz_wrapper(sym, argtup, retchar) \
	make_caller_wrapper(__wrap_ ## sym, __real_ ## sym, sym, argtup, retchar, /* leave sz set? */ 1)

int  __index_small_alloc(void *ptr, int level, unsigned size_bytes);
void __unindex_small_alloc(void *ptr, int level);

#define make_suballoc_wrapper(sym, argtup, retchar) \
	static int sym ## _alloclevel; /* FIXME: thread-safety for access to this. */ \
	type_for_argchar_ ## retchar __real_ ## sym ( make_argdecls(argtup) ); \
	make_caller_wrapper(__wrap_ ## sym, __wrap___real_ ## sym, sym, argtup, retchar, 0) \
	type_for_argchar_ ## retchar __wrap___real_ ## sym( make_argdecls(argtup) ) \
	{ \
		type_for_argchar_ ## retchar retval = __real_ ## sym( make_argnames(argtup) ); \
		int seen_alloclevel = __index_small_alloc(retval, /* sym ## _alloclevel */ -1, \
			__current_allocsz); \
		assert(sym ## _alloclevel == 0 || seen_alloclevel == sym ## _alloclevel); \
		if (sym ## _alloclevel == 0) sym ## _alloclevel = seen_alloclevel; \
		return retval; \
	}

#define make_subfree_wrapper(sym, argtup, corresponding_alloc_name) \
	void __real_ ## sym ( make_argdecls(argtup) ); \
	make_free_wrapper(__wrap_ ## sym, __wrap___real_ ## sym, sym, argtup) \
	void __wrap___real_ ## sym( make_argdecls(argtup) ) \
	{ \
		assert(corresponding_alloc_name ## _alloclevel); \
		/* HACK: assume void */ __real_ ## sym( make_argnames(argtup) ); \
		__unindex_small_alloc(cap_arg(argtup), corresponding_alloc_name ## _alloclevel); \
	}

/* We also have some macros for generating callee wrappers. These are what 
 * do the indexing, at least logically. Being "callee" wrapper, we only 
 * generate them for objects that really do define the given allocator.
 * 
 * Logically, indexing operations belong here: we should actually invoke
 * the indexing hooks from this wrapper. Currently this isn't what happens.
 * Instead:
 * 
 * - "deep" allocators get the indexing done on the caller side (see above);
 *
 * - wrappers around the system malloc get hte indexing done in the preload 
 *   malloc;
 *
 * - objects which define their own malloc get the callee wrappers from
 *   liballocs_nonshared.a, which is using a mashup of this style of __wrap_*
 *   and the mallochooks stuff (in nonshared_hook_wrappers.c).
 *
 * So there is a gap to close off here: we should do the indexing here,
 * and only rely on the preload as a "special case" albeit the common case,
 * where libc supplies the malloc but is not itself built via us. We should
 * generate the "struct allocator" instance here. And we should dogfood these
 * macros to generate the actual preload stuff.
 *
 * Note that to do this properly, we need to distinguish actual alloc
 * functions from wrappers. Currently LIBALLOCS_ALLOC_FNS really refers
 * to wrappers; for your own actual allocators, they need to be a suballoc.
 *
 * See below for the alloc event stuff which is a step towards clearing this
 * mess up.
 *
 * I thought these were unused. But they're not.
       # for genuine allocators (not wrapper fns), also make a callee wrapper
       if allocFn in self.allSubAllocFns(): # FIXME: cover non-sub clases
           stubsfile.write("make_callee_wrapper(%s, %s)\n" % (fnName, retSig))
 * What do __wrap___real_ functions do in the suballocator (non-malloc) case?
 * They seem simply to dlsym the real symbol and call it. So why are they needed?
 * Because we link with --wrap X and also --wrap __real_X
 * so our reference to __real_x actually goes to __wrap___real_X
 * but we can't write __real___real_X -- it doesn't work. Hence the dlsym.
 * Isn't the answer simply not to link with --wrap __real_X for suballoc funcs?
 * Let's try that.
 */
#if 0
#define make_callee_wrapper(name, retchar) \
	type_for_argchar_ ## retchar __wrap___real_ ## name ( arglist_ ## name (make_argdecl) ) \
	{ \
		static type_for_argchar_ ## retchar (*real_ ## name)( arglist_ ## name (make_argtype) ); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, "__real_" #name); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, #name); /* probably infinite regress... */ \
		if (!real_ ## name) abort(); \
		type_for_argchar_ ## retchar real_retval; \
		real_retval = real_ ## name( arglist_ ## name (make_argname) ); \
		return real_retval; \
	}
#define make_void_callee_wrapper(name) \
	void __wrap___real_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		void (*real_ ## name)( arglist_ ## name (make_argtype) ); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, "__real_" #name); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, #name); /* probably infinite regress... */ \
		if (!real_ ## name) abort(); \
		real_ ## name( arglist_ ## name (make_argname) ); \
		return; \
	}
#endif

/* Protos for our hook functions. The mallocapi-to-hookapi glue comes
 * from a copy of alloc_events.c. */
#include "mallochooks/eventapi.h"

/* hookapi-to-indexapi glue can be generated! */
/* TODO: We could e.g. also parameterise
 * the generation by alignment, or some other parameter of the malloc,
 * so that the code is tailored to that malloc. */
#define ALLOC_ALLOCATOR_NAME(frag) frag ## _allocator
#define ALLOC_EVENT_INDEXING_DEFS4(allocator_namefrag, index_namefrag, sizefn, do_lifetime_policies) \
ALLOC_EVENT_ATTRIBUTES void ALLOC_EVENT(post_init)(void) {} \
ALLOC_EVENT_ATTRIBUTES \
void  \
ALLOC_EVENT(post_successful_alloc)(void *allocptr, size_t modified_size, size_t modified_alignment, \
		size_t requested_size, size_t requested_alignment, const void *caller) \
{ \
	index_namefrag ## _index_insert(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), \
		ensure_arena_info_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), allocptr), \
		allocptr /* == userptr */, requested_size, \
		__current_allocsite ? __current_allocsite : caller, sizefn); \
} \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(pre_alloc)(size_t *p_size, size_t *p_alignment, const void *caller) \
{ \
	/* We increase the size by the amount of extra data we store,  \
	 * and possibly a bit more to allow for alignment.  */ \
	size_t orig_size = *p_size; \
	size_t size_to_allocate = CHUNK_SIZE_WITH_TRAILER(orig_size, INSERT_TYPE, void*); \
	assert(0 == size_to_allocate % ALIGNOF(void *)); \
	*p_size = size_to_allocate; \
} \
ALLOC_EVENT_ATTRIBUTES \
int ALLOC_EVENT(pre_nonnull_free)(void *userptr, size_t freed_usable_size) \
{ \
	if (do_lifetime_policies) /* always statically known but we can't #ifdef here */ \
	{ \
		lifetime_insert_t *lti = lifetime_insert_for_chunk(userptr, sizefn); \
		*lti &= ~MANUAL_DEALLOCATION_FLAG; \
		if (*lti) return 1; /* Cancel free if we are still alive */ \
		__notify_free(userptr); \
	} \
	index_namefrag ## _index_delete(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), \
		ensure_arena_info_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), \
		userptr/*, freed_usable_size*/, sizefn); \
	return 0; \
} \
 \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(post_nonnull_free)(void *userptr) \
{} \
 \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(pre_nonnull_nonzero_realloc)(void *userptr, size_t size, const void *caller) \
{ \
	/* When this happens, we *may or may not be freeing an area* */ \
	/* -- i.e. if the realloc fails, we will not actually free anything. */ \
	/* However, when we were using trailers, and  */ \
	/* in the case of realloc()ing a *slightly smaller* region,  */ \
	/* the allocator might trash our insert (by writing its own data over it).  */ \
	/* So we *must* delete the entry first, */ \
	/* then recreate it later, as it may not survive the realloc() uncorrupted. */  \
	/* */ \
	/* Another complication: if we're realloc'ing a bigalloc, we might have to */ \
	/* move its children. BUT should the user ever do this? It's only sensible */ \
	/* to realloc a suballocated area if you know the realloc will happen in-place,  */ \
	/* i.e. if you're making it smaller (only).  */ \
	/*  */ \
	/* BUT some bigallocs are just big; they needn't have children.  */ \
	/* For those, does it matter if we delete and then re-create the bigalloc record? */ \
	/* I don't see why it should. */ \
	index_namefrag ## _index_delete(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), \
		arena_info_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), \
		userptr/*, malloc_usable_size(ptr)*/, sizefn); \
} \
ALLOC_EVENT_ATTRIBUTES \
void ALLOC_EVENT(post_nonnull_nonzero_realloc)(void *userptr, \
	size_t modified_size,  \
	size_t old_usable_size, \
	const void *caller, void *new_allocptr) \
{ \
	/* FIXME: This requested size could be wrong. */ \
	/* The caller should give us the real requested size instead. */ \
	size_t requested_size = __current_allocsz ? __current_allocsz : \
		modified_size - sizeof(INSERT_TYPE); \
	index_namefrag ## _index_reinsert_after_resize(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), \
		arena_info_for_userptr(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), userptr), \
		userptr, \
		modified_size, \
		old_usable_size, \
		requested_size, \
		caller, \
		new_allocptr, \
		sizefn\
	); \
}
/* Now the allocator itself. */
#define ALLOC_EVENT_ALLOCATOR_DEFS4(allocator_namefrag, index_namefrag, sizefn, do_lifetime_policies) \
extern struct allocator ALLOC_ALLOCATOR_NAME(allocator_namefrag); \
static struct big_allocation *ensure_big(void *addr, size_t size) \
{ \
	return index_namefrag ## _ensure_big(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), addr, size); \
} \
static struct liballocs_err *set_type(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *new_type) \
{ \
	return index_namefrag ## _set_type(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), maybe_the_allocation, \
			obj, new_type, sizefn); \
} \
static struct liballocs_err *get_info( \
	void *obj, struct big_allocation *maybe_the_allocation, \
	struct uniqtype **out_type, void **out_base,  \
	unsigned long *out_size, const void **out_site) \
{ \
	return index_namefrag ## _get_info(&ALLOC_ALLOCATOR_NAME(allocator_namefrag), sizefn, obj, maybe_the_allocation, \
		out_type, out_base, out_size, out_site); \
} \
 \
ALLOC_EVENT_ATTRIBUTES \
struct allocator ALLOC_ALLOCATOR_NAME(allocator_namefrag) = { \
	.name = #allocator_namefrag, \
	.get_info = get_info, \
	.is_cacheable = 1, \
	.ensure_big = ensure_big, \
	.set_type = set_type, \
	.free = (void (*)(struct allocated_chunk *)) free, \
};

#ifdef LIFETIME_POLICIES
#define __do_lp 1
#else
#define __do_lp 0
#endif

#ifndef index_namefrag
#define index_namefrag __generic_malloc
#endif

#define ALLOC_EVENT_INDEXING_DEFS(allocator_namefrag, sizefn) \
  ALLOC_EVENT_INDEXING_DEFS4(allocator_namefrag, __generic_malloc, sizefn, __do_lp) \
  ALLOC_EVENT_ALLOCATOR_DEFS4(allocator_namefrag, __generic_malloc, sizefn, __do_lp)
