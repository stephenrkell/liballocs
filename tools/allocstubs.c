/* A version of this file gets linked in to every link job that
 * is processed by the liballocs linker plugin (gold-plugin.so).
 * On the cpp command line, various macros MUST be defined.
 * These are lists, declaring various kinds of allocation functions.
 * Examples of each (as envvars and old-style; they get mangled slightly for macroisation; FIXME):

LIBALLOCS_ALLOC_FNS="Perl_safesysmalloc(Z)p \
LIBALLOCS_FREE_FNS="Safefree(P) perl_free(P) PerlMem_free(P)"
LIBALLOCS_ALLOCSZ_FNS="__ckd_calloc_2d__(iiIpi)p __ckd_calloc_3d__(iiiIpi)p fe_create_2d(iiI)p"
LIBALLOCS_SUBALLOC_FNS="Perl_newSV(p)p"
LIBALLOCS_SUBFREE_FNS="libcrunch_free_object(P)->ggc_alloc"
LIBALLOCS_ALLOCSITE_OVERRIDE="S_more_sv,Perl_safesys_malloc,char,sv"

 * For LIBALLOCS_SUB{ALLOC,FREE}_FNS, the named functions should be
 * defined elsewhere in the link job. For others this needn't be the
 * case, since we may simply be creating wrappers for the caller side.

 * Additionally, LIBALLOCS_MALLOC_CALLEE_WRAPPERS may optionally be
 * defined. If it is, callee-side indexing stubs will be generated.
 * See liballocs/Documentation/malloc-indexing.txt
 * FIXME: this should also be variadic and prefix-aware.
 */

#ifdef LIBALLOCS_MALLOC_CALLEE_WRAPPERS

#undef MALLOC_PREFIX
#define MALLOC_PREFIX(s) __wrap___real_##s
#undef HOOK_PREFIX
#define HOOK_PREFIX(s) hook_##s
#include "../src/user2hook.c"
#undef HOOK_PREFIX
#define HOOK_PREFIX(s) __terminal_hook_##s
#include "mallochooks/hookapi.h"
#define ALLOC_EVENT(s) __global_malloc_##s
#define HOOK_PREFIX(s) __terminal_hook_##s
#include "../src/hook2event.c"
/* set the prefix that will get dlsym'd. But what is it?
 * It can't be 'no prefix'... it has to be __real_. Remember
 * we're actually defining the mallocs locally now, so
 * '__real_malloc' is a real symbol. */
#undef MALLOC_PREFIX
#define MALLOC_PREFIX(s) __real_##s
#define dlsym_nomalloc fake_dlsym
#undef HOOK_PREFIX
#define MALLOC_DLSYM_TARGET get_link_map(__terminal_hook_malloc)
#include "../src/terminal-indirect-dlsym.c"
#define RELF_ALREADY_DEFINED_STRUCTURES /* see below */
/* Our caller-side stubgen logic (below) will generate
  __wrap_malloc functions (et al), that want to call __real_malloc (et al).
  But we want them to call the caller-side stuff we just generated, so....
  (+ note that the output DSO's global 'malloc' will point to out __wrap_malloc (thanks to xwrap)
 */
#define __real_malloc __wrap___real_malloc
#define __real_free __wrap___real_free
#define __real_calloc __wrap___real_calloc
#define __real_realloc __wrap___real_realloc
#define __real_free __wrap___real_free
#define __real_memalign __wrap___real_memalign

#endif /* LIBALLOCS_MALLOC_CALLEE_WRAPPERS */

#ifndef RELF_ALREADY_DEFINED_STRUCTURES
#define RELF_DEFINE_STRUCTURES
#endif
#include "stubgen.h"


/* Here we generate all the wrappers that the invoker told us about.
 * But what about the case where they're not defined in the link?
 * Then we will get an undefined reference error for __real_*.
 * The xwrap plugin already handles the case where something is defined
 * only in a .so, not in the link proper; it turns itself into --wrap.
 * So we really only need to worry about the case where a symbol is
 * not defined at all. Probably the plugin needs to prune those symnames
 * from the macro that it passes us on the compiler command line. */
LIBALLOCS_ALLOC_FNS(make_caller_alloc_wrapper)
LIBALLOCS_FREE_FNS(make_caller_free_wrapper)
LIBALLOCS_ALLOCSZ_FNS(make_caller_sz_wrapper)
LIBALLOCS_SUBALLOC_FNS(make_suballoc_wrapper)
LIBALLOCS_SUBFREE_FNS(make_subfree_wrapper)

/* Can we now handle LIBALLOCS_ALLOCSITE_OVERRIDE by emitting
 * .dynamic section content in this file? In short: no, this doesn't work,
 * because our .dynamic section gets appended after the DT_NULL entry
 * in the linker-generated section. See Experiments/custom-dynamic-section.
 * However, we can do it with --spare-dynamic-tags and some
 * post-hoc editing, either at run time or on the binary.
 * Alternatively we could do the post-hoc editing to move the
 * null terminator to the end, in which case we could emit the
 * content here. Does any other code/system emit .dynamic content that
 * shouldn't be included before the null terminator?
 * Maybe we need a new linker plugin, custom-dynent-plugin.so
 * that takes arguments like
 * 'DT_NEEDED=blah.so'
 * or
 * '0x6a110042=mystring'
 * where these strings need to be generated and added to the link
 * in a new .dynstr section...
 * Can we add a new dynstr section?
 * Find the equals; if successful, try strtol with base=16, else
 * look up a string (DT_*) in SOMEWHERE (-g3 / .debug_macro?)
 * and use it if it falls within range (0x6.......?)
 * FIXME how to distinguish string data from other? Similar strtol approach?
 * Need to be careful not to clobber existing --spare-dynamic-tags
 * value... I think the trick is to always restart exactly once,
 * but to record the original number of spare tags requested (0 if absent)
 * in the sentinel environment variable.
 * Note that our plugin also has to open the output binary and do
 * the edit to the .dynamic section. Want an elftin tool that can do this
 * standalone, which we call out to lib-style.
 */
