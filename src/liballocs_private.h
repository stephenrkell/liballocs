#ifndef LIBALLOCS_PRIVATE_H_
#define LIBALLOCS_PRIVATE_H_

/* x86_64 only, for now */
#if !defined(__x86_64__) && !defined(X86_64)
#error Unsupported architecture.
#endif
/* FIXME: more portable */
#define PAGE_SIZE 4096
#define LOG_PAGE_SIZE 12
#define PAGE_MASK ~((PAGE_SIZE - 1))

#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#endif

#include <stddef.h>
#include <stdint.h>
#include <link.h>
#include "systrap.h"
#include "librunt.h"
#include "liballocs.h"

#ifndef likely
#define likely(cond) \
  __builtin_expect( (cond), 1 )
#endif
#ifndef unlikely
#define unlikely(cond) \
  __builtin_expect( (cond), 0 )
#endif

/* Macros to help with visibility.
 * We had these long ago, then removed them. Why?
 *
 * We now want to reintroduce them. Why?
 * It's prompted by a very surprising dynamic linking behaviour:
 * a protected-visibility UND symbol won't be resolved
 * to a protected-visibility definition in an external DSO.
 * The UND symbol needs to have default visibility.
 * Within the *same* DSO, it will resolve fine.
 *
 * We could just always make declarations use default visibility,
 * and only put visibility restrictions on definitions.
 * That feels fragile, though, e.g. where we have both prototypea and
 * definition in the same file, and might copy a definition's prototype
 * in order to forward-declare it, say (why ever forward-declare? hmm).
 *
 * Also, protected UND does give us an extra check: it *must* resolve
 * within the given DSO, so we get a link-time error if the symbol
 * is not defined, rather than a run-time error.
 *
 * It's also getting less clear what the intended use of each symbol
 * is... normally 'hidden' means internal, 'protected' means exported.
 * But we have at least two kinds of client: extenders (libcrunch)
 * and client DSOs (common case). What interface should extenders see?
 *
 * If we were to define some macros, what would we define?
 * INTERNAL
 * EXTENDER
 * PUBLIC
 *
 * We could just blanket-delete visibilities on declarations and
 * then check that our DSO don't export any public symbols it shouldn't. */

extern char execfile_name[4096];
extern const char *meta_base;
extern unsigned meta_base_len;
const char *ensure_meta_base(void) __attribute__((visibility("hidden")));

char *realpath_quick(const char *arg);
const char *format_symbolic_address(const void *addr);

#include "pageindex.h"

/* FIXME: 'mappings' should probably be a flexible array member. */
#define MAPPING_SEQUENCE_MAX_LEN 8
struct mapping_sequence
{
	void *begin;
	void *end;
	const char *filename;
	unsigned nused;
#if 0 /* sketch for what we might do if tracking fds for deferred mapping */
	int fd_plus_one_if_part_deferred; /* i.e. zero is still the null value, for the fd -1 */
#endif
	struct mapping_entry mappings[MAPPING_SEQUENCE_MAX_LEN];
};
_Bool __augment_mapping_sequence(struct mapping_sequence *cur, 
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename,
	void *caller);
struct big_allocation *__add_mapping_sequence_bigalloc_with_seq(struct mapping_sequence *seq,
	void (*free_fn)(void*));

extern void *executable_end_addr;
extern struct big_allocation *executable_file_bigalloc;
extern struct big_allocation *executable_data_segment_bigalloc;
extern uintptr_t executable_data_segment_start_addr;
/* Normally, the mapping that contiguously precedes the program break
 * is the executable's mapping. However, in some cases where allocsld
 * is 'the program' from the kernel's p.o.v., the program break is above
 * the dynamic linker but 'the executable' (from our p.o.v.) is the binary
 * loaded by the dynamic linker. So this may or may not alias
 * executable_mapping_bigalloc. */
extern struct big_allocation *brk_mapping_bigalloc;

struct dl_phdr_info; /* for include contexts that lack this */
void mmap_replacement(struct generic_syscall *s, post_handler *post);
void munmap_replacement(struct generic_syscall *s, post_handler *post);
void mremap_replacement(struct generic_syscall *s, post_handler *post);
void __liballocs_systrap_init(void);
void __systrap_brk_hack(void);

int load_types_for_one_object(struct dl_phdr_info *, size_t, void *data);
int load_and_init_allocsites_for_one_object(struct dl_phdr_info *, size_t, void *data);
int link_stackaddr_and_static_allocs_for_one_object(struct dl_phdr_info *, size_t, void *data);
void load_meta_objects_for_early_libs(void);
extern void *(*orig_dlopen)(const char *, int);
extern void *(*orig_memmove)(void *, const void *, unsigned long);
const char *format_symbolic_address(const void *addr);
/* We contain our own private malloc, and we wrap it using the linker 
 * to keep track of whether it's active on the current thread. */
extern _Bool __thread __private_malloc_active;
extern _Bool __thread __private_calloc_active;
extern _Bool __thread __private_free_active;
extern _Bool __thread __private_realloc_active;
extern _Bool __thread __private_memalign_active;
extern _Bool __thread __private_posix_memalign_active;
extern _Bool __thread __private_malloc_usable_size_active;
#define PRIVATE_MALLOC_ALIGN 16
#define LOG_PRIVATE_MALLOC_ALIGN 4

extern struct allocator __private_malloc_allocator;
void *__private_malloc(size_t);
void *__private_realloc(void*, size_t);
void __private_free(void *);

char *__private_strndup(const char *, size_t);

void __private_nommap_malloc_set_metadata(void *ptr, size_t size, const void *allocsite);
struct big_allocation *create_private_nommap_malloc_heap(void);
extern void *__private_nommap_malloc_heap_base;
extern void *__private_nommap_malloc_heap_limit;
extern struct big_allocation *__liballocs_private_nommap_malloc_bigalloc;

void *__private_nommap_malloc(size_t);
void *__private_nommap_calloc(size_t, size_t);
void *__private_nommap_realloc(void*, size_t);
void __private_nommap_free(void *);
extern struct allocator __private_nommap_malloc_allocator;

extern FILE *stream_err;
FILE *get_stream_err(void);
#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= __liballocs_debug_level) { \
      fprintf(get_stream_err(), "%s: " fmt, get_exe_command_basename(), ## __VA_ARGS__ );  \
    } \
  } while (0)

#ifndef NO_TLS
extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
#else
extern void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
#endif
struct addrlist
{
	unsigned count;
	unsigned allocsz;
	void **addrs;
};
struct frame_uniqtype_and_offset
{
	struct uniqtype *u;
	unsigned o;
};

#define META_OBJ_SUFFIX "-meta.so"
#define MAX_EARLY_LIBS 128
extern struct link_map *early_lib_handles[MAX_EARLY_LIBS];

/* avoid dependency on libc headers (in this header only) */
void __assert_fail(const char *assertion, 
	const char *file, unsigned int line, const char *function);
void warnx(const char *fmt, ...);
unsigned long malloc_usable_size (void *ptr);

/* counters */
extern unsigned long __liballocs_aborted_stack;
extern unsigned long __liballocs_aborted_static;
extern unsigned long __liballocs_aborted_unknown_storage;
extern unsigned long __liballocs_hit_heap_case;
extern unsigned long __liballocs_hit_alloca_case;
extern unsigned long __liballocs_hit_stack_case;
extern unsigned long __liballocs_hit_static_case;
extern unsigned long __liballocs_aborted_unindexed_heap;
extern unsigned long __liballocs_aborted_unindexed_alloca;
extern unsigned long __liballocs_aborted_unrecognised_allocsite;

void print_exit_summary(void) __attribute__((visibility("hidden")));

/* We're allowed to malloc, thanks to __private_malloc(), but we 
 * we shouldn't call strdup because libc will do the malloc. */
char *__liballocs_private_strdup(const char *s);
char *__liballocs_private_strndup(const char *s, size_t n);

/* Our handling of mmap is in two phases: before systrapping enabled,
 * and after. */
extern _Bool __liballocs_systrap_is_initialized;
void __liballocs_post_systrap_init(void);

/* If this weak function is defined, it will be called when we've loaded
 * the metadata for one object. */
int __hook_loaded_one_object_meta(struct dl_phdr_info *info, size_t size, void *meta_object_handle) __attribute__((weak));
struct load_and_init_all_metadata_args
{
	struct allocs_file_metadata *in_meta;
	void *out_handle;
};
int load_and_init_all_metadata_for_one_object(struct dl_phdr_info *info, size_t size, void *inout_args);

int find_and_open_meta_libfile(struct allocs_file_metadata *meta) __attribute__((visibility("hidden")));

void __notify_copy(void *dest, const void *src, unsigned long n);
void __notify_free(void *dest);

/* Some boilerplate helpers for use by allocators. */
#define DEFAULT_GET_TYPE \
static struct uniqtype *get_type(void *obj) \
{ \
	struct uniqtype *out; \
	struct liballocs_err *err = get_info(obj, NULL, &out, \
		NULL, NULL, NULL); \
	if (err) return NULL; \
	return out; \
}

#ifndef MIN
#define MIN(a, b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a, b) ((a)>(b)?(a):(b))
#endif

/* HACK used in diagnostics that use __builtin_return_address(), e.g.
 * to avoid misattributing a call to <abort> to the next function in .text...*/
#define CALL_INSTR_LENGTH 5 /* FIXME: sysdep */

extern void *__liballocs_rt_uniqtypes_obj;
extern ElfW(Sym) *__liballocs_rt_uniqtypes_dynsym;
extern ElfW(Word) *__liballocs_rt_uniqtypes_gnu_hash;
extern unsigned char *__liballocs_rt_uniqtypes_dynstr;

void update_rt_uniqtypes_obj(void *handle, void *old_base);
void init_rt_uniqtypes_obj(void);

extern struct uniqtype *pointer_to___uniqtype__void;
extern struct uniqtype *pointer_to___uniqtype__signed_char;
extern struct uniqtype *pointer_to___uniqtype__unsigned_char;
extern struct uniqtype *pointer_to___uniqtype____uninterpreted_byte;
extern struct uniqtype *pointer_to___uniqtype____PTR_signed_char;
extern struct uniqtype *pointer_to___uniqtype____PTR___PTR_signed_char;
extern struct uniqtype *pointer_to___uniqtype__long_unsigned_int;
extern struct uniqtype *pointer_to___uniqtype__long_int;
extern struct uniqtype *pointer_to___uniqtype__Elf64_auxv_t;
extern struct uniqtype *pointer_to___uniqtype____ARR0_signed_char;
extern struct uniqtype *pointer_to___uniqtype__intptr_t;

void workaround_glibc_bugs(void) __attribute__((visibility("hidden")));

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
