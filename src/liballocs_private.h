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
#include "heap_index.h" /* includes memtable */
#include "systrap.h"

#include "liballocs.h"

#ifndef likely
#define likely(cond) \
  __builtin_expect( (cond), 1 )
#endif
#ifndef unlikely
#define unlikely(cond) \
  __builtin_expect( (cond), 0 )
#endif

char execfile_name[4096] __attribute__((visibility("hidden")));
extern const char *meta_base __attribute__((visibility("hidden")));
extern unsigned meta_base_len __attribute__((visibility("hidden")));

char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));

#include "pageindex.h"

/* FIXME: this should probably be a flexible array member, to
 * allow for DSOs that have tons of segments.*/
#define MAPPING_SEQUENCE_MAX_LEN 8
struct mapping_sequence
{
	void *begin;
	void *end;
	const char *filename;
	unsigned nused;
	struct mapping_entry mappings[MAPPING_SEQUENCE_MAX_LEN];
};
_Bool __augment_mapping_sequence(struct mapping_sequence *cur, 
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename,
	void *caller) __attribute__((visibility("hidden")));

extern struct big_allocation *executable_mapping_bigalloc __attribute__((visibility("hidden")));
extern struct big_allocation *executable_file_bigalloc __attribute__((visibility("hidden")));
extern struct big_allocation *executable_data_segment_bigalloc __attribute__((visibility("hidden")));
extern uintptr_t executable_data_segment_start_addr __attribute__((visibility("hidden")));

void mmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void munmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mremap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void __liballocs_systrap_init(void);
void __systrap_brk_hack(void);
int load_types_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
int load_and_init_allocsites_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
int link_stackaddr_and_static_allocs_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
void load_meta_objects_for_early_libs(void) __attribute__((visibility("hidden")));
void *(*orig_dlopen)(const char *, int) __attribute__((visibility("hidden")));
void *(*orig_memmove)(void *, const void *, unsigned long) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));
/* We contain our own private malloc, and we wrap it using the linker 
 * to keep track of whether it's active on the current thread. */
extern _Bool __thread __private_malloc_active __attribute__((visibility("hidden")));
extern _Bool __thread __private_calloc_active __attribute__((visibility("hidden")));
extern _Bool __thread __private_free_active __attribute__((visibility("hidden")));
extern _Bool __thread __private_realloc_active __attribute__((visibility("hidden")));
extern _Bool __thread __private_memalign_active __attribute__((visibility("hidden")));
extern _Bool __thread __private_posix_memalign_active __attribute__((visibility("hidden")));
extern _Bool __thread __private_malloc_usable_size_active __attribute__((visibility("hidden")));
void *__private_malloc(size_t);
void __private_free(void *);

extern FILE *stream_err;
__attribute__((visibility("hidden"))) FILE *get_stream_err(void);
#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= __liballocs_debug_level) { \
      fprintf(get_stream_err(), "%s: " fmt, get_exe_basename(), ## __VA_ARGS__ );  \
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
struct liballocs_err
{
	const char *message;
};
struct frame_uniqtype_and_offset
{
	struct uniqtype *u;
	unsigned o;
};

#define META_OBJ_SUFFIX "-meta.so"
_Bool is_meta_object_for_lib(struct link_map *maybe_types, struct link_map *l)
			__attribute__((visibility("hidden")));

#define MAX_EARLY_LIBS 128
extern struct link_map *early_lib_handles[MAX_EARLY_LIBS] __attribute((visibility("hidden")));

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
extern unsigned long __liballocs_hit_stack_case;
extern unsigned long __liballocs_hit_static_case;
extern unsigned long __liballocs_aborted_unindexed_heap;
extern unsigned long __liballocs_aborted_unrecognised_allocsite;

/* We're allowed to malloc, thanks to __private_malloc(), but we 
 * we shouldn't call strdup because libc will do the malloc. */
char *__liballocs_private_strdup(const char *s) __attribute__((visibility("hidden")));
char *__liballocs_private_strndup(const char *s, size_t n) __attribute__((visibility("hidden")));

/* Our handling of mmap is in two phases: before systrapping enabled,
 * and after. */
extern _Bool __liballocs_systrap_is_initialized;
void __liballocs_post_systrap_init(void) __attribute__((visibility("hidden")));

void __generic_malloc_allocator_init(void) __attribute__((visibility("hidden")));

/* If this weak function is defined, it will be called when we've loaded
 * the metadata for one object. */
int __hook_loaded_one_object_meta(struct dl_phdr_info *info, size_t size, void *meta_object_handle) __attribute__((weak));
int load_and_init_all_metadata_for_one_object(struct dl_phdr_info *info, size_t size, void *out_meta_handle)
	__attribute__((visibility("hidden")));

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

extern struct uniqtype *pointer_to___uniqtype__void __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype__signed_char __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype__unsigned_char __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype____uninterpreted_byte __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype____PTR_signed_char __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype____PTR___PTR_signed_char __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype__long_unsigned_int __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype__long_int __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype__Elf64_auxv_t __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype____ARR0_signed_char __attribute__((visibility("hidden")));
extern struct uniqtype *pointer_to___uniqtype__intptr_t __attribute__((visibility("hidden")));
#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
