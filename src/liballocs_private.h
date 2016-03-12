#ifndef LIBALLOCS_PRIVATE_H_
#define LIBALLOCS_PRIVATE_H_

#ifndef VIS
#define VIS(v) //__attribute__((visibility( #v )))
#endif

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

#include "heap_index.h" /* includes memtable */
#include "allocsmt.h"
#include "systrap.h"
#include <link.h>
#include <stdint.h>

#include "liballocs.h"

#define likely(cond) \
  __builtin_expect( (cond), 1 )
#define unlikely(cond) \
  __builtin_expect( (cond), 0 )

const char *
dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr)
		__attribute__((visibility("hidden")));
char execfile_name[4096] __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));

#include "pageindex.h"

extern struct big_allocation *executable_data_segment_bigalloc __attribute__((visibility("hidden")));

void mmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void munmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mremap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void __liballocs_systrap_init(void);
int load_types_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
int load_and_init_allocsites_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
int link_stackaddr_and_static_allocs_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
void *(*orig_dlopen)(const char *, int) __attribute__((visibility("hidden")));
int dl_for_one_object_phdrs(void *handle,
	int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
	void *data) __attribute__((visibility("hidden")));
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

extern FILE *stream_err;
#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= __liballocs_debug_level) { \
      fprintf(stream_err, "%s: " fmt, get_exe_basename(), ## __VA_ARGS__ );  \
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

struct frame_uniqtype_and_offset 
vaddr_to_stack_uniqtype(const void *vaddr)
		__attribute__((visibility("hidden")));
struct uniqtype *
static_addr_to_uniqtype(const void *static_addr, void **out_object_start) 
		__attribute__((visibility("hidden")));

#define TYPES_OBJ_SUFFIX "-types.so"
#define ALLOCSITES_OBJ_SUFFIX "-allocsites.so"
_Bool is_meta_object_for_lib(struct link_map *maybe_types, struct link_map *l, const char *meta_suffix)
			__attribute__((visibility("hidden")));

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
char *private_strdup(const char *s);

/* Our handling of mmap is in two phases: before systrapping enabled,
 * and after. */
extern _Bool __liballocs_systrap_is_initialized;

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
