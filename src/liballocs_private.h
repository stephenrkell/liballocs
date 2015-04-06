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
#include <link.h>
#include <stdint.h>

#include "liballocs.h"

#define ROUND_DOWN_TO_PAGE_SIZE(n) \
	(assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE), ((n)>>LOG_PAGE_SIZE)<<LOG_PAGE_SIZE)
#define ROUND_UP_TO_PAGE_SIZE(n) \
	(assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE), (n) % PAGE_SIZE == 0 ? (n) : ((((n) >> LOG_PAGE_SIZE) + 1) << LOG_PAGE_SIZE))
// mappings over 4GB in size are assumed to be memtables and are ignored
#define BIGGEST_MAPPING (1ull<<32)

#define MAPPING_BASE_FROM_PHDR_VADDR(base_addr, vaddr) \
   (ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr)))
#define MAPPING_END_FROM_PHDR_VADDR(base_addr, vaddr, memsz) \
	(ROUND_UP_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr) + (memsz)))

/* We use these for PT_GNU_RELRO mappings. */
#define MAPPING_NEXT_PAGE_START_FROM_PHDR_BEGIN_VADDR(base_addr, vaddr) \
   (ROUND_UP_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr)))
#define MAPPING_PRECEDING_PAGE_START_FROM_PHDR_END_VADDR(base_addr, vaddr, memsz) \
	(ROUND_DOWN_TO_PAGE_SIZE((uintptr_t) (base_addr) + (uintptr_t) (vaddr) + (memsz)))

/* The biggest virtual address that we might find in an executable image. */
#define BIGGEST_SANE_EXECUTABLE_VADDR  (1ull<<31)

#define PAGENUM(p) (((uintptr_t) (p)) >> LOG_PAGE_SIZE)
#define ADDR_OF_PAGENUM(p) ((const void *) ((p) << LOG_PAGE_SIZE))

const char *
dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr)
		__attribute__((visibility("hidden")));
char execfile_name[4096] __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));

typedef uint16_t mapping_num_t;
mapping_num_t *l0index __attribute__((visibility("hidden")));
extern _Bool initialized_maps;

/* FIXME: rename to __liballocs_ */
_Bool mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2);

void __liballocs_init_l0(void) VIS(protected);
struct mapping_info *mapping_add(void *base, size_t s, mapping_flags_t f, const void *arg) __attribute__((visibility("hidden")));
void mapping_add_sloppy(void *base, size_t s, mapping_flags_t f, const void *arg) __attribute__((visibility("hidden")));
struct mapping_info *mapping_add_full(void *base, size_t s, struct mapping_info *arg) __attribute__((visibility("hidden")));
void mapping_del(void *base, size_t s) __attribute__((visibility("hidden")));
void mapping_del_node(struct mapping_info *n) __attribute__((visibility("hidden")));
int mapping_lookup_exact(struct mapping_info *n, void *begin, void *end) __attribute__((visibility("hidden")));
size_t
mapping_get_overlapping(struct mapping_info **out_begin, 
		size_t out_size, void *begin, void *end) __attribute__((visibility("hidden")));
// these ones are public, so use protected visibility
void __liballocs_add_missing_maps(void) VIS(protected);
enum object_memory_kind __liballocs_get_memory_kind(const void *obj) VIS(protected);;
void __liballocs_print_mappings_to_stream_err(void) VIS(protected);
_Bool mapping_info_has_data_ptr_equal_to(mapping_flags_t f, const struct mapping_info *info, const void *data_ptr) __attribute((visibility("hidden")));

int load_types_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
int load_and_init_allocsites_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
int link_stackaddr_and_static_allocs_for_one_object(struct dl_phdr_info *, size_t, void *data) __attribute__((visibility("hidden")));
void *(*orig_dlopen)(const char *, int) __attribute__((visibility("hidden")));
int dl_for_one_object_phdrs(void *handle,
	int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
	void *data) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));

struct mapping_info *
mapping_lookup(void *base) __attribute__((visibility("hidden")));
struct mapping_info *
mapping_bounds(const void *ptr, const void **begin, const void **end) __attribute__((visibility("hidden")));
int __liballocs_add_all_mappings_cb(struct dl_phdr_info *info, size_t size, void *data) __attribute__((visibility("hidden")));

extern char exe_fullname[4096];
extern char exe_basename[4096];
extern FILE *stream_err;
#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= __liballocs_debug_level) { \
      fprintf(stream_err, "%s: " fmt, exe_basename, ## __VA_ARGS__ );  \
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

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
