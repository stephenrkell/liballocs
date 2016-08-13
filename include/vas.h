#ifndef LIBALLOCS_VAS_H_
#define LIBALLOCS_VAS_H_

#define MINIMUM_USER_ADDRESS  ((char*)0x400000) /* FIXME: less {x86-64,GNU/Linux}-specific please */
#define MAXIMUM_USER_ADDRESS  ((char*)(0x800000000000ul-1)) /* FIXME: less {x86-64,GNU/Linux}-specific please */

#define WORD_BITSIZE ((sizeof (void*))<<3)
#if defined(__x86_64__) || defined(x86_64)
#define ADDR_BITSIZE 48
#else
#define ADDR_BITSIZE WORD_BITSIZE
#endif

/* The biggest virtual address that we might find in an executable image. */
// #define BIGGEST_SANE_EXECUTABLE_VADDR  (1ull<<31)
#define BIGGEST_SANE_USER_ALLOC ((1ull<<32)-1ull)

#define MAXPTR(a, b) \
	((((char*)(a)) > ((char*)(b))) ? (a) : (b))

#define MINPTR(a, b) \
	((((char*)(a)) < ((char*)(b))) ? (a) : (b))

#define PAGE_SIZE 4096 /* FIXME: this is sysdep */
#define LOG_PAGE_SIZE 12

#define PAGENUM(p) (((uintptr_t) (p)) >> LOG_PAGE_SIZE)
#define ADDR_OF_PAGENUM(p) ((const void *) ((p) << LOG_PAGE_SIZE))

#endif
