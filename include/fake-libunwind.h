#ifndef PMIRROR_FAKE_LIBUNWIND_H_
#define PMIRROR_FAKE_LIBUNWIND_H_

#include <stdlib.h> /* for size_t */

#if !defined(__i386__) && !defined(__x86__) && !defined(__x86_64__) && !defined(X86_64)
#error "Unsupported architecture for fake libunwind."
#endif

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#if defined(__i386__) || defined(__x86__)
#define UNW_TARGET_X86
#elif defined(__x86_64__) || defined(X86_64)
#define UNW_TARGET_X86_64
#endif
typedef unsigned long unw_word_t;
typedef void *unw_addr_space_t;
extern long local_addr_space;
extern unw_addr_space_t unw_local_addr_space;
struct accessors
{
	int (*access_mem) (unw_addr_space_t as, unw_word_t addr, unw_word_t *data, int dir, void *priv);
};
typedef struct accessors unw_accessors_t;

extern struct accessors local_accessors;
inline struct accessors *unw_get_accessors(unw_addr_space_t as)
{
	return &local_accessors;
} 

#if defined(__cplusplus) || defined(c_plusplus)
enum unw_error_t
#else
typedef enum
#endif
{
	UNW_ESUCCESS = 0,
	UNW_EUNSPEC,
	UNW_ENOMEM,
	UNW_EBADREG,
	UNW_EREADONLYREG,
	UNW_ESTOPUNWIND,
	UNW_EINVALIDIP,
	UNW_EBADFRAME,
	UNW_EINVAL,
	UNW_EBADVERSION,
	UNW_ENOINFO
#if defined(__cplusplus) || defined(c_plusplus)
};
#else 
} unw_error_t;
#endif

/* core register numbers from libunwind-x86.h */
#if defined(__cplusplus) || defined(c_plusplus)
enum x86_regnum_t
#else
typedef enum
#endif
{
	UNW_X86_EAX,
	UNW_X86_EDX,
	UNW_X86_ECX,
	UNW_X86_EBX,
	UNW_X86_ESI,
	UNW_X86_EDI,
	UNW_X86_EBP,
	UNW_X86_ESP,
	UNW_X86_EIP,
	UNW_X86_EFLAGS,
	UNW_X86_TRAPNO,
#if defined(__cplusplus) || defined(c_plusplus)
};
#else
} x86_regnum_t;
#endif
/* core register numbers from libunwind-x86_64.h */
#if defined(__cplusplus) || defined(c_plusplus)
enum x86_64_regnum_t
#else
typedef enum
#endif
{
    UNW_X86_64_RAX,
    UNW_X86_64_RDX,
    UNW_X86_64_RCX,
    UNW_X86_64_RBX,
    UNW_X86_64_RSI,
    UNW_X86_64_RDI,
    UNW_X86_64_RBP,
    UNW_X86_64_RSP,
    UNW_X86_64_R8,
    UNW_X86_64_R9,
    UNW_X86_64_R10,
    UNW_X86_64_R11,
    UNW_X86_64_R12,
    UNW_X86_64_R13,
    UNW_X86_64_R14,
    UNW_X86_64_R15,
    UNW_X86_64_RIP
#if defined(__cplusplus) || defined(c_plusplus)
};
#else
} x86_64_regnum_t;
#endif

#if defined(__i386__) || defined(__x86__)
#define UNW_REG_IP UNW_X86_EIP
#define UNW_REG_SP UNW_X86_ESP
#define UNW_REG_BP UNW_X86_EBP
#define UNW_TDEP_BP UNW_X86_EBP
#elif defined(__x86_64__) || defined(X86_64)
#define UNW_REG_IP UNW_X86_64_RIP
#define UNW_REG_SP UNW_X86_64_RSP
#define UNW_REG_BP UNW_X86_64_RBP
#define UNW_TDEP_BP UNW_X86_64_RBP
#endif

#if defined(__cplusplus) || defined(c_plusplus)
struct unw_cursor_t
#else
typedef struct 
#endif
{
	unw_word_t frame_sp;
	unw_word_t frame_bp;
	unw_word_t frame_ip;
#if defined(__cplusplus) || defined(c_plusplus)
};
#else
} unw_cursor_t;
#endif
typedef unw_cursor_t unw_context_t;


/* These are defined in fake-unwind.c. We make them hidden to allow them to be 
 * inlined, and also to avoid their replacing the non-fake libunwind in others
 * parts of the program. */
int __attribute__((visibility("hidden"))) unw_get_reg(unw_cursor_t *cursor, int reg, unw_word_t *dest);
int __attribute__((visibility("hidden"))) unw_init_local(unw_cursor_t *cursor, unw_context_t *context);
int __attribute__((visibility("hidden"))) unw_get_proc_name(unw_cursor_t *p_cursor, char *buf, size_t n, unw_word_t *offp);
int __attribute__((visibility("hidden"))) unw_getcontext(unw_context_t *ucp);
int __attribute__((visibility("hidden"))) unw_step(unw_cursor_t *cp);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
