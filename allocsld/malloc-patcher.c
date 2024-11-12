#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Simple binary patcher for allocation function prologues.
 * We do roughly the following:
 *
 * 1. Decode the first N bytes of the function, where
 * N is the number of bytes in a jump instruction [sequence] that can get us
 * into a per-function trampoline. On x86 and x86-64, N is 5. Any instruction
 * that covers any of these bytes is a "displaced instruction".
 *
 * 2. Check that the displaced instructions are all position-independent, i.e.
 * they run correctly even if sited at a different address. If they are not,
 * we fail because such cases are currently too hard for us.
 *
 * 3. In our trampoline, we
 *
 *    - tweak the argument register
 *
 *    - hook the return path by overwriting the return address, having
 *      stored the real return address in a thread-local buffer. HMM. But
 *      do we have working thread-locals yet? No, I don't think so. Is there
 *      some clever way we can communicate save the return address? Maybe in the red zone?
 *      No because we cede ownership of the red zone to the real malloc code, and
 *      it will return directly into our hook code.
 *      Maybe working thread-locals are not too much to ask. Let's try it.
 *
 *    - execute the displaced instructions
 *
 *    - jump to the first non-displaced instruction. 
 */

// TODO: rather like generic_syscall in libsystrap,
// we want something like a "generic_abicall"... our "add    $0x8,%rdi" is
// specific to instrumenting malloc, but really we should call out
// to some general-purpose C code that lets us interfere with the
// call however we like and then segue back into its code. We can
// still use a per-entry-point trampoline to do this, and indeed
// I think we have to. But probably we want templates that are
// per function signature at the ABI level. Each template can
// push/pop only the relevant registers from the stack, e.g.
// only %rdi for a one-pointer-argument call, and so on. The trampoline
// then pops them back into place. It's a lot like a signal frame but
// doing it in user space and tailored to the argument signature being
// instrumented.
//
// We could use a lot of the machinery that is used to define mcontext_t,
// but we'd want to change the order of registers s.t. we have
#if 0
struct generic_abi_call_entry
{
	const void *real_callee;          // we always push this
	const void **active_return_address_slot;
	                                  // we always push the *address* of the return address...
	                                  // Do we always hook the return address when creating
	                                  // the trampoline? Note that we CAN't skip the thread-
	                                  // -local thing, because this struct only exists at the
	                                  // entry end of the function. I think it is probably
	                                  // optional to do the return-address hooking, i.e. only when
	                                  // requested should the trampoline do the hooking.
	const void **maybe_saved_return_address_slot;
	                                  // ^ this is non-null only if the trampoline did the
	                                  // hooking and stored the return address.
	                                  // What if we want multiple hooked functions active
	                                  // on the stack at once? We should be able to get away
	                                  // with just a single TLS variable, I think, but not sure why.
	
	unsigned char ngregs;             // the number that we pushed
	unsigned char nfpregs;
	__greg_t reg1; // rdi
	__greg_t reg2; // rsi
	__greg_t reg3; // rdx
	__greg_t reg4; // rcx
	__greg_t reg5; // r8
	__greg_t reg6; // r9
	// fp regs may follow....

	// on-stack args live in a contiguous block that should be easy to reach
	// starting from the return address slot, I guess?
}
#endif
// But how do we build this on the stack? We have to push in reverse order!
// i.e. if we want to materialise r9, we push r9 first, then r8, then...
// Then we lea the on-stack address of the overall structure and pass that
// as the argument to handle_generic_abi_call.
//
// How does this compare to what DynInst does?

static char trampoline_template_pre[] = {
/*   0:  */  0x48, 0x83, 0xc7, 0x08,                         // add    $0x8,%rdi  # munge args
/*   4:  */  0x57,                                           // push   %rdi       # 
/*   5:  */  0x50,                                           // push   %rax
/*   6:  */  0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,   // mov    %fs:0x0,%rax
/*   f:  */  0x48, 0x8d, 0x80, 0x00, 0x00, 0x00, 0x00,               // lea    0x0(%rax),%rax
//                        12: R_X86_64_TPOFF32     real_return_address
/*  16:  */  0x48, 0x8b, 0x7c, 0x24, 0x10,                   // mov    0x10(%rsp),%rdi
/*  1b:  */  0x48, 0x89, 0x38,                               // mov    %rdi,(%rax)
/*  1e:  */  0x58,                                           // pop    %rax
/*  1f:  */  0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, // lea    0x0(%rip),%rdi
//                        22: R_X86_64_32S        generic_return_hook
/*  26:  */  0x48, 0x89, 0x7c, 0x24, 0x10,                   // mov    %rdi,0x10(%rsp)
/*  2b:  */  0x5f                                            // pop    %rdi
/*  2c:  */  // displaced instructions go here, then the jump back into the original function
};

static char trampoline_template_post[] = {
/*  2c+NDISPLACED:  */  0xe9, 0x00, 0x00, 0x00, 0x00                    // jmp    2e <mytramp+0x2e>
//                        2c+NDISPLACED: R_X86_64_PLT32      first_non_displaced-0x4
}; // total: 0x30+NDISPLACED bytes

void generic_return_hook(void) __attribute__((visibility("hidden"))); // same-object binding

// from libsystrap
unsigned long instr_len(unsigned const char *ins, unsigned const char *end);

__asm__ (
	".pushsection .data\n"
	".globl real_return_address_tpoff\n"
	"real_return_address_tpoff:\n"
	".long real_return_address@tpoff\n"
	".popsection"
);
extern signed real_return_address_tpoff;
void instrument_malloc_entry(const void *func, const void *func_limit,
	void *trampoline_buf, void *trampoline_buf_limit)
{
#define NBYTES_TO_CLOBBER  5 /* FIXME: sysdep */
#define CHECK_DISPLACEABLE(ptr) 1 /* FIXME: actually do this */
	/* + REMEMBER: displaceable instructions must not only be position-independent
	 * but also have no incoming branches! */
	unsigned nbytes_decoded = 0;
	unsigned char *insbyte = (unsigned char *) func;
	while (nbytes_decoded < NBYTES_TO_CLOBBER)
	{
		// decode one, check we can 
		unsigned inslen = instr_len(insbyte, func_limit);
		if (inslen == 0) /* error */ abort();
		if (!CHECK_DISPLACEABLE(insbyte)) abort();

		nbytes_decoded += inslen;
		insbyte += inslen;
	}
	void *first_non_displaced = insbyte;
	
	memcpy(trampoline_buf, trampoline_template_pre, sizeof trampoline_template_pre);
#define APPLY_32BIT_FIXUP_NATIVE_ENDIANNESS(buf, offset, value) \
    do { \
        int32_t val = (value); \
        memcpy((char*) (buf) + (offset), &val, 4); \
    } while (0)
#define APPLY_32BIT_FIXUP_PCREL(buf, offset, addr) \
    APPLY_32BIT_FIXUP_NATIVE_ENDIANNESS(buf, offset, (addr) - ((uintptr_t) (buf) + offset));

	APPLY_32BIT_FIXUP_NATIVE_ENDIANNESS(trampoline_buf, 0x12, real_return_address_tpoff);
	APPLY_32BIT_FIXUP_PCREL(trampoline_buf, 0x22, (int64_t) &generic_return_hook - 0x4);
	// copy displaced instructions
	unsigned ndisplaced_bytes = insbyte - (unsigned char*) func;
	memcpy(trampoline_buf + 0x2c, func, ndisplaced_bytes);
	// copy post instructions
	memcpy(trampoline_buf + 0x2c + ndisplaced_bytes, trampoline_template_post, sizeof trampoline_template_post);
	// fix up post instructions
	APPLY_32BIT_FIXUP_PCREL(trampoline_buf, 0x2c + ndisplaced_bytes + 1, (uintptr_t) first_non_displaced - 0x4);
	// now we have a trampoline... do the clobber
	char jump_insn[] = { 0xe9, 0x00, 0x00, 0x00, 0x00 };
	memcpy((void*) func, jump_insn, 4);
	// relocate in place
	APPLY_32BIT_FIXUP_PCREL((void*) func, 1, (uintptr_t) trampoline_buf - 0x4); 
}

#ifdef SELF_TEST

#include <stdio.h>
#include <sys/mman.h>
#include <err.h>
#include <errno.h>
extern int _end;

void *__libc_malloc(size_t);

void *malloc(size_t sz)
{
	static __thread _Bool active = 0;
	_Bool we_set_active = 0;
	if (!active) { active = 1; printf("Asked to malloc %ld bytes!\n", (long) sz); we_set_active = 1; }
	void *ret = __libc_malloc(sz);
	if (we_set_active) active = 0;
	return ret;
}

extern __thread size_t real_return_address;

int main(void)
{
	printf("in this thread, real_return_address is stored at %p\n", &real_return_address);
	void *dummy = malloc(42);

	int ret = mprotect((void*) (((uintptr_t) malloc) & ~0xfff), 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
	if (ret != 0) err(errno, "doing mprotect");
	
	// get some RWX memory that is not too far from our own memory
	// FIXME: use libdlbind? doesn't exactly work in our use case but
	// maybe there's a subset of its functionality that makes sense, or
	// maybe its interface / utility logic helps here.
	void *rwx_buf = mmap( (void*) (((uintptr_t) &_end + 1048576) & ~0xfff), 4096,
			PROT_READ|PROT_WRITE|PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0); 
	if (rwx_buf == MAP_FAILED) err(errno, "doing mmap");
	
	// do the instrumentation
	instrument_malloc_entry(malloc, (char*) malloc + 4096,
		rwx_buf, rwx_buf + 4096);

	dummy = malloc(42);
	return 0;
}
#endif
