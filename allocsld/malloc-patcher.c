#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "asmutil.h"

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
 * 3. Set up a trampoline and clobber the entry point to jump to it. The approach
 * is rather like 'Detours' by Hunt & Brubacher (Proc. 3rd USENIX Windows NT
 * Symposium, 1999).
 */
// from libsystrap
unsigned long instr_len(unsigned const char *ins, unsigned const char *end);

static void *prologue_get_first_non_displaced(const void *func, const void *func_limit)
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
		if (inslen == 0) /* error */ return NULL;
		if (!CHECK_DISPLACEABLE(insbyte)) return NULL;

		nbytes_decoded += inslen;
		insbyte += inslen;
	}
	return insbyte; // first non-displaced
}
/* Next for the Detours-style stuff. The trampoline is a "monopoline" because
 * it's specialised to a single detoured entry point. We therefore don't need to
 * save the entry point address anywhere in code... our generated trampoline code
 * embodies it in the displaced-instructinos-then-jump sequence.
 *
 * It's impossible to generate the monopoline as a compiled chunk of code, because
 * we only know where it needs to jump back to when we are doing the patching,
 * i.e. at run time. Likewise it needs to know the displaced instructions and
 * those are also only known at run time.
 *
 * Still, this ends suspiciously similar to a link-time-interposed function.
 * Our orig_post_displaced is similar to the dlsym() result.
 * But we are regrettably more malware-like... we are defeating the normal
 * dynamic-linking-induced points-to and called-from relation.
 */

void *write_monopoline_and_detour(void *func, void *func_limit,
	void *detour_func,
	void *detour_func_orig_callee_slot,
	void *trampoline_buf,
	void *trampoline_buf_limit)
{
	/* We jump straight from the target function entry instruction
	 * to the detour function, not via the trampoline.
	 * The trampoline is used only for return: it is specialised to
	 * a particular callee, and its entry point is what we set the
	 * orig callee slot to point to -- it performs the displaced
	 * instructions and then jumps back. It could be used either
	 * for a call or a jump, but a call is easier when coming from
	 * compiler-generated code. */
	void *first_non_displaced = prologue_get_first_non_displaced(func, func_limit);
	unsigned ndisplaced_bytes = (unsigned char *) first_non_displaced - (unsigned char*) func;

	// create the trampoline, beginning with the displaced instructions
	memcpy((char*) trampoline_buf, func, ndisplaced_bytes);
	INSTRS_FROM_ASM(trampoline_exit,
"1:jmp 0 \n\
        RELOC 1b + 1, "R_(X86_64_PC32)", "/* symidx 0: original entry point */" 0, -0x4\n"
	);
	memcpy_and_relocate((char*) trampoline_buf + ndisplaced_bytes,
		trampoline_exit,
		(uintptr_t) func + ndisplaced_bytes);
	*(void**) detour_func_orig_callee_slot = trampoline_buf;

	// finally, plumb in the detour function
	INSTRS_FROM_ASM(jump_to_detour,
"1:jmp 0 \n\
        RELOC 1b + 1, "R_(X86_64_PC32)", "/* symidx 0: detour func addr */" 0, -0x4\n"
	);
	memcpy_and_relocate((void*) func,
		jump_to_detour,
		(uintptr_t) detour_func);
	extern size_t trampoline_exit_size;
	return (char*) trampoline_buf + ndisplaced_bytes + trampoline_exit_size;
}

/* Now we want to use mallochooks to generate our detour functions.
 * From libmallochooks we can get user2hook (narrowing to a minimal
 * malloc API) and hook2event (turning malloc/realloc/free into events).
 * The implementation of event hooks comes from stubgen.h. And
 * in turn those call indexing functions in generic_malloc.h. */

/* This is the malloc that the above malloc entry point gets detoured to,
 * if we are doing a detour. */
void *(*detour_malloc_orig_callee)(size_t);
void *detour_malloc(size_t sz)
{
	/* Don't try to print anything here without adding reentrancy guards.
	 * Or just use write(). */
	static __thread _Bool active = 0;
	_Bool we_set_active = 0;
	sz += 8;
	if (!active) { active = 1; printf("Asked to malloc %ld bytes!\n", (long) sz); we_set_active = 1; }
	void *ret = detour_malloc_orig_callee(sz);
	if (we_set_active) active = 0;
	return ret;
}
