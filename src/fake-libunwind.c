#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include "fake-libunwind.h"

long local_addr_space __attribute__((visibility("hidden")));
unw_addr_space_t unw_local_addr_space __asm__("__liballocs_unw_local_addr_space") __attribute__((visibility("protected")))
 = &local_addr_space;
static int access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *data,int dir, void *priv)
{
	if (dir == 0) /* 0 means read */
		 *(void**)data = *(void **)addr;
	else if (dir == 1) /* 1 means write */
		*(void **)addr = *(void**)data;
	else return 1;
	return 0;
}
struct accessors local_accessors = { &access_mem };

int unw_get_reg(unw_cursor_t *cursor, int reg, unw_word_t *dest) __attribute__((visibility("protected")));
int unw_get_reg(unw_cursor_t *cursor, int reg, unw_word_t *dest)
{
	switch (reg)
	{
		case UNW_REG_SP: *(void**)dest = (void*) cursor->frame_sp; return 0;
		case UNW_TDEP_BP: 
			if (cursor->frame_bp)
			{
				*(void**)dest = (void*) cursor->frame_bp; return 0;
			} else return -EINVAL;
		case UNW_REG_IP: *(void**)dest = (void*) cursor->frame_ip; return 0;
		default: return 1;
	}
}

int unw_init_local(unw_cursor_t *cursor, unw_context_t *context) __attribute__((visibility("protected")));
int unw_init_local(unw_cursor_t *cursor, unw_context_t *context)
{
	*cursor = *context;
	return 0;
}
// sanity-check bp: it should be higher (or equal), but not loads higher
#define SANE_BP_OR_NULL(bp, sp) \
	(((char*) (bp) >= (char*) (sp) && ((char*) (bp) - (char*) (sp)) < 0x10000)  \
		? (unw_word_t) (bp) \
		: 0)

int unw_getcontext(unw_context_t *ucp) __attribute__((noinline,visibility("protected")));
int unw_getcontext(unw_context_t *ucp)
{
	/* The initial state of the cursor should be such that 
	 * if the caller does 
	 * 
	 * unw_getcontext(...)
	 * then
	 * unw_get_reg(UNW_REG_SP )
	 * 
	 * they get their own stack pointer. */
	unw_word_t caller_sp_minus_two_words = (unw_word_t) __builtin_frame_address(0);
	unw_word_t caller_bp, caller_sp;
	unw_word_t current_return_addr;

	assert(caller_sp_minus_two_words != 0);
	current_return_addr = (unw_word_t)
		/*__builtin_extract_return_address( */
			__builtin_return_address(0/*)*/
		);
	/* We get the old break pointer by dereferencing the addr found at 0(%rbp) */
	caller_bp = (unw_word_t) *((void**)caller_sp_minus_two_words);
	assert(caller_bp != 0);
	/* We get the caller stack pointer by taking the addr, and adjusting for
	 * the arguments & return addr to this function (two words). */
	caller_sp = (unw_word_t) (((void**)caller_sp_minus_two_words) + 2);
	*ucp = (unw_context_t){ 
		/* context sp = */ caller_sp, 
		/* context bp = */ SANE_BP_OR_NULL(caller_bp, caller_sp), 
		/* context ip = */ current_return_addr
	};
	return 0;
}
#if defined(__i386__) || defined(__x86__)
#ifndef BEGINNING_OF_STACK
#define BEGINNING_OF_STACK 0xc0000000ul
#endif
#elif defined(__x86_64__) || defined(X86_64)
#ifndef BEGINNING_OF_STACK
#define BEGINNING_OF_STACK 0x800000000000ul
#endif
#endif

int unw_step(unw_cursor_t *cp) __attribute__((visibility("protected")));
int unw_step(unw_cursor_t *cp)
{
	/* Return >0 if we have stepped to a valid frame, or 0 if we were already
	 * at the end of the chain, or <0 on error. */
	
	unw_context_t ctxt = *cp;
	// can't step if we don't have a bp
	if (ctxt.frame_bp == 0) return 0;
	
	// the next-higher ip is the return addr of the frame, i.e. 4(%eip)
	void *return_addr = *(((void**)ctxt.frame_bp) + 1);
	void *sp = (((void**)ctxt.frame_bp) + 2);
	void *candidate_bp = *((void**)ctxt.frame_bp);
	void *sane_bp_or_null = (void*) SANE_BP_OR_NULL(candidate_bp, sp);

#if 0
	/* It would be useful to be able to walk the stack through gdb's
	 * "called from gdb" frames. We can recognise gdb frames by
	 * (1) the new rbp is sane, but
	 * (2) the return address is a short distance above it on the stack, and
	 * (3) the *next* rbp equals that return address.*/
	if (unlikely(sane_bp_or_null &&
			(intptr_t) return_addr - (intptr_t) sane_bp_or_null < 0x20 &&
			*((void**) sane_bp_or_null) == (void*) return_addr)
	{
		/* How do we unwind past a gdb frame?
		 * gdb says that
		 * (gdb) up
		   #1  <function called from gdb>
		   (gdb) print $rsp
		   $79 = (void *) 0x7fffffff82d0       this is one word higher than the callee's saved rbp slot 0x7fffffff82c8
		   (gdb) print $rbp
		   $80 = (void *) 0x7fffffff82c8       this is the address of the saved rbp slot
		
		 * i.e. rsp and rbp are inverted! rsp is higher!
		 * Where is the pre-call frame's rsp stored?
		 
		 * 0x7fffffff8300: 0x7fffffff8350  0x7ffff6bddb88 <__fetch_bounds_ool+360>
		                       ^-- it's here      ^-- this is not related to any current frame
		 * because although $rsp is showing as
		                   0x7fffffff8360   in the pre-call frame,
		   by the time the call has happened we've pushed two words (sp and ip).
		 * So how can I infer the address 0x7fffffff8300
		 * from the previous context? Not sure, but
		   (gdb) x /20ga $rbp
		   0x7fffffff82c0: 0x7fffffff82c8  0x7fffffff82df
		   0x7fffffff82d0: 0x41    0xcc00000000000001
		   0x7fffffff82e0: 0x1032488       0x0
		   0x7fffffff82f0: 0x20    0x7
		   0x7fffffff8300: 0x7fffffff8350  0x7ffff6bddb88 <__fetch_bounds_ool+360>
		   0x7fffffff8310: 0xdf7c80 <__uniqtype__owl_move_data>    0x7fffffffc6b0
		   0x7fffffff8320: 0x700000e6d800  0xffffffffffffff08
		   0x7fffffff8330: 0xc68e00 <owl_vital_apat+1472>  0x0
		   0x7fffffff8340: 0x7fffffffc6b0  0xc68840 <owl_vital_apat>
		   0x7fffffff8350: 0x7fffffff8400  0x786e7a <owl_shapes_callback+106>

		 * ... perhaps 0x41 is an offset that will help us get there?
		 * If I add it to 0x7fffffff82df  I get 0x7fffffff8320
		 * but that looks to be pointing into the middle of user code data.
		 * GIVE UP for now; it's a private gdb detail anyhow.

		 * rsp is one word higher than the saved rbp slot
		 * rbp some distance higher */
	}
#endif
	unw_context_t new_ctxt = (unw_context_t) { 
		/* context sp = */ (unw_word_t) sp,
		/* context bp = */ (unw_word_t) sane_bp_or_null,
		/* context ip = */ (unw_word_t) return_addr
	};
	
	// sanity check the results -- should move down in memory, but (HACK) not more than 256MB
	if (new_ctxt.frame_sp > (uintptr_t) sp || new_ctxt.frame_sp <= ((uintptr_t) sp - 0x10000000ul))
	{
		// looks dodgy -- say we failed
		return -1;
	}
	// otherwise return the number of bytes we stepped up
	else
	{
		*cp = new_ctxt;
		return new_ctxt.frame_sp - ctxt.frame_sp;
	}
}
