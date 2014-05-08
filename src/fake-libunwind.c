#include <assert.h>
#include "pmirror/fake-libunwind.h"

long local_addr_space;
unw_addr_space_t unw_local_addr_space = &local_addr_space;
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

int unw_get_reg(unw_cursor_t *cursor, int reg, unw_word_t *dest)
{
	switch (reg)
	{
		case UNW_REG_SP: *(void**)dest = (void*) cursor->frame_sp; return 0;
		case UNW_TDEP_BP: *(void**)dest = (void*) cursor->frame_bp; return 0;
		case UNW_REG_IP: *(void**)dest = (void*) cursor->frame_ip; return 0;
		default: return 1;
	}
}
int unw_init_local(unw_cursor_t *cursor, unw_context_t *context)
{
	*cursor = *context;
	return 0;
}

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
	unw_word_t caller_sp_minus_two_words;
	unw_word_t caller_bp, caller_sp;
	unw_word_t current_return_addr;
#if defined(__i386__) || defined(__x86__)
	__asm__ ("movl %%ebp, %0\n" :"=r"(caller_sp_minus_two_words));
#elif defined(__x86_64__) || defined(X86_64)
	/* PROBLEM: sometimes our mov of bp 
	 * happens *before* the current rsp is saved into bp! 
	 * To get around this, we actually move *rsp* and make sure
	 * we are the first instruction after the prologue.
	 * */
	__asm__ ("movq %%rsp, %0\n" :"=r"(caller_sp_minus_two_words));
#else 
#error "Unsupported architecture"
#endif
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
		/* context bp = */ caller_bp, 
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

int unw_step(unw_cursor_t *cp)
{
	/*
       On successful completion, unw_step() returns a positive  value  if  the
       updated  cursor  refers  to  a  valid stack frame, or 0 if the previous
       stack frame was the last frame in the chain.  On  error,  the  negative
       value of one of the error-codes below is returned.
	*/
	
	unw_context_t ctxt = *cp;
	// can't step if we don't have a bp
	if (ctxt.frame_bp == 0) return 0;
	
	// the next-higher ip is the return addr of the frame, i.e. 4(%eip)
	void *return_addr = *(((void**)ctxt.frame_bp) + 1);
	
	unw_context_t new_ctxt = (unw_context_t) { 
		/* context sp = */ (unw_word_t) (((void**)ctxt.frame_bp) + 2),
		/* context bp = */ (unw_word_t) *((void**)ctxt.frame_bp),
		/* context ip = */ (unw_word_t) return_addr
	};
		
	// sanity check the results
	if (new_ctxt.frame_sp >= BEGINNING_OF_STACK
	||  new_ctxt.frame_sp <= (BEGINNING_OF_STACK - 0x100000000))
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
