#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "relf.h"
#include "vas.h"
#include "liballocs_private.h"
#include "pageindex.h"

#ifdef USE_REAL_LIBUNWIND
#include <libunwind.h>
#else
#include "fake-libunwind.h"
#endif

/* This is the allocator that knows about ABI-defined *stack frames*,
 * as distinct from the (machine/OS-defined) *stack mappings*. */

static liballocs_err_t get_info(void * obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site);
	
struct allocator __stackframe_allocator = {
	.name = "stackframe",
	.is_cacheable = 0,
	.get_info = get_info
};

static _Bool trying_to_initialize;
static _Bool initialized;

static void *main_bp; // beginning of main's stack frame

struct suballocated_chunk_rec; // FIXME: remove once heap_index has been refactored

void __stackframe_allocator_init(void) __attribute__((constructor(101)));
void __stackframe_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;

		// grab the start of main's stack frame -- we'll use this 
		// when walking the stack
		unw_cursor_t cursor;
		unw_context_t unw_context;
		int ret = unw_getcontext(&unw_context); assert(ret == 0);
		ret = unw_init_local(&cursor, &unw_context); assert(ret == 0);
		char buf[8];
		unw_word_t ip;
		unw_word_t sp;
		unw_word_t bp;
		_Bool have_bp;
		_Bool have_name;
		assert(ret == 0);
		do
		{
			// get bp, sp, ip and proc_name
			ret = unw_get_proc_name(&cursor, buf, sizeof buf, NULL); have_name = (ret == 0 || ret == -UNW_ENOMEM);
			buf[sizeof buf - 1] = '\0';
			// if (have_name) fprintf(stream_err, "Saw frame %s\n", buf);

			ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(ret == 0);
			ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(ret == 0);
			ret = unw_get_reg(&cursor, UNW_TDEP_BP, &bp); have_bp = (ret == 0);
		} while ((!have_name || 0 != strcmp(buf, "main")) && 
			(ret = unw_step(&cursor)) > 0);

		// have we found main?
		if (have_name && 0 == strcmp(buf, "main"))
		{
			// did we get its bp?
			if (!have_bp)
			{
				// try stepping once more
				ret = unw_step(&cursor);
				if (ret == 0)
				{
					ret = unw_get_reg(&cursor, UNW_REG_SP, &bp);
				}

				if (ret == 0) have_bp = 1;
			}

			if (have_bp)
			{
				main_bp = (void*) (intptr_t) bp;
			}
			else
			{
				// underapproximate bp as the sp
				main_bp = (void*) (intptr_t) sp;
			}
		}

		if (main_bp == 0) 
		{
			// underapproximate bp as our current sp!
			debug_printf(1, "Warning: using egregious approximation for bp of main().\n");
			unw_word_t our_sp;
		#ifdef UNW_TARGET_X86
			__asm__ ("movl %%esp, %0\n" :"=r"(our_sp));
		#else // assume X86_64 for now
			__asm__("movq %%rsp, %0\n" : "=r"(our_sp));
		#endif
			main_bp = (void*) (intptr_t) our_sp;
		}
		assert(main_bp != 0);
		
		initialized = 1;
		trying_to_initialize = 0;
		
		/* NOTE: we don't add any mappings initially; we rely on the mmap allocator 
		 * to tell us about them. Similarly for new mappings, we rely on the 
		 * mmap trap logic to identify them, by their MAP_GROWSDOWN flag. */
	}
}

struct big_allocation *__stackframe_allocator_find_or_create_bigalloc(
		unsigned long *frame_counter, const void *caller, const void *frame_sp_at_caller, 
		const void *frame_bp_at_caller)
{
	/* Do we have a big allocation spanning the frame counter address? */
	void *existing_frame_start;
	struct big_allocation *found = __lookup_bigalloc(frame_counter, 
		&__stackframe_allocator, &existing_frame_start);
	if (found) return found;

	void *begin = (void*) frame_sp_at_caller;
	void *end = (void*) frame_bp_at_caller;
	struct big_allocation *found_begin = __lookup_deepest_bigalloc(begin);
	/* Our deepest existing bigalloc should be a stack bigalloc. */
	assert(!found_begin || found_begin->allocated_by == &__stack_allocator);
	struct big_allocation *found_end = __lookup_deepest_bigalloc((char*) end - 1);
	assert(found_end);
	assert(found_end->allocated_by == &__stack_allocator);
	
	/* None found, so we have to promote the frame into a bigalloc. 
	 * So what are its dimensions? The caller has passed them to us.
	 * 
	 * PROBLEM: when the frame silently resizes itself, the begin/end will
	 * be wrong.
	 * HOPEFUL SOLUTION: for a frame doing alloca(), which is the only
	 * kind we care about, the compiler should not use any space *below* 
	 * the first alloca for anything except alloca space. HMM. There's
	 * no guarantee of that. 
	 * 
	 * FIXME: when the frame counter hits zero, the caller must be sure to delete
	 * this bigalloc!
	 */
	struct big_allocation *b = __liballocs_new_bigalloc(
		begin,
		(char*) end - (char*) begin,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = NULL,
					.free_func = NULL
				}
			}
		},
		NULL, // filled in for us
		&__stackframe_allocator
	);
	__liballocs_sanity_check_bigalloc(b);
	if (!b) abort();
	return b;
}

static liballocs_err_t get_info(void *obj, struct big_allocation *b,
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void** out_site)
{		
	++__liballocs_hit_stack_case;
	liballocs_err_t err;
#define BEGINNING_OF_STACK ((uintptr_t) MAXIMUM_USER_ADDRESS)
	// we want to walk a sequence of vaddrs!
	// how do we know which is the one we want?
	// we can get a uniqtype for each one, including maximum posoff and negoff
	// -- yes, use those
	/* We declare all our variables up front, in the hope that we can rely on
	 * the stack pointer not moving between getcontext and the sanity check.
	 * FIXME: better would be to write this function in C90 and compile with
	 * special flags. */
	unw_cursor_t cursor, saved_cursor, prev_saved_cursor __attribute__((unused));
	unw_word_t higherframe_sp = 0, sp, higherframe_bp = 0, bp = 0, ip = 0, higherframe_ip = 0, callee_ip __attribute__((unused));
	int unw_ret;
	unw_context_t unw_context;

	unw_ret = unw_getcontext(&unw_context);
	unw_init_local(&cursor, /*this->unw_as,*/ &unw_context);

	unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp);
#ifndef NDEBUG
	unw_word_t check_higherframe_sp;
	// sanity check
#ifdef UNW_TARGET_X86
	__asm__ ("movl %%esp, %0\n" :"=r"(check_higherframe_sp));
#else // assume X86_64 for now
	__asm__("movq %%rsp, %0\n" : "=r"(check_higherframe_sp));
#endif
	assert(check_higherframe_sp == higherframe_sp);
#endif
	unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip);

	_Bool at_or_above_main = 0;
	do
	{
		callee_ip = ip;
		prev_saved_cursor = saved_cursor;	// prev_saved_cursor is the cursor into the callee's frame 
											// FIXME: will be garbage if callee_ip == 0
		saved_cursor = cursor; // saved_cursor is the *current* frame's cursor
			// and cursor, later, becomes the *next* (i.e. caller) frame's cursor

		/* First get the ip, sp and symname of the current stack frame. */
		unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
		unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0); // sp = higherframe_sp
		// try to get the bp, but no problem if we don't
		unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &bp); 
		_Bool got_bp = (unw_ret == 0);
		_Bool got_higherframe_bp = 0;
		/* Also do a test about whether we're in main, above which we want to
		 * tolerate unwind failures more gracefully. NOTE: this is just for
		 * debugging; we don't normally pay any attention to this. 
		 */
		at_or_above_main |= 
			(
				(got_bp && bp >= (uintptr_t) __liballocs_main_bp)
			 || (sp >= (uintptr_t) __liballocs_main_bp) // NOTE: this misses the in-main case
			);

		/* Now get the sp of the next higher stack frame, 
		 * i.e. the bp of the current frame. NOTE: we're still
		 * processing the stack frame ending at sp, but we
		 * hoist the unw_step call to here so that we can get
		 * the *bp* of the current frame a.k.a. the caller's bp 
		 * (without demanding that libunwind provides bp, e.g. 
		 * for code compiled with -fomit-frame-pointer). 
		 * This means "cursor" is no longer current -- use 
		 * saved_cursor for the remainder of this iteration!
		 * saved_cursor points to the deeper stack frame. */
		int step_ret = unw_step(&cursor);
		if (step_ret > 0)
		{
			unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp); assert(unw_ret == 0);
			// assert that for non-top-end frames, BP --> saved-SP relation holds
			// FIXME: hard-codes calling convention info
			if (got_bp && !at_or_above_main && higherframe_sp != bp + 2 * sizeof (void*))
			{
				// debug_printf(2, "Saw frame boundary with unusual sp/bp relation (higherframe_sp=%p, bp=%p != higherframe_sp + 2*sizeof(void*))", 
				// 	higherframe_sp, bp);
			}
			unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip); assert(unw_ret == 0);
			// try to get the bp, but no problem if we don't
			unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &higherframe_bp); 
			got_higherframe_bp = (unw_ret == 0) && higherframe_bp != 0;
		}
		/* NOTE that -UNW_EBADREG happens near the top of the stack where 
		 * unwind info gets patchy, so we should handle it mostly like the 
		 * BEGINNING_OF_STACK case if so... but only if we're at or above main
		 * (and anyway, we *should* have that unwind info, damnit!).
		 */
		else if (step_ret == 0 || (at_or_above_main && step_ret == -UNW_EBADREG))
		{
			higherframe_sp = BEGINNING_OF_STACK;
			higherframe_bp = BEGINNING_OF_STACK;
			got_higherframe_bp = 1;
			higherframe_ip = 0x0;
		}
		else
		{
			// return value <1 means error

			err = &__liballocs_err_stack_walk_step_failure;
			goto abort_stack;
			break;
		}

		// useful variables at this point: sp, ip, got_bp && bp, 
		// higherframe_sp, higherframe_ip, 
		// callee_ip

		// now do the stuff

		/* NOTE: here we are doing one vaddr_to_uniqtype per frame.
		 * Can we optimise this, by ruling out some frames just by
		 * their bounding sps? YES, I'm sure we can. FIXME: do this!
		 * The difficulty is in the fact that frame offsets can be
		 * negative, i.e. arguments exist somewhere in the parent
		 * frame. */
		/* 0. if our target address is greater than higherframe_bp,
		 * -- i.e. *higher* in the stack than the top of the next frame 
		 * -- continue (it's in a frame we haven't yet reached!)
		 */
		if (got_higherframe_bp && (uintptr_t) obj > higherframe_bp)
		{
			continue;
		}

		// (if our target address is *lower* than sp, we'll abandon the walk, below)

		// 1. get the frame uniqtype for frame_ip
		struct frame_uniqtype_and_offset s = vaddr_to_stack_uniqtype((void *) ip);
		struct uniqtype *frame_desc = s.u;
		if (!frame_desc)
		{
			// no frame descriptor for this frame; that's okay!
			// e.g. our liballocs frames should (normally) have no descriptor
			continue;
		}
		// 2. what's the frame base? it's the higherframe stack pointer
		unsigned char *frame_base = (unsigned char *) higherframe_sp;
		// 2a. what's the frame *allocation* base? It's the frame_base *minus*
		// the amount that s told us. 
		unsigned char *frame_allocation_base = frame_base - s.o;
		// 3. is our candidate addr between frame_allocation_base and that+posoff?
		if ((unsigned char *) obj >= frame_allocation_base
			&& (unsigned char *) obj < frame_allocation_base + frame_desc->pos_maxoff)
		{
			if (out_base) *out_base = frame_allocation_base;
			if (out_type) *out_type = frame_desc;
			if (out_site) *out_site = (void*)(intptr_t) ip; // HMM -- is this the best way to represent this?
			if (out_size) *out_size = frame_desc->pos_maxoff;
			goto out_success;
		}
		// have we gone too far? we are going upwards in memory...
		// ... so if our current frame (not higher frame)'s 
		// numerically lowest (deepest) addr 
		// is still higher than our object's addr, we must have gone past it
		if (frame_allocation_base > (unsigned char *) obj)
		{
			struct insert *heap_info = lookup_object_info(obj, (void**) out_base, 
				out_size, NULL);
			if (heap_info)
			{
				/* It looks like this is an alloca chunk, so proceed. */
				// goto do_alloca_as_if_heap; // FIXME: reinstate alloca handling
			}

			err = &__liballocs_err_stack_walk_reached_higher_frame;
			goto abort_stack;
		}

		assert(step_ret > 0 || higherframe_sp == BEGINNING_OF_STACK);
	} while (higherframe_sp != BEGINNING_OF_STACK);
	// if we hit the termination condition, we've failed
	if (higherframe_sp == BEGINNING_OF_STACK)
	{
		err = &__liballocs_err_stack_walk_reached_top_of_stack;
		goto abort_stack;
	}
out_success:
	return NULL;
abort_stack:
	if (!err) err = &__liballocs_err_unknown_stack_walk_problem;
	++__liballocs_aborted_stack;
	return err;
}
#define maximum_vaddr_range_size (4*1024) // HACK

struct frame_uniqtype_and_offset
vaddr_to_stack_uniqtype(const void *vaddr)
{
	assert(__liballocs_allocsmt != NULL);
	if (!vaddr) return (struct frame_uniqtype_and_offset) { NULL, 0 };
	
	/* We chained the buckets to completely bypass the extra struct layer 
	 * that is frame_allocsite_entry.
	 * This means we can walk the buckets as normal.
	 * BUT we then have to fish out the frame offset.
	 * We do this with a "CONTAINER_OF"-style hack. 
	 * Then we return a *pair* of pointers. */
	
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)vaddr | (BEGINNING_OF_STACK+1ul)));
	struct allocsite_entry **bucketpos = initial_bucketpos;
#if 0
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= vaddr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > vaddr))
			{
				struct frame_allocsite_entry *e = (struct frame_allocsite_entry *) (
					(char*) p
					- offsetof(struct frame_allocsite_entry, entry)
				);
				assert(&e->entry == p);
				return (struct frame_uniqtype_and_offset) { p->uniqtype, e->offset_from_frame_base };
			}
			might_start_in_lower_bucket &= (p->allocsite > vaddr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_vaddr_range_size);
#endif
	return (struct frame_uniqtype_and_offset) { NULL, 0 };
}
#undef maximum_vaddr_range_size
#undef BEGINNING_OF_STACK
