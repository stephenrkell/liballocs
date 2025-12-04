#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for dladdr1() */
#endif
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <strings.h> /* for bzero() */
#include <err.h>
#include <alloca.h>
#include <dwarf.h>
#include <dlfcn.h>
#include <link.h> /* for ElfW */

/* program -- a sequence of opcodes with arguments.
 * We use a type-level sequence.
 * Each DWARF opcode can have up to two arguments, here Arg1 and Arg2.
 * We need EncodedLength because branch targets (in DW_OP_bra) are encoded in terms
 * of bytes. */
template <unsigned Op, signed long Arg1, signed long Arg2, unsigned EncodedLength, class Next>
struct program
{
	static const long op = Op;
	static const long arg1 = Arg1;
	static const long arg2 = Arg2;
	static const unsigned encoded_length = EncodedLength;
	typedef Next tail;
};

/* States in a computation. Note that the program counter is encoded by ProgramTail. */
template <
	/* Program */ typename Program,
	/* ProgramTail */ typename ProgramTail    /* i.e. a suffix of the Program, 
	                                             beginning with the next instruction to run. */
	>
struct state
{
};

/* We want to compile the generated functions into -meta.so files,
 * such that a caller can evaluate them _on a struct mcontext_.
 *
 * Where does the caller of such a function need its temporary
 * storage to go? On the stack, silly.
 *
 * The difference from what came before is that I don't want to mmap
 * my own stack. I just want to use the calling stack.
 *
 * When we tail-call the next operation, we do need some way to pass
 * the DWARF operand stack. AHA. That tail-call doesn't have to have
 * the same signature as the entry point function. The entry-point
 * function of course creates its *own* root of the stack, and can
 * thread that through the opcodes it executes, all of which take a
 * pointer to a stack. Simples!
 *
 * So we can still use our morestack and killstack primitives. But
 * they do something different: they work on the threaded stack
 * that we are defining here.
 */
struct stack_section
{
	unsigned nwords;
	unsigned nspare;      // [0..nwords)
	struct stack_section *prev;
	long words[/* nwords */]; // words[nspare] is the top, then words[nspare-1], ...,
		// then prev->words[prev->nspare] and so on.
		/* In this way, we still have the property that the stack grows downwards,
		 * i.e. the lowest address is the top of the stack.
		 */

	long& operator[](signed offset)
	{
		if (offset < 0)      /* whoops */ assert(false && "stack indexes may not be negative");
		if (offset < (nwords - nspare)) /* easy! */ return words[nspare + offset];
		/* If we got here, we need to look further up the stack.
		 * Use a recursive call. */
		if (!prev) /* ran out of stack! */ assert(false && "stack index ran off the end");
		//printf("Escalating for offset %d (we have only %d of which %d spare)...\n",
		//	(int) offset, (int) nwords, (int) nspare);
		return (*prev)[offset - (nwords - nspare)];
	}
	void drop_n(unsigned nwords_to_drop)
	{
#ifndef MIN
#define MIN(a,b)  (((a)<(b))?(a):(b))
#endif
		// how many can we drop locally?
		unsigned our_drop_nwords = MIN(this->nwords - this->nspare, nwords_to_drop);
		nspare += our_drop_nwords;
		signed remaining = nwords_to_drop - our_drop_nwords;
		if (remaining > 0)
		{
			if (!prev) abort();
			prev->drop_n(remaining);
		}
	}
};

/* Ditched the morestack(), lessstack(), killstack() calls for now
 * since I think, one our stack segments are local vars, the compiler will
 * be smart enough to figure it out... */
#define killstack(...) do {} while(0)
// now we require the local stack to be called 'end'
#define initstack(nwords_) \
  struct stack_section& end = *(struct stack_section *)(\
    alloca(offsetof(struct stack_section, words) + (nwords_)*(sizeof (long)))\
  ); \
  end.nwords = (nwords_); \
  end.nspare = 0; \
  end.prev = nullptr
#define morestack(nbytes) \
  initstack((nbytes) / sizeof (long)); \
  end.prev = &prev_end;
#define lessstack(nbytes) \
  (({ end.drop_n((nbytes) / sizeof (long)); }), end)

/* Get the length of a sequence. */
template <class Seq> 
struct sequence_length
{
	static const long value = 1 + sequence_length<typename Seq::tail>::value;
};

template <>
struct sequence_length<void>
{
	static const long value = 0;
};

/* Get the byte length of a sequence of instructions. */
template <class Seq> 
struct byte_length
{
	static const unsigned value = Seq::encoded_length + byte_length<typename Seq::tail>::value;
};

template <>
struct byte_length<void>
{
	static const long value = 0;
};

/* Utility for getting the tail of a type-level sequence. */
template <typename Seq>
struct tail_of
{
	typedef typename Seq::tail type;
};
template <>
struct tail_of<void>
{
	typedef void type;
};

/* Utility for getting the nth of a sequence
 * -- it's like "let s = drop n Seq in (hd s, tl s)" */
template <unsigned n, class Program> // n > 0 case
struct drop_n_instructions
{
	static const long op = drop_n_instructions<n-1, typename tail_of<Program>::type>::op;
	static const long arg1 = drop_n_instructions<n-1, typename tail_of<Program>::type>::arg1;
	static const long arg2 = drop_n_instructions<n-1, typename tail_of<Program>::type>::arg2;
	static const unsigned encoded_length = drop_n_instructions<n-1, typename tail_of<Program>::type>::encoded_length;
	typedef typename tail_of< drop_n_instructions<n-1, typename tail_of<Program>::type> >::type tail;
};

template <>
struct drop_n_instructions<0, void>
{
	static const long op = 0l; /* i.e. something fishy going on */
	static const long arg1 = 0l;/* i.e. something fishy going on */
	static const long arg2 = 0l;/* i.e. something fishy going on */
	static const unsigned encoded_length = 0; /* ditto */
	typedef void tail;
};

template <class Seq>
struct drop_n_instructions<0, Seq>
{
	static const long op = Seq::op;
	static const long arg1 = Seq::arg1;
	static const long arg2 = Seq::arg2;
	static const unsigned encoded_length = Seq::encoded_length;
	typedef typename tail_of<Seq>::type tail;
};

/* Utility for seeking n bytes into an instruction sequence. */
template <unsigned n, class Seq> // n > 0 case
struct gobble_nbytes
{
	static const long op = gobble_nbytes<n - Seq::encoded_length, typename tail_of<Seq>::type>::op;
	static const long arg1 = gobble_nbytes<n - Seq::encoded_length, typename tail_of<Seq>::type>::arg1;
	static const long arg2 = gobble_nbytes<n - Seq::encoded_length, typename tail_of<Seq>::type>::arg2;
	static const unsigned encoded_length = gobble_nbytes<n - Seq::encoded_length, typename tail_of<Seq>::type>::encoded_length;
	typedef typename tail_of< gobble_nbytes<n - Seq::encoded_length, typename tail_of<Seq>::type> >::type tail;
};

template <>
struct gobble_nbytes<0, void>
{
	static const long op = -1l; /* i.e. something fishy going on */
	static const long arg1 = 0l;
	static const long arg2 = 0l;
	static const unsigned encoded_length = 0u;
	typedef void tail;
};

template <class Seq>
struct gobble_nbytes<0, Seq>
{
	static const long op = Seq::op;
	static const long arg1 = Seq::arg1;
	static const long arg2 = Seq::arg2;
	static const unsigned encoded_length = Seq::encoded_length;
	typedef typename tail_of<Seq>::type tail;
};

/* Dummy type signifying that the next instruction is not statically known.
 * We can always supply an upper bound on the target PC though -- at worst,
 * it's the length of the program (minus one). */
template <unsigned UpperBound> 
struct run_time_pc {};

/* This specialization handles "end of program". */
template <
	/* Program */ typename Program
	>
struct state< Program, void>
{
	__attribute__((always_inline))
	static long eval(struct stack_section& end)
	{
		long ret = end[0];
		killstack(end, (stack_highest_word + 1 - end) * sizeof (long));
		return ret;
	}
};

/* Branches to the 'void' program tail i.e. the end of the program...
 * it's perfectly valid to branch to the end, to skip over tail instrs. */
template <
	/* Program */ typename Program
	>
struct state< Program, program<0u, 0l, 0l, 0u, void > >
{
	static long eval(struct stack_section& end)
	{
		return end[0]; // this is bounds-checked by stack_section
	}
};
/* This specialization handles *any* indirect (data-dependent) branch target,
 * by taking a program counter value as a *run-time* index, and 
 * dispatching to the appropriate specialization that is *statically*
 * bound to that index. This allows us to transition back to the 
 * generated code. It also saves us from adding a separate run_time_pc specialization
 * for every opcode.  */
template <
	/* Program */ typename WholeProgram,
	              unsigned MaxByteOffset
	>
struct state< WholeProgram, run_time_pc<MaxByteOffset> >
{
	/* We can avoid bounding the number of instructions by using recursive elaboration.
	 * This is fast only if the C++ compiler can turn if--else chains back into jump table. */
	__attribute__((always_inline)) // <-- this will break, e.g. for backward-branching programs
	static long eval_if_else(struct stack_section& end, long pc)
	{
		if (pc == MaxByteOffset) return state< // "branch to pc MaxByteOffset" where MaxByteOffset is non-zero
			WholeProgram,
			program<
				/* We build the tail starting from the nth, using the definitions in `nth<>'. */
				drop_n_instructions<MaxByteOffset, WholeProgram>::op,
				drop_n_instructions<MaxByteOffset, WholeProgram>::arg1,
				drop_n_instructions<MaxByteOffset, WholeProgram>::arg2,
				drop_n_instructions<MaxByteOffset, WholeProgram>::encoded_length,
				typename drop_n_instructions<MaxByteOffset, WholeProgram>::tail
			> 
		>::eval(end);
		else return state<WholeProgram, run_time_pc<MaxByteOffset - 1> >::eval_if_else(end, pc);
	}

	__attribute__((always_inline)) // <-- this will break, e.g. for backward-branching programs
	static long eval_jump_table(struct stack_section& end, long pc)
	{
		/* This will generate a jump table 
		 * where each entry is a tail-call (i.e. another jump)
		 * to the machine-code snippets 
		 * handling each of the program instructions (0..MAX). 
		 * When inlined into the caller, we get effectively 
		 * a jump keyed on the destination value.
		 * If the destination value is *statically* known
		 * at the caller (i.e. is a literal in the program, not a computed
		 * value), what we get is a direct branch! 
		 * 
		 * In our current machine, branch destinations are encoded
		 * on the operand stack, so we only know the destination if the 
		 * stack is non-materialized. BUT in DWARF, the destinations
		 * are arguments to the instructions! So they are statically
		 * known very often (i.e. for any non-computed branch), meaning
		 * we do get a simple direct branch.
		 */
		switch (pc)
		{
#define MAX_PROGRAM_SIZE 64
#define CASE(n) \
case n: return state< \
		WholeProgram, \
		program< \
			/* We build the tail starting from the nth, using the definitions in `nth<>'. */ \
				drop_n_instructions< n, WholeProgram>::op, \
				drop_n_instructions< n, WholeProgram>::arg1, \
				drop_n_instructions< n, WholeProgram>::arg2, \
				drop_n_instructions< n, WholeProgram>::encoded_length, \
				typename drop_n_instructions< n, WholeProgram>::tail \
			> \
		>::eval(end);
			CASE(0)  // returns... as do all the others
			CASE(1)
			CASE(2)
			CASE(3)
			CASE(4)
			CASE(5)
			CASE(6)
			CASE(7)
			CASE(8)
			CASE(9)
			CASE(10)
			CASE(11)
			CASE(12)
			CASE(13)
			CASE(14)
			CASE(15)
			CASE(16)
			CASE(17)
			CASE(18)
			CASE(19)
			CASE(20)
			CASE(21)
			CASE(22)
			CASE(23)
			CASE(24)
			CASE(25)
			CASE(26)
			CASE(27)
			CASE(28)
			CASE(29)
			CASE(30)
			CASE(31)
			CASE(32)
			CASE(33)
			CASE(34)
			CASE(35)
			CASE(36)
			CASE(37)
			CASE(38)
			CASE(39)
			CASE(40)
			CASE(41)
			CASE(42)
			CASE(43)
			CASE(44)
			CASE(45)
			CASE(46)
			CASE(47)
			CASE(48)
			CASE(49)
			CASE(50)
			CASE(51)
			CASE(52)
			CASE(53)
			CASE(54)
			CASE(55)
			CASE(56)
			CASE(57)
			CASE(58)
			CASE(59)
			CASE(60)
			CASE(61)
			CASE(62)
			CASE(63)
			CASE(64) // ... returns
			/* MAX_PROGRAM_SIZE */
			default: 
				#ifndef DEBUG
						__builtin_unreachable();
				#endif
				assert(pc >= MAX_PROGRAM_SIZE); 
				warnx("jumped to an offset beyond the maximum program size");
				abort();
		}
	}

};

template <
	/* Program */ typename WholeProgram
	>
struct state< WholeProgram, run_time_pc<0> >
{
	static long eval_if_else(struct stack_section& end, long pc)
	{
		if (pc == 0) return state<
			WholeProgram,
			program<
				/* We build the tail starting from the nth, using the definitions in `nth<>'. */
				drop_n_instructions<0, WholeProgram>::op,
				drop_n_instructions<0, WholeProgram>::arg1,
				drop_n_instructions<0, WholeProgram>::arg2,
				drop_n_instructions<0, WholeProgram>::encoded_length,
				typename drop_n_instructions<0, WholeProgram>::tail
			> 
		>::eval(end);
		else
		{
#ifndef DEBUG
			__builtin_unreachable();
#endif
			warnx("if-else cascaded beyond 0");
			abort();
		}
	}
};

#define GET_BYTE_OFFSET(prog) \
	byte_length<WholeProgram>::value \
			 - byte_length< prog >::value

/* Specialize for DW_OP_bra */
template <
	/* Program */ typename WholeProgram,
	signed long ArgByteDistance,
	signed long Arg2 /* unused */,
	unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_bra, ArgByteDistance, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline)) // <-- this fails with "function not inlinable" if we also put it on eval_jump_table
	static long eval(struct stack_section& end)
	{
		long testval = end[0];
		lessstack(sizeof (long));
		return (testval != 0) ? 
			/* We were previously using run_time_pc, but that was totally unnecessary.
			 * The reason: we have ArgByteDistance statically!
			 * We only need run_time_pc where the branch target is computed. And
			 * currently there is no way in DWARF (at least DWARF5, at least by my reading)
			 * to do a computed branch. So the whole run_time_pc thing is not needed. */
#if 0
			state<WholeProgram, run_time_pc<sequence_length<WholeProgram>::value> >::/*template */ /*eval_if_else*/ eval_jump_table(
				end,
				byte_length<WholeProgram>::value // byte idx of target
				 - byte_length< 
				 	program<DW_OP_bra, ArgByteDistance, Arg2, EncodedLength, ProgramTail> 
				   >::value
				 + EncodedLength + ArgByteDistance
			)
#else
			/* FIXME: I suspect that this will fail with "function not inlinable" for
			 * backwards branches. We might want to separate out that case. An
			 * eval_noinline function could do it. */
			state<WholeProgram, typename gobble_nbytes<
				// byte idx of target is our current index, i.e. whole program - tail...
				byte_length<WholeProgram>::value
				 - byte_length< 
				 	program<DW_OP_bra, ArgByteDistance, Arg2, EncodedLength, ProgramTail> 
				   >::value
				// ... plus our encoded length, plus "number of bytes to skip forward"
				// ("beginning after the 2-byte constant" i.e. after the encoded end of
				// the current instruction)
				 + EncodedLength + ArgByteDistance
				, WholeProgram >::tail
			>::eval(end)
#endif
			:
			state<WholeProgram, ProgramTail >::/*template */eval(
				end
			);
	}
};

/* Specialize for DW_OP_dup */
template <
	/* Program */ typename WholeProgram,
	signed long Arg1, signed long Arg2, unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_dup, Arg1, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline))
	static long eval(struct stack_section& prev_end)
	{
		morestack(sizeof (long));
		end[0] = end[1];
		return state<WholeProgram, ProgramTail >::eval(end);
	}
};

/* Specialize for DW_OP_nop */
template <
	/* Program */ typename WholeProgram,
	signed long Arg1, signed long Arg2, unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_nop, Arg1, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline))
	static long eval(struct stack_section& prev_end)
	{
		return state<WholeProgram, ProgramTail >::eval(prev_end);
	}
};

/* Specialize for DW_OP_mod */
template <
	/* Program */ typename WholeProgram,
	signed long Arg1, signed long Arg2, unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_mod, Arg1, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline))
	static long eval(struct stack_section& end)
	{
		end[1] = end[1] % end[0];
		return state<WholeProgram, ProgramTail >::eval(lessstack(sizeof (long)));
	}
};

/* Specialize for DW_OP_plus */
template <
	/* Program */ typename WholeProgram,
	signed long Arg1, signed long Arg2, unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_plus, Arg1, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline))
	static long eval(struct stack_section& end)
	{
		end[1] = end[1] + end[0];
		return state<WholeProgram, ProgramTail >::eval(lessstack(sizeof (long)));
	}
};

/* Specialize for DW_OP_mul */
template <
	/* Program */ typename WholeProgram,
	signed long Arg1, signed long Arg2, unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_mul, Arg1, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline))
	static long eval(struct stack_section& end)
	{
		end[1] = end[1] * end[0];
		return state<WholeProgram, ProgramTail >::eval(lessstack(sizeof (long)));
	}
};

/* Specialize for DW_OP_lit2 */
template <
	/* Program */ typename WholeProgram,
	signed long Arg1, signed long Arg2, unsigned EncodedLength,
	/* ProgramTail */ typename ProgramTail
	>
struct state< WholeProgram, program<DW_OP_lit2, Arg1, Arg2, EncodedLength, ProgramTail> >
{
	__attribute__((always_inline))
	static long eval(struct stack_section& prev_end)
	{
		morestack(sizeof (long));
		end[0] = 2;
		return state<WholeProgram, ProgramTail >::eval(end);
	}
};

#ifdef SELF_TEST

#include <iostream>

/* Map from the host calling convention to the on-stack calling convention.
 * FIXME: also add variants that take a mcontext_t*. It is threaded to all eval
 * methods. The variants lacking it get a null pointer. */
template <typename InitialState>
long invoke()
{
	initstack(0);
	return InitialState::eval(end);
}
template <typename InitialState>
long invoke(long arg1)
{
	initstack(1);
	end[0] = arg1;
	return InitialState::eval(end);
}
template <typename InitialState>
long invoke(long arg1, long arg2)
{
	initstack(2);
	end[0] = arg1;
	end[1] = arg2;
	return InitialState::eval(end);
}

template <typename T>
unsigned get_function_length(T *fun)
{
	Dl_info i;
	bzero(&i, sizeof i);
	void *extra = NULL;
	int ret = dladdr1((void*) fun, &i, &extra, RTLD_DL_SYMENT);
	return (ret != 0) ? ((ElfW(Sym) *) extra)->st_size : 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) { std::cout << "Give me two numerical arguments please" << std::endl; return 1; }
	// test program 1 -- literal 2
	{
		{
			typedef program< DW_OP_lit2, 0l, 0l, 1u, void > prog;
			typedef state<
				prog,
				prog
			> initial_state;
			long result = invoke<initial_state>();
			long(*fn)(long, long) = &invoke<initial_state>;
			std::cout << "result of { DW_OP_lit2 } is " << result << std::endl;
			std::cout << "function to compute it is at " << (void*) fn 
				<< " and has length " << get_function_length(fn) << " bytes" << std::endl;
		}
	}
	// test program 2 -- add two numbers (the same number)
	{
		{
			typedef program< DW_OP_plus, 0l, 0l, 1u, void > prog;
			typedef state<
				prog,
				prog
			> initial_state;
			long result = invoke<initial_state>(atoi(argv[1]), atoi(argv[1]));
			long(*fn)(long, long) = &invoke<initial_state>;
			std::cout << "result of { DW_OP_plus } is " << result << std::endl;
			std::cout << "function to compute it is at " << (void*) fn 
				<< " and has length " << get_function_length(fn) << " bytes" << std::endl;
		}
	}
	// test program 3 -- return an odd argument or twice an even one
	/* This program blows up (435 bytes for me) because the compiler loses track of
	 * the stack state, and our stack operations are expensive. Can we make them simpler?
	 * Or can we help the compiler? Note that the branch is to the end, so really
	 * it should be analyzable as a straight-line program; currently the compiler
	 * is not managing this. */
	{
		{
			typedef program< DW_OP_dup, 0l, 0l, 1u, 
			        	program< DW_OP_lit2, 0l, 0l, 1u, 
				        	program< DW_OP_mod, 0l, 0l, 1u, 
					        	program< DW_OP_bra, 2l /* skip two "one-byte" instrs */, 0l, 1u, 
						        	program< DW_OP_lit2, 0l, 0l, 1u, 
							        	program< DW_OP_mul, 0l, 0l, 1u, 
			void > > > > > > prog;
			typedef state<
				prog,
				prog
			> initial_state;
			long result = invoke<initial_state>(atoi(argv[1]));
			long(*fn)(long, long) = &invoke<initial_state>;
			std::cout << "result of { 6-instruction branching program } is " << result << std::endl;
			std::cout << "function to compute it is at " << (void*) fn 
				<< " and has length " << get_function_length(fn) << " bytes" << std::endl;
		}
	}
	// test program 4 -- unconditionally branch over a nop and then return literal 2
	// Note that the unconditional branch still needs a nonzero value on the stack; we use 2.
	// And terminating the expression needs a value on the stack; we also use 2.
	{
		{
			typedef program< DW_OP_lit2, 0l, 0l, 1u,
						program< DW_OP_lit2, 0l, 0l, 1u,
							program< DW_OP_bra, 1l, 0l, 1u,
			        			program< DW_OP_nop, 0l, 0l, 1u, 
				        			program< DW_OP_lit2, 0l, 0l, 1u,
			void > > > > > prog;
			typedef state<
				prog,
				prog
			> initial_state;
			long result = invoke<initial_state>();
			long(*fn)() = &invoke<initial_state>;
			std::cout << "result of { minimal branching program } is " << result << std::endl;
			std::cout << "function to compute it is at " << (void*) fn
				<< " and has length " << get_function_length(fn) << " bytes" << std::endl;
		}
	}
}

#endif
