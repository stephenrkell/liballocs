#include <stdio.h>
#include "donald.h"

void __attribute__((noreturn)) enter(void *entry_point)
{
	fprintf(stderr, DONALD_NAME ": jumping to system ld.so entry point %p with rsp %p\n",
		(void*) entry_point, rsp_on_entry);
	fflush(stderr);
	__asm__ volatile ("movq %0, %%rsp\n"
		  "xorq %%rbp, %%rbp\n" /* clear rbp to avoid confusing stack walkers */
		  "jmpq *%1\n" : : "m"(rsp_on_entry), "r"(entry_point));
	__builtin_unreachable();
}
