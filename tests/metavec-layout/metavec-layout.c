#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "allocmeta-defs.h"

union
{
	union sym_or_reloc_rec fields;
	uint64_t word;
} u[] = {
	{ fields: { sym: { .kind = 7, .uniqtype_ptr_bits_no_lowbits = 1, .idx = 9 } } },
	{ word: SYM_ONLY_REC_WORD(7ul, 9ul, /* ptr_as_integer_incl_lowbits */ 8ul) }
};

int main(void)
{
	assert(sizeof (union sym_or_reloc_rec) == 8);
	assert(u[0].word == u[1].word);
	return 0;
}

