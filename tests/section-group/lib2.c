#include <dlfcn.h>
#include <assert.h>
#include "libcrunch.h"

struct rec
{
	const char *name;
	short pos_maxoff; // 16 bits
	short neg_maxoff; // 16 bits
	unsigned nmemb:12;	 // 12 bits -- number of `contained's (always 1 if array)
	unsigned is_array:1;       // 1 bit
	unsigned array_len:19;     // 19 bits; 0 means undetermined length
	struct { 
		signed offset;
		struct rec *ptr;
	} contained[];
};

extern struct rec *l2a(void);

struct s2
{
	int x;
} s;

void *l2(int arg)
{
	/* Get our __uniqtype__s1. */
	struct rec *resolved = dlsym(__libcrunch_my_typeobj(), "__uniqtype__s2");
	struct rec *int32 = resolved->contained[0].ptr;
	
	/* Check that we're using the same "__uniqtype_int$32" as l2a is. */
	assert(l2a() == int32);
	
	/* Pass our pointer up to main(), so it can test globally. */
	return int32;
}
