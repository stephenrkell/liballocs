#include <dlfcn.h>
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

struct s1a
{
	int x;
} s;

void *l1a(void)
{
	/* Get our __uniqtype__s1a. */
	struct rec *resolved = dlsym(__libcrunch_my_typeobj(), "__uniqtype__s1a");
	/* Return our __uniqtype__int$32. */
	return resolved->contained[0].ptr;
}
