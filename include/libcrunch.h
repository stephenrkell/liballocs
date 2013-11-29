/* stuff defined by libcrunch */

/* Copied from dumptypes.cpp */
struct rec
{
	const char *name;
	short pos_maxoff; // 16 bits
	short neg_maxoff; // 16 bits
	unsigned nmemb:12;         // 12 bits -- number of `contained's (always 1 if array)
	unsigned is_array:1;       // 1 bit
	unsigned array_len:19;     // 19 bits; 0 means undetermined length
	struct { 
		signed offset;
		struct rec *ptr;
	} contained[];
};

_Bool __libcrunch_is_initialized __attribute__((weak));
int __libcrunch_global_init(void) __attribute__((weak));
struct rec *__libcrunch_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
void *__libcrunch_my_typeobj(void) __attribute__((weak));
