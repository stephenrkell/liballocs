/* We don't currently use any standard headers, because CIL configured
 * with GCC won't lex them as Clang needs (_Float64 as an ident, etc).
 */
struct uniqtype;
#include "uniqtype.h"
struct uniqtype *__liballocs_get_alloc_type(void *);
void *dlsym(void *, const char *);
extern void
__assert_fail (
const char *assertion, const char *file,
#if !defined(__musl__) && !defined(ASSERT_FAIL_LINE_SIGNED)
        unsigned
#endif
        int line, const char *function
)
#if __STDC_VERSION__ >= 201112L
 __attribute__((__noreturn__))
#endif
;
#define assert(cond) \
  do { if (!(cond)) { \
          __assert_fail(#cond , __FILE__, __LINE__, __func__); \
  } } while(0)
extern __thread void *__current_allocsite __attribute__((weak));

// HACK: pasted from liballocs.h which we're not yet able to include here
#define BITS_STRING_CAT(tok1, tok2) tok1 ## tok2 /* extra indirection, working around how '##' inhibits expansion... */
#define BITS_STRING(nbytes) BITS_STRING_CAT(BITS_STRING_, nbytes) /* ... i.e. it wouldn't work to just '##' in here */
#define BITS_STRING_1 "8"
#define BITS_STRING_2 "16"
#define BITS_STRING_4 "32"

int main(void)
{
	void *a = __builtin_alloca(42 * sizeof (int));
	struct uniqtype *got_type = __liballocs_get_alloc_type(a);
	struct uniqtype *int_type = dlsym(/*RTLD_NEXT*/ (void*)-1l, "__uniqtype__int$$" BITS_STRING(__SIZEOF_INT__));
	assert(int_type);
	assert(got_type);
	assert(UNIQTYPE_IS_ARRAY_TYPE(got_type));
	assert(UNIQTYPE_ARRAY_ELEMENT_TYPE(got_type) == int_type);
	
	return 0;
}

