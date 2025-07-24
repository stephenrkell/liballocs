#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "liballocs_private.h"

/* __private_malloc is defined by our Makefile as __wrap_dlmalloc.
 * Since dlmalloc does not include a strdup, we need to define
 * that explicitly. */
char *__liballocs_private_strdup(const char *s)
{
	size_t len = strlen(s) + 1;
	char *mem = __private_malloc(len);
	if (!mem) return NULL;
	return memcpy(mem, s, len);
}
char *__private_strdup(const char *s) __attribute__((alias("__liballocs_private_strdup")));
char *__liballocs_private_strndup(const char *s, size_t n)
{
	size_t maxlen = strlen(s);
	size_t len = (n > maxlen ? maxlen : n) + 1;
	char *mem = __private_malloc(len);
	if (!mem) return NULL;
	return memcpy(mem, s, len);
}
char *__private_strndup(const char *s, size_t n) __attribute__((alias("__liballocs_private_strndup")));
