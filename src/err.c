#define _GNU_SOURCE
#include <stdio.h>

/* HACK to avoid too much librunt dependency in this allocsld-borrowed code. */
#ifndef IN_LIBALLOCS_DSO
#define get_exe_command_basename(...) "(no name)"
#endif

/* If we are linking librunt, as we usually are, we will get this from there.
 * But otherwise don't! E.g. from allocsld, don't pull in librunt. */
FILE *stream_err __attribute__((weak));
#include "liballocs_private.h"

int __liballocs_debug_level;

__attribute__((visibility("hidden")))
FILE *get_stream_err(void)
{
	// figure out where our output goes
	const char *errvar = getenv("LIBALLOCS_ERR");
	if (errvar)
	{
		// try opening it
		stream_err = fopen(errvar, "w");
		if (!stream_err)
		{
			stream_err = stderr;
			debug_printf(0, "could not open %s for writing\n", errvar);
		}
	} else stream_err = stderr;
	assert(stream_err);
	return stream_err;
}

const char *__liballocs_errstring(struct liballocs_err *err)
{
	return err->message;
}
