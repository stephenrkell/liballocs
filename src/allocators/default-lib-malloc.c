/* This file uses GNU C extensions */
#define _GNU_SOURCE

#include <sys/types.h>
size_t malloc_usable_size(void *ptr);
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include "liballocs_private.h"
#include "relf.h"
#include "pageindex.h"
#include "generic_malloc_index.h"
#include "malloc-meta.h"

/* This is the default, but go with it anyway. */
#define ALLOC_EVENT_ATTRIBUTES __attribute__((visibility("hidden")))

/* Stuff we need to generate glue goes in here. */
#include "../tools/stubgen.h" /* HACK */

/* This file should contain stuff that "could be generated", although
 * for now we're only generating some of it. */

ALLOC_EVENT_INDEXING_DEFS(__default_lib_malloc)

/* By default, the 'malloc' first in libraries' link order, i.e. the one */
/* our preload sits in front of, is deemed the global malloc. But if the */
/* executable has one too, it should override this. */
extern struct allocator __global_malloc_allocator
__attribute__((weak,alias("__default_lib_malloc_allocator")));
