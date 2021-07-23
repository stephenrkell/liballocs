#define _GNU_SOURCE
#define SYSTRAP_DEFINE_FILE
#include "do-syscall.h"
#include "systrap.h"
#include "vas.h"
#include "allocsmt.h"
#include "maps.h"
#include "pageindex.h"
#define RELF_DEFINE_STRUCTURES
#include "relf.h"

void __liballocs_systrap_init(void) {}

_Bool __liballocs_systrap_is_initialized; /* globally visible, so that it gets overridden. */

void __systrap_brk_hack(void) {}
