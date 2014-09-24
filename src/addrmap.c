#include <stdint.h>
#include <unistd.h>
#include "addrmap.h"

uintptr_t __liballocs_startup_brk;

static void save_startup_brk(void) __attribute__((constructor(101))); /* top user priority... */
static void save_startup_brk(void)
{
	__liballocs_startup_brk = (uintptr_t) sbrk(0);
}
