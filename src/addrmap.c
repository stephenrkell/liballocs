#include <stdint.h>
#include <unistd.h>
#include "addrmap.h"

#ifdef USE_STARTUP_BRK
intptr_t startup_brk;

static void save_startup_brk(void) __attribute__((constructor(100))); /* top user priority... */
static void save_startup_brk(void)
{
	startup_brk = (intptr_t) sbrk(0);
}
#endif
