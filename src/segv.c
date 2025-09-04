#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "pageindex.h"
#include "vas.h"
#include "raw-syscalls-defs.h" /* we need raw_mmap() and write_string() */
#include "liballocs_private.h"

static struct sigaction oldaction; /* We will restore this... */

/* FIXME: we should really use some handler chaining, not
 * just clobbering whatever handler pre-exists. libcrunch
 * needs its own handler, and the guest program may too. */
static void handle_sigsegv(int n, siginfo_t *info, void *ucontext)
{
	/* If the fault falls within the pageindex area, we map something there.
	 * Otherwise, don't. */
	if ((uintptr_t) info->si_addr >= PAGEINDEX_ADDRESS &&
	    (uintptr_t) info->si_addr <  PAGEINDEX_ADDRESS + PAGEINDEX_SIZE_BYTES)
	{
		/* FIXME: check whether we have already mapped something here. */
		/* Do we want to keep a bitmap of which hugepages of pageindex are
		 * already mapped? If the pageindex is 2^37 bytes, and a hugepage
		 * is 2^21 bytes, then there are 2^16 bits in this bitmap, or 2^13
		 * bytes, which is very manageable for mapping locally. */
		/* NOTE that we use hugepages only as a convenient unit, i.e. a coarse-
		 * -grained division of memory -- nothing about our logic depends on matching
		 * the underlying architecture's hugepage size. */
		uintptr_t range_base = RELF_ROUND_DOWN_((uintptr_t) info->si_addr, COMMON_HUGEPAGE_SIZE);
		uintptr_t range_idx = (range_base - PAGEINDEX_ADDRESS) >> LOG_COMMON_HUGEPAGE_SIZE;
		void *ret = raw_mmap((void*) range_base, COMMON_HUGEPAGE_SIZE,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
		if (ret != (void*) range_base) abort();
		debug_printf(0, "lazily mapped a piece of pageindex at %p (idx 0x%lx)\n",
			ret, (unsigned long) range_idx);
		return; // we explicitly resume from the segfault
	}
	/* FIXME: be more compositional, w.r.t. other possible handlers (installed
	 * either before we install ours or after!).
	 * For now, we want to do whatever would happen if our handler was not installed...
	 * probably that's just exit. However, exiting has the side effect of disabling
	 * the core handling path. Instead we disable ourselves and then resume! FIXME: this
	 * is not foolproof, e.g. if there are concurrent threads futzing with the memory map. */
	write_string("Segmentation fault not handleable by lazy memory mapping\n");
	//raw_exit(128 + SIGSEGV);
	sigaction(SIGSEGV, &oldaction, NULL);
}

/* FIXME: consider using SIGBUS here, as it is more rarely triggered
 * than SIGSEGV and so is less confusing/disruptive at debug time. We could
 * memory-map a zero-length temporary file that we immediately unlink. I
 * suppose a third party could still re-truncate that file while we're running,
 * using the /proc/pid/fd/* symlink, but would that be a useful attack? More
 * importantly, does this SIGBUS approach also avoid huge core files? */

__attribute__((visibility("hidden")))
void install_segv_handler(void)
{
	struct sigaction action = {
		.sa_handler = (void*) &handle_sigsegv,
		.sa_flags = SA_NODEFER | SA_SIGINFO
	};
	int ret = sigaction(SIGSEGV, &action, &oldaction);
	if (ret != 0) abort();
}
