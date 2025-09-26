#define _GNU_SOURCE
#include <stdio.h>
#include <link.h>
#include "librunt.h"
#include "liballocs_private.h"

const char *format_symbolic_address(const void *addr) __attribute__((visibility("hidden")));
const char *format_symbolic_address(const void *addr)
{
	Dl_info info = fake_dladdr_with_cache(addr);
	
	static __thread char buf[8192];
	
	snprintf(buf, sizeof buf, "%s`%s+%p", 
		info.dli_fname ? basename(info.dli_fname) : "unknown", 
		info.dli_sname ? info.dli_sname : "unknown", 
		info.dli_saddr
			? (void*)((char*) addr - (char*) info.dli_saddr)
			: NULL);
		
	buf[sizeof buf - 1] = '\0';
	
	return buf;
}

