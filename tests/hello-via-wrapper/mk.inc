# Instead of allocscc/allocscompilerwrapper.py, use the new toolsub-based
# minimalist wrapping + linker plugin.

CC := cc `$(LIBALLOCS)/tools/allocs-cflags` `$(LIBALLOCS)/tools/allocs-ldflags`
export LIBALLOCS # the linker plugin needs this

# HACKy attempt to forestall __tls_get_addr and "DSO missing from command line" problems
#LDLIBS += /lib64/ld-linux-x86-64.so.2
