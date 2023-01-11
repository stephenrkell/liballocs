# Instead of allocscc/allocscompilerwrapper.py, use the new toolsub-based
# minimalist wrapping + linker plugin.

CC := cc `$(LIBALLOCS)/tools/allocs-cflags` `$(LIBALLOCS)/tools/allocs-ldflags`
