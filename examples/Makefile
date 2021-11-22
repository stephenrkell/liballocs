THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE))/..)
-include $(srcroot)/config.mk

# HACK while LTO is broken
CFLAGS += -fno-lto
LDFLAGS += -fno-lto

.PHONY: default
default: client-allocator-elf

CFLAGS += -I$(srcroot)/include
LDFLAGS += -L$(srcroot)/lib -L$(LIBDLBIND)/lib
LDLIBS += -lallocs -ldlbind -ldl
