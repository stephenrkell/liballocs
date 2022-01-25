THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE))/..)
-include $(srcroot)/config.mk

# HACK while LTO is broken
CFLAGS += -fno-lto
LDFLAGS += -fno-lto

META_BASE ?= /usr/lib/meta

.PHONY: default
default: client-allocator-elf+meta $(META_BASE)$(realpath $(dir $(THIS_MAKEFILE)))/client-allocator-elf+meta-meta.so

$(META_BASE)$(realpath $(dir $(THIS_MAKEFILE)))/client-allocator-elf+meta-meta.so: client-allocator-elf+meta
	$(MAKE) -f $(srcroot)/tools/Makefile.meta  $@

CFLAGS += -I$(srcroot)/include -g
LDFLAGS += -L$(srcroot)/lib -L$(LIBDLBIND)/lib
LDLIBS += -lallocs -ldlbind -ldl -lbsd

client-allocator-elf+meta: client-allocator-elf+meta.o

client-allocator-elf+meta.o: client-allocator-elf.o
	cp "$<" "$@" && ../tools/lang/c/bin/link-used-types "$@" || (rm -f "$@"; false)
