THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE))/..)
-include $(srcroot)/config.mk

# HACK while LTO is broken
CFLAGS += -fno-lto
LDFLAGS += -fno-lto

CLANG ?= clang

# HACK while gcc can't grok our case / atomify4 metaprogramming
# SIGH: without -fPIC, with clang we hit the infamous 'copy reloc of protected
# symbols' bug, because it generates R_X86_64_64 direct to big_allocations
# that it thinks will be copy-reloc'd into the executable, but the real liballocs
# is using its own copy
CC := $(CLANG) -fPIC -fno-lto

META_BASE ?= /usr/lib/meta

.PHONY: default
default: client-allocator-elf+meta $(META_BASE)$(realpath $(dir $(THIS_MAKEFILE)))/client-allocator-elf+meta-meta.so

$(META_BASE)$(realpath $(dir $(THIS_MAKEFILE)))/client-allocator-elf+meta-meta.so: client-allocator-elf+meta
	$(MAKE) -f $(srcroot)/tools/Makefile.meta $@

CFLAGS += -I$(srcroot)/include -g $(LIBALLOCSTOOL_CFLAGS)
LDFLAGS += -L$(srcroot)/lib -L$(LIBDLBIND)/lib -Wl,--dynamic-linker,$(srcroot)/lib/allocsld.so $(srcroot)/lib/interp-pad.o
LDLIBS += -lallocs -ldlbind -ldl -lbsd

client-allocator-elf+meta: client-allocator-elf.o elf-allocators+meta.o elf-refs.o emit-asm.o
	$(CC) -o $@ $+ $(LDFLAGS) $(LDLIBS)

%+meta.o: %.o
	cp "$<" "$@" && ../tools/lang/c/bin/link-used-types "$@" || (rm -f "$@"; false)

.PHONY: clean
clean:
	rm -f  client-allocator-elf.o  client-allocator-elf+meta.o client-allocator-elf+meta
