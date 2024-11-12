.PHONY: default
default: allocsld.so

.PHONY: all
all: default

include ../config.mk

vpath %.c $(DONALD)/src

CFLAGS += -std=gnu99 -g -fPIC -save-temps
CFLAGS += -fno-stack-protector
CFLAGS += -I$(DONALD)/src # for donald.h, for non-vpath'd .c files
CFLAGS += -I$(LIBRUNT)/include
CFLAGS += -DDONALD_NAME=\"allocsld\"
CFLAGS += -DCHAIN_LOADER

# Thanks to Dan Williams for the recipes that my link commands were based on.
# http://www.cs.virginia.edu/~dww4s/articles/ld_linux.html

LIBC_ARCHIVE ?= $(LIBSYSTRAP)/contrib/musl/lib/libc.a
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

OBJS := premain.o main.o entry.o load.o chain.o debug.o allocinstr.o
C_DEPS := $(patsubst %.o,.%.d,$(OBJS))
DEPS := $(C_DEPS)

$(C_DEPS): .%.d: %.c
	$(CC) -MM $(CFLAGS) "$<" > "$@" || rm -f "$@"
	
-include $(DEPS)

# We use the 'dynappend' tool to add a DT_DEBUG entry to our .dynamic section.
# Normally only an executable gets these. But we are an executable, in the
# 'invoked' case, so a debugger will sometimes want to look at our DT_DEBUG.
# We use an outrageous hack to make this point to the 'real' _r_debug structure.
# FIXME: is this hack really necessary? Does debugging work when the ld.so is
# 'invoked'? I think it does, but the ld.so lacks a DT_DEBUG, so would be good
# to understand how it does so.
DYNAPPEND ?= $(ELFTIN)/dynappend/dynappend

# We must use the BFD-based linker (ld.bfd) -- gold doesn't work
# (it won't generate the donald.lds linker script, though I'm not yet sure why).
# FIXME: what happened to our flags for ensuring this?
allocsld.so: LDFLAGS += -fuse-ld=bfd \
            -nostdlib -nostartfiles \
            -Wl,--spare-dynamic-tags,2 \
            -Wl,-soname=ld-linux.so.2 -Wl,-Bsymbolic

# FIXME: localize all global symbols except maybe _start?
allocsld.so: allocsld.lds $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o "$@" \
            $(filter-out %.lds,$+) \
            -Wl,-Bstatic $(LIBC_ARCHIVE) -Wl,-Bsymbolic \
            -T $(filter %.lds,$+)
	$(DYNAPPEND) $@ 21 # add DT_DEBUG

# FIXME: including code here is not nice. Why not just call a function?
# I think it's because we can't anticipate what locals our function will
# want to receive from the calling context. Maybe instead do an #include?
# Then we would put the code quoted below into its own .h or .inc file for
# inclusion.
main.o: CFLAGS += -DCHAIN_LOADER \
  -DCHAIN_LOADER_COVER_TRACKS_H='"$(shell pwd)/cover-tracks.h"' \
  -DCHAIN_LOADER_COVER_TRACKS_INC='"$(shell pwd)/cover-tracks.inc.c"'

# We need to ensure we don't have any pages of 'hole'
# in between the two segments. But how? How does the
# break in segments even get made? The data segment
# seems to be created between here and DATA_SEGMENT_END.
#
# DATA_SEGMENT_ALIGN is tricky; recall my bug report
# https://sourceware.org/bugzilla/show_bug.cgi?id=19203
#
# Use of DATA_SEGMENT_ALIGN will *always* bump to a new
# MAXPAGESIZE-sized vaddr. Its different cases are about
# what offset within that 'big page' we resume at. Only
# COMMONPAGESIZE worth of memory or disk space is up for
# grabs, so it's small beer.
#
# Interestingly, my own machine's ld.so is vaddr-contiguous.
#
#  LOAD  0x000000000000 0x000000000000 0x000000000000
#        0x000000000f08 0x000000000f08  R      0x1000
#  LOAD  0x000000001000 0x000000001000 0x000000001000
#        0x00000001db20 0x00000001db20  R E    0x1000
#  LOAD  0x00000001f000 0x00000001f000 0x00000001f000
#        0x0000000073dc 0x0000000073dc  R      0x1000
#  LOAD  0x000000026640 0x000000027640 0x000000027640
#        0x0000000019b8 0x000000001b50  RW     0x1000
#
# i.e. it only bumps to a COMMONPAGESIZE boundary. If I
# just use COMMONPAGESIZE as arg to DATA_SEGMENT_ALIGN,
# it *should* work. But might not be usable on a system
# with MAXPAGESIZE-sized pages? Hmm. I think the loader
# would still have to deal with it. The ELF64 spec just
# says that p_offset and p_addr must be congruent modulo
# p_align. AH, but it couldn't! The consequence of big
# pages is that it can't set up those permissions at fine
# granularity.
#
# (I had thought the following, i.e. hacking the phdrs
# might be another way to do it. It would be more robust,
# in that it would still let us do big-page alignment.)
# What we want to do is avoid holes in the phdrs, for ANY
# page size. So it's really about the phdrs' vaddr and
# memsz, not the offsets etc. That means I think we need
# to wheel out the phdr-hacking scripts.
allocsld.lds: $(shell which ld) $(THIS_MAKEFILE)
	USE_LD=ld.bfd $(CC)   -nostdlib -nostartfiles -shared \
      -Wl,--verbose 2>&1 |  \
        LC_ALL=C \
          sed -e '/^=========/,/^=========/!d;/^=========/d'    \
              -e 's/\. = .* + SIZEOF_HEADERS;/& _begin = . - SIZEOF_HEADERS;/' \
              -e 's/\. = DATA_SEGMENT_ALIGN.*/. = DATA_SEGMENT_ALIGN (CONSTANT (COMMONPAGESIZE), CONSTANT (COMMONPAGESIZE));/' \
          > "$@" || (rm -f $@; false)

clean:
	rm -f allocsld.lds allocsld.so $(OBJS) $(DEPS)

malloc-patcher-self-test: return-hook.o malloc-patcher-with-main.o
	$(CC) -o $@ $+ $(LDFLAGS) $(LDLIBS)

malloc-patcher-with-main.o: malloc-patcher.c
	$(CC) -o $@ -c $< -DSELF_TEST $(CFLAGS) $(CPPFLAGS)

malloc-patcher-self-test: LDFLAGS += -fno-lto -L$(LIBSYSTRAP)/lib -L$(LIBRUNT)/lib

#   -Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
#   -Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr

malloc-patcher-self-test: LDLIBS += -Wl,-Bstatic -lsystrap -lrunt_preload -Wl,-Bdynamic

