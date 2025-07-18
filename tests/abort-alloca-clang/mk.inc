LIBALLOCS ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
#CC := $(LIBALLOCS_LIB)/contrib/llvm/build/bin/clang -fsanitize=allocs

# HACK
CLANG ?= clang-13

# To use clang, we need to use the wrapper
# XXX: FIXME: this still doesn't work. We need 'wrapper' to support
# the full clang -cc1 command line, which is not interchangeable
# with the driver version. -cc1 has to be the first argument it seems.
# A quick hack might be to prepend "-Xclang" to everything.
export CC_DRIVER := $(shell which $(CLANG))
CC := $(LIBALLOCS)/tools/allocs-wrap $(CC_DRIVER) -std=gnu99  \
  `$(LIBALLOCS)/tools/allocs-ldflags` \
  -fno-addrsig # HACK but by itself doesn't work... hacked toolsub 'wrapper' to undo -faddrsig that creeps in earlier
export LIBALLOCS # the linker plugin needs this

export META_CC := cc

LDLIBS += -lallocs -ldl
