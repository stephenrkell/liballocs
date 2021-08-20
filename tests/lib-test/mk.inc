# lib-test is a plain old C program, not allocscc'd, and it
# dlopens liballocs (test build) to run its self-test constructors.
export CC := cc
export CFLAGS := -fPIC -O0 -g3 -DTEST
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))../..)
# One exception: we must avoid the ld.so  hole, so use allocsld for that.
export LDFLAGS := -Wl,--dynamic-linker,$(srcroot)/allocsld/allocsld.so
export LDLIBS := $(srcroot)/lib/interp-pad.o -ldl
export LIBALLOCS_BUILD := $(srcroot)/build/test/liballocs_preload.so
export LD_PRELOAD := # empty
export PRELOAD := # empty
export LIBALLOCS_USE_PRELOAD := no

lib-test: $(LIBALLOCS_BUILD)

$(LIBALLOCS_BUILD):
	$(MAKE) -C $(srcroot) TEST=1
