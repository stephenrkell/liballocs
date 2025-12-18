THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
# lib-test is a plain old C program, not allocscc'd, and it
# dlopens liballocs (test build) to run its self-test constructors.
export CC := cc
# HACK: force DWARF 4 until v5 is supported (https://github.com/stephenrkell/liballocs/issues/77)
# This is necessary only because we use plain CC, not allocscc
export CFLAGS := -fPIC -O0 -g3 -DTEST -gdwarf-4
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))../..)
# One exception: we must avoid the ld.so  hole, so use allocsld for that.
export LDFLAGS := -Wl,--dynamic-linker,$(srcroot)/allocsld/allocsld.so
export LDLIBS := $(srcroot)/lib/interp-pad.o -ldl
# Another exception: we may want to load a meta-object.
real_obj :=             $(dir $(realpath $(THIS_MAKEFILE)))lib-test
meta_obj := $(META_BASE)$(dir $(realpath $(THIS_MAKEFILE)))lib-test-meta.so
META_CC := cc
export META_CC
_onlyrun-lib-test _onlygdbrun-lib-test: $(meta_obj)
$(info goals $(MAKECMDGOALS))
export LIBALLOCS_BUILD := $(srcroot)/build/test/liballocs_preload.so
export LD_PRELOAD := # empty
export PRELOAD := # empty
export LIBALLOCS_USE_PRELOAD := no

lib-test: $(LIBALLOCS_BUILD)

$(LIBALLOCS_BUILD):
	$(MAKE) -C $(srcroot) TEST=1

$(meta_obj): $(real_obj)
	$(MAKE) -f $(srcroot)/tools/Makefile.meta $@
