cases ?= $(basename $(wildcard [a-z]*.[ch]))

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
LIBALLOCS_BASE := $(realpath $(dir $(THIS_MAKEFILE))/../..)
-include $(LIBALLOCS_BASE)/config.mk

# FIXME: this is repetitive w.r.t. liballocs core build flags
CFLAGS += -I$(LIBALLOCS_BASE)/include -I$(LIBRUNT)/include -I$(LIBSYSTRAP)

CFLAGS += -g -std=c11 -D_GNU_SOURCE -save-temps
# for metavec's test case to work, it needs to be able to find "main" in dynsym
LDFLAGS += -Wl,--export-dynamic

# FIXME: this is fine for a single-file unit test, but hwat about unit
# tests that need other stuff from liballocs to work properly? Maybe
# they're not unit tests, by definition. Still, it may make sense to unify
# this with the existing approach to testing the mmap allocator. That
# uses the liballocs_test.so: test cases run in its constructor.

.PHONY: build-% run-% cleanbuild-% gdbrun-% gdbcleanrun-% clean-%
build-%: %
%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNIT_TEST -o $@ $< $(LDFLAGS) $(LDLIBS)
%: %.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNIT_TEST -o $@ -x c $< -x none  $(LDFLAGS) $(LDLIBS)

default:
	for case in $(cases); do \
            $(MAKE) run-$$case; \
        done

run-%: %
	./$*

clean-%:
	rm -f $* $*.o $*.s

cleanrun-%:
	$(MAKE) clean-$*
	$(MAKE) run-$*
