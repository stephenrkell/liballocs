CFLAGS += -g3 -std=c99 -fno-eliminate-unused-debug-types -O2
CFLAGS += -DUSE_STARTUP_BRK

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

export CFLAGS

UNIQTYPES_BASE ?= /usr/lib/allocsites
ALLOCSITES_BASE ?= /usr/lib/allocsites

export UNIQTYPES_BASE
export ALLOCSITES_BASE

export CC := $(realpath $(dir $(THIS_MAKEFILE))/../frontend/c/bin/crunchcc)

ifeq ($(CC),)
$(error Could not find crunchcc)
endif

cases := $(wildcard [a-z]*)

LIBCRUNCH := $(realpath $(dir $(THIS_MAKEFILE))/../lib/libcrunch.so)
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(LIBCRUNCH)),)
        $(error You must first build libcrunch and link it from ../lib)
endif
endif

LIBHEAP_INDEX_HOOKS ?= $(realpath $(dir $(THIS_MAKEFILE))/../../libpmirror.hg/lib/libheap_index_fast_hooks.so)

run-%:
	$(MAKE) -C "$*" "$*" && ( cd "$*" && LD_PRELOAD="$(LIBHEAP_INDEX_HOOKS) $(LIBCRUNCH)" ./$* ); \

cleanrun-%: 
	$(MAKE) -C $* -f ../Makefile clean && \
	$(MAKE) run-$*

gdbrun-%: # run the test case with itself as input
	$(MAKE) -C "$*" "$*" && ( cd "$*" && gdb --eval-command "set environment LD_PRELOAD=$(LIBHEAP_INDEX_HOOKS) $(LIBCRUNCH)" --args ./$* ./$* )

gdbcleanrun-%:
	$(MAKE) -C $* -f ../Makefile clean && $(MAKE) gdbrun-$*

clean-%:
	$(MAKE) -C "$*" -f $(realpath $(THIS_MAKEFILE)) clean

default:
	for case in $(cases); do \
            $(MAKE) run-$$case; \
        done

# generic clean rule that we can run from test dirs too (with $(MAKE) -f ../Makefile)
clean: # (delete anything whose name is a prefix of a .c file's and doesn't contain a dot)
	rm -f $(filter-out .,$(patsubst %.c,%,$(shell find -name '*.c')))
	find -name '*.cil.*'  -o -name '*.i' -o -name '*.o' -o -name '*.s' -o -name '*.allocs' | xargs rm -f
