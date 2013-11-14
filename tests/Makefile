CFLAGS += -g3 -std=c99 -fno-eliminate-unused-debug-types -O2
CFLAGS += -DUSE_STARTUP_BRK

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

export CFLAGS
export CC := $(realpath $(dir $(THIS_MAKEFILE))/../bin/crunchcc)

cases := $(wildcard [a-z]*)

LIBCRUNCH := $(realpath $(dir $(THIS_MAKEFILE))/../lib/libcrunch.so)
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(LIBCRUNCH)),)
        $(error You must first build libcrunch and link it from ../lib)
endif
endif

run-%:
	$(MAKE) -C "$*" "$*" && ( cd "$*" && LD_PRELOAD=$(LIBCRUNCH) ./$* ); \

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
