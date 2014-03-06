CFLAGS += -g3 -gstrict-dwarf -std=c99 -fno-eliminate-unused-debug-types -O2
CFLAGS += -DUSE_STARTUP_BRK

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

export CFLAGS

UNIQTYPES_BASE ?= /usr/lib/allocsites
ALLOCSITES_BASE ?= /usr/lib/allocsites

export UNIQTYPES_BASE
export ALLOCSITES_BASE

export CC := $(realpath $(dir $(THIS_MAKEFILE))/../frontend/c/bin/crunchcc)
export CFLAGS += -I$(realpath $(dir $(THIS_MAKEFILE)))/../include

ifeq ($(CC),)
$(error Could not find crunchcc)
endif

cases := $(wildcard [-a-z]*)

ifneq ($(LIBCRUNCH_USE_PRELOAD),no)
LIBCRUNCH := $(realpath $(dir $(THIS_MAKEFILE))/../lib/libcrunch_preload.so)
else
LIBCRUNCH := $(realpath $(dir $(THIS_MAKEFILE))/../lib/libcrunch.so)
endif
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(LIBCRUNCH)),)
        $(error You must first build libcrunch{.so,_preload.so} and link them from ../lib)
endif
endif

ifneq ($(LIBCRUNCH_USE_PRELOAD),no)
export PRELOAD := "$(LIBCRUNCH)"
else
LIBHEAP_INDEX_HOOKS ?= $(realpath $(dir $(THIS_MAKEFILE))/../../libpmirror.hg/lib/libheap_index_fast_hooks.so)
# FIXME: do we really need to preload libcrunch in this case?
export PRELOAD := "$(LIBHEAP_INDEX_HOOKS) $(LIBCRUNCH)"
endif

INCLUDE_MK_INC = `if test -e $(dir $(realpath $(THIS_MAKEFILE)))/$*/mk.inc; then /bin/echo -f mk.inc; else true; fi`

default: checkall

checkall: $(patsubst %,checkrun-%,$(cases))

# Most test cases should output a libcrunch summary in which 
# -- zero or more checks passed (trivially or by lazy typing)
# -- zero checks aborted
# -- zero checks failed
checkrun-%:
	@echo "case is $*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	$(MAKE) cleanrun-$* 1>$$out 2>$$err && \
		tail -n6 "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0.* 0.* [0-9]\+$$' >/dev/null || \
		(tail -n20 $$err; false)

# Some cases are special and require only an exit status of zero
checkrun-hello: 
	$(MAKE) cleanrun-hello >/dev/null 2>&1
checkrun-hello-errno: 
	$(MAKE) cleanrun-hello-errno >/dev/null 2>&1
checkrun-hello-qualified-char:
	$(MAKE) cleanrun-hello-qualified-char >/dev/null 2>&1
checkrun-random:
	$(MAKE) cleanrun-random >/dev/null 2>&1
checkrun-sloppy-dumptypes:
	$(MAKE) cleanrun-sloppy-dumptypes >/dev/null 2>&1
checkrun-section-group:
	$(MAKE) cleanrun-section-group >/dev/null 2>&1

_onlyrun-%:
	LD_PRELOAD=$(PRELOAD) ./$*

_onlygdbrun-%:
	gdb --eval-command "set environment LD_PRELOAD=$(PRELOAD)" --args ./$* ./$*

build-%:
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) "$*" 

run-%:
	$(MAKE) build-$* && ( $(MAKE) -C "$*" $(INCLUDE_MK_INC) -f ../Makefile _onlyrun-$* )

cleanbuild-%:
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && \
	$(MAKE) build-$* 

cleanrun-%: 
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && \
	$(MAKE) run-$*

gdbrun-%: # run the test case with itself as input
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) "$*" && ( cd "$*" && $(MAKE) $(INCLUDE_MK_INC) -f ../Makefile _onlygdbrun-$* )

gdbcleanrun-%:
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && $(MAKE) gdbrun-$*

clean-%:
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) -f $(realpath $(THIS_MAKEFILE)) clean

default:
	for case in $(cases); do \
            $(MAKE) run-$$case; \
        done

# generic clean rule that we can run from test dirs too (with $(MAKE) -f ../Makefile)
clean: # (delete anything whose name is a prefix of a .c file's and doesn't contain a dot)
	rm -f $(filter-out .,$(patsubst %.c,%,$(shell find -name '*.c')))
	find -name '*.cil.*'  -o -name '*.i' -o -name '*.o' -o -name '*.s' -o -name '*.allocs' | xargs rm -f
