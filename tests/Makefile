THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
-include $(dir $(THIS_MAKEFILE))/../config.mk

CFLAGS += -g3 -gstrict-dwarf -std=c99 -fno-eliminate-unused-debug-types -Wl,-q -O2 -save-temps

ifneq ($(USE_FAKE_LIBUNWIND),)
CFLAGS += -DUSE_FAKE_LIBUNWIND=1
else
LDLIBS += -lunwind-x86_64 -lunwind
endif

UNIQTYPES_BASE ?= /usr/lib/meta
META_BASE ?= /usr/lib/meta

export UNIQTYPES_BASE
export META_BASE

CC := $(realpath $(dir $(THIS_MAKEFILE))/../tools/lang/c/bin/allocscc)
CFLAGS += -I$(realpath $(dir $(THIS_MAKEFILE)))/../include
LDFLAGS += -L$(realpath $(dir $(THIS_MAKEFILE)))/../lib
LDFLAGS += -L$(realpath $(dir $(THIS_MAKEFILE)))/../src

# HMM -- this is causing us to re-add the +='d stuff in each recursive make.
# can we get away without this?
export CC
export CFLAGS
export LDFLAGS
export LDLIBS

ifeq ($(CC),)
$(error Could not find allocscc)
endif

cases := $(sort $(wildcard [-a-z]*))

LIBALLOCS := $(realpath $(dir $(THIS_MAKEFILE))/..)
export LIBALLOCS

ifneq ($(LIBALLOCS_USE_PRELOAD),no)
LIBALLOCS_LIB := $(realpath $(dir $(THIS_MAKEFILE))/../lib/liballocs_preload.so)
else
LIBALLOCS_LIB := $(realpath $(dir $(THIS_MAKEFILE))/../lib/liballocs.so)
endif
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(LIBALLOCS_LIB)),)
        $(error You must first build liballocs{.so,_preload.so} and link them from ../lib)
endif
endif

ifneq ($(LIBALLOCS_USE_PRELOAD),no)
export PRELOAD := "$(LIBALLOCS_LIB)"
endif

INCLUDE_MK_INC = `if test -e $(dir $(realpath $(THIS_MAKEFILE)))/$*/mk.inc; then /bin/echo -f mk.inc; else true; fi`

default: checkall

checkall: $(patsubst %,checkrun-%,$(cases))

# Some cases are expected to fail
checkrun-fail-%:
	@echo "expected-fail case is fail-$*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	$(MAKE) cleanrun-fail-$* 1>$$out 2>$$err && \
		tail -n6 "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0\+.* [1-9][0-9]*.* 0\+$$' >/dev/null || \
		(tail -n20 $$err; false)
# special: this failing case aborts, for now
checkrun-fail-alloca-clang:
	@echo "expected-fail case is fail-alloca-clang" && \
		out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
		err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
		! $(MAKE) cleanrun-fail-alloca-clang 1>$$out 2>$$err

# Some cases are expected to abort
checkrun-abort-%:
	@echo "expected-fail case is abort-$*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	if $(MAKE) cleanrun-abort-$* 1>$$out 2>$$err; then false; else true; fi

# Most test cases should output a liballocs summary in which 
# -- zero queries aborted
checkrun-%:
	@echo "case is $*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	$(MAKE) cleanrun-$* 1>$$out 2>$$err && \
		tail -n6 "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0=\+$$' >/dev/null || \
		(tail -n20 $$err; false)

# disabled cases
checkrun-plugin-hello:
	true # disabled plugin-hello while expected to fail
checkrun-lib-test:
	true # currently fails, see https://github.com/stephenrkell/liballocs/issues/38
checkrun-uniqtype-make-precise:
	true # currently fails, see https://github.com/stephenrkell/liballocs/issues/39
# Some cases are special and require only an exit status of zero
checkrun-stack-walk:
	$(MAKE) cleanrun-stack-walk >/dev/null 2>&1
checkrun-no-unbind-self:
	$(MAKE) cleanrun-no-unbind-self >/dev/null 2>&1
checkrun-sloppy-dumptypes:
	$(MAKE) cleanrun-sloppy-dumptypes >/dev/null 2>&1
checkrun-section-group:
	$(MAKE) cleanrun-section-group >/dev/null 2>&1
checkrun-simple-multi-alloc:
	$(MAKE) cleanrun-simple-multi-alloc >/dev/null 2>&1
checkrun-simple-client:
	$(MAKE) cleanrun-simple-client >/dev/null 2>&1
checkrun-nopreload-alloca:
	$(MAKE) cleanrun-nopreload-alloca >/dev/null 2>&1
checkrun-relf-auxv-dynamic:
	$(MAKE) cleanrun-relf-auxv-dynamic >/dev/null 2>&1
checkrun-relf-auxv-static:
	$(MAKE) cleanrun-relf-auxv-static >/dev/null 2>&1
# checkrun-uniqtype-make-precise:
# 	$(MAKE) cleanrun-uniqtype-make-precise >/dev/null 2>&1
# checkrun-lib-test:
# 	$(MAKE) cleanrun-lib-test >/dev/null 2>&1
checkrun-forward-decls:
	$(MAKE) cleanrun-forward-decls >/dev/null 2>&1

_onlyrun-nopreload-%:
	./nopreload-$*

_onlygdbrun-nopreload-%:
	gdb --args ./nopreload-$* ./nopreload-$*

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
	find -name '*.cil.*' -o -name '*.i' -o -name '*.o' -o \
	     -name '*.s' -o -name '*.allocs' -o -name '*.so' -o \
	     -name '*.allocstubs.c' -o -name '*.fixuplog' | xargs rm -f
