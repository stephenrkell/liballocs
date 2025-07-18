$(info Initially CFLAGS is $(CFLAGS) and CPPFLAGS is $(CPPFLAGS))
# How can we stop our CFLAGS multiplying up as we recursively make?
# If we use CPPFLAGS at least it's maybe not exported. Possibly we
# should avoid recursive make (and try to merge this file with
# libcrunch's)?
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
-include $(dir $(THIS_MAKEFILE))/../config.mk

# tell allocscc which C compiler to use -- TEST / FIXME
#export ALLOCSCC_CC := clang-13
#export CC_IS_CLANG := 1

CFLAGS += -g3 -gstrict-dwarf -std=c99 -fno-eliminate-unused-debug-types
CFLAGS += -Wl,-q             # FIXME: I think this is no longer needed
ifeq ($(TEST_OPT_LEVEL),)
CFLAGS += -O2                # 'normal'...
else
CFLAGS += -O$(TEST_OPT_LEVEL) # ... but sometimes we want to override
endif
CFLAGS += -save-temps        # helps debugging

# HACK while LTO is broken
CFLAGS += -fno-lto
LDFLAGS += -fno-lto

# HACK: config.mk generates our CPPFLAGS (not CFLAGS)
# for mallochooks, liballocstool and librunt; and
# gold-plugin needs them to get the liballocstool headers
META_CFLAGS += $(CPPFLAGS)
export META_CFLAGS

ifneq ($(USE_FAKE_LIBUNWIND),)
CFLAGS += -DUSE_FAKE_LIBUNWIND=1
else
LDLIBS += -lunwind-x86_64 -lunwind
endif

UNIQTYPES_BASE ?= /usr/lib/meta
META_BASE ?= /usr/lib/meta
LIBALLOCS ?= $(dir $(realpath $(dir $(THIS_MAKEFILE))/..
LIBALLOCS_BUILD ?= $(dir $(realpath $(dir $(THIS_MAKEFILE))/../lib/liballocs_preload.so))

export UNIQTYPES_BASE
export META_BASE
export LIBALLOCS
export LIBALLOCS_BUILD
# these are HACKs! Need more robust liballocs interface
export LIBRUNT # needed by stubgen.h in allocscompilerwrapper.py
export ELFTIN # needed by allocscompilerwrapper.py
export TOOLSUB

CC := $(realpath $(dir $(THIS_MAKEFILE))/../tools/lang/c/bin/allocscc)
#CC := cc
META_CC := cc
#CFLAGS += $(shell $(realpath $(dir $(THIS_MAKEFILE)))/../tools/allocs-cflags)
CFLAGS += -I$(realpath $(dir $(THIS_MAKEFILE)))/../include
# HACK: liballocs headers now also depend on librunt headers
$(info appending $(filter %,$(CPPFLAGS)))
CFLAGS += $(filter %,$(CPPFLAGS))
#LDFLAGS += $(shell $(realpath $(dir $(THIS_MAKEFILE)))/../tools/allocs-ldflags)
LDFLAGS += -L$(realpath $(dir $(THIS_MAKEFILE)))/../lib
LDFLAGS += -L$(realpath $(dir $(THIS_MAKEFILE)))/../src

GDB ?= gdb
RR ?= rr

# HMM -- this is causing us to re-add the +='d stuff in each recursive make.
# can we get away without this?
export CC
export CFLAGS
export LDFLAGS
export LDLIBS

ifeq ($(CC),)
$(error Could not find allocscc)
endif

cases := $(filter-out unit-tests,$(sort $(wildcard [-a-z]*)))

LIBALLOCS := $(realpath $(dir $(THIS_MAKEFILE))/..)
export LIBALLOCS

ifneq ($(LIBALLOCS_USE_PRELOAD),no)
LIBALLOCS_LIB := $(realpath $(dir $(THIS_MAKEFILE))/../lib/liballocs_preload.so)
else
LIBALLOCS_LIB := $(realpath $(dir $(THIS_MAKEFILE))/../lib/liballocs.so)
endif
export LIBALLOCS_LIB
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(LIBALLOCS_LIB)),)
        $(error You must first build liballocs{.so,_preload.so} and link them from ../lib)
endif
endif

ifneq ($(LIBALLOCS_USE_PRELOAD),no)
export PRELOAD := "$(LIBALLOCS_LIB)"
endif

INCLUDE_MK_INC = `if test -e $(dir $(realpath $(THIS_MAKEFILE)))/$*/mk.inc; then printf "%s %s" -f mk.inc; else true; fi`

default: checkall

checkall: $(patsubst %,checkrun-%,$(cases))

define set_out_err
printf "%-20s\t" "$(1)" && out=$$(mktemp) && err=$$(mktemp) && printf '\texpected: %-10s\t' "$(2)"
endef
dollar := $$
define fail_action_escaped
{ echo "FAIL$$(dollar){status:+ (exit status $$(dollar){status})}; out $$(dollar)out, err $$(dollar)err"; \
(if [ -e $$(dollar)err ]; then tail -n20 $$(dollar)err; fi); }
endef
define fail_action
{ echo "FAIL$${status:+ ($${status})}"; \
(tail -n20 $$err; false); }
endef
define success_action
echo 'PASS'
endef
# Some cases are expected to fail
checkrun-fail-%:
	@$(call set_out_err,fail-$*,fail) && \
	$(MAKE) cleanrun-fail-$* 1>$$out 2>$$err && \
		sed -n '/liballocs summary/,/^========/ p' "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0\+.* [1-9][0-9]*.* 0\+$$' >/dev/null && \
		$(success_action) || \
		$(fail_action)

# Some cases are expected to abort
checkrun-abort-%:
	@$(call set_out_err,abort-$*,abort) && \
	if $(MAKE) cleanrun-abort-$* 1>$$out 2>$$err; then $(fail_action); else $(success_action); fi

# Most test cases should output a liballocs summary in which
# -- zero queries aborted (the last four counts in the summary, followed by '===='...)
checkrun-%:
	@$(call set_out_err,$*,zero-aborts) && \
	$(MAKE) cleanrun-$* 1>$$out 2>$$err && \
		sed -n '/liballocs summary/,/^========/ p' "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0=\+$$' >/dev/null && $(success_action) || \
		$(fail_action)

# disabled cases
checkrun-ld-so-malloc:
	true # disabled ld-so-malloc while DWARF 5-using ld.so is not introspectable

# Some cases are special and require only to build OK
checkrun-allocsld-as-cmd:
	@/bin/echo -ne "$*\tbuild only" && \
	$(MAKE) cleanbuild-allocsld-as-cmd >/dev/null 2>&1 && $(success_action) || $(fail_action)

# Some cases are special and require only an exit status of zero
# NOTE: this define is going to be eval'd, so we need two layers of escaping
define exit-zero-case
checkrun-$(1):
	@$$(call set_out_err,$(1),exit-zero) && \
	$(MAKE) cleanrun-$(1) >$$(dollar)out 2>$$(dollar)err; status=$$(dollar)?; if ! [ $$(dollar)status -eq 0 ]; then $(fail_action_escaped); else $(success_action); fi; exit $$(dollar)status
endef
define exit-zero-case-names
allocsld-as-ldso \
anon-aliases \
stack-walk \
no-unbind-self \
sloppy-dumptypes \
section-group \
simple-multi-alloc \
simple-client \
nopreload-alloca \
uniqtype-make-precise \
lib-test \
forward-decls \
metavec-layout \
packed-seq-walk \
hello-via-wrapper \
hello-environ \
ifunc
endef
$(foreach case,$(exit-zero-case-names),$(eval $(call exit-zero-case,$(case))))
# disabled above:
# ld-so-malloc \

_onlyrun-nopreload-%:
	./nopreload-$*

_onlygdbrun-nopreload-%:
	$(GDB) --args ./nopreload-$* ./nopreload-$*

_onlyrun-%:
	LD_PRELOAD=$(PRELOAD) ./$*

_onlygdbrun-%:
	$(GDB) --symbols=./$* --args env LD_PRELOAD="$(PRELOAD)" ./$* ./$*

_onlyrrrun-%:
	$(RR) record env LD_PRELOAD="$(PRELOAD)" ./$* ./$*

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

rrrun-%: # run the test case with itself as input
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) "$*" && ( cd "$*" && $(MAKE) $(INCLUDE_MK_INC) -f ../Makefile _onlyrrrun-$* )

gdbcleanrun-%:
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && $(MAKE) gdbrun-$*

rrcleanrun-%:
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && $(MAKE) rrrun-$*

clean-%:
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) -f $(realpath $(THIS_MAKEFILE)) clean

default:
	for case in $(cases); do \
            $(MAKE) run-$$case; \
        done

# generic clean rule that we can run from test dirs too (with $(MAKE) -f ../Makefile)
clean: # (delete anything whose name is a prefix of a .c file's and doesn't contain a dot)
	rm -f $(filter-out .,$(foreach pat,% %.o %.allocstubs.o %.allocstubs.c %.linked.o %.s %.i %.cil.s %.cil.i,$(patsubst %.c,$(pat),$(shell find -name '*.c'))))
	find -name '*.cil.c' -o \
	     -name '*.allocs' -o -name '*.so' -o -name '*.ltrans.out' -o \
	     -name '*.allocstubs.c' -o -name '*.fixuplog' | xargs rm -f

.PHONY: unit-tests
unit-tests:
	$(MAKE) -C unit-tests
