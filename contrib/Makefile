THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
CONTRIB := $(realpath $(dir $(THIS_MAKEFILE)))

# NOTE all this env.sh amounts to just a different way to do
# ./configure --with-blah=/path/to/blah ?
# ... but we prefer it because it's more compositional:
# we can build an env.sh / config.mk out of others,
# whereas each configure cmd has to specify everything.
# ALSO remember that our configure scripts *do* support the pkg-config-style
# approach of either a .pc file OR the *_{C,LD}FLAGS variables,
# and we're building on that as it lets us supply configure-time stuff
# as environment variables.

# things we need to build:
# - libsystrap
# - dwarfidl
# - libdlbind
# - toolsub
#
# things that just sit here, but we have to set config for:
# - libmallochooks
#
# contrib things that live elsewhere
# - everything in libsystrap/contrib, dwarfidl/contrib
# - cil (in liballocs/tools/lang/c)

# varlist is used to build env.sh (by writing a rule to config.mk)

default: $(CONTRIB)/env.sh config.mk build-libsystrap build-liballocstool \
  build-libdlbind build-cil build-toolsub build-elftin

OLD_CONTRIB := $(CONTRIB)
include config.mk
ifneq ($(OLD_CONTRIB),$(CONTRIB))
$(error config.mk changed CONTRIB)
endif

# ----------------------------libsystrap

.PHONY: build-libsystrap
# HMM. I *think( depending on a config.mk is not enough to depend on the
# completion of a contrib/ build, because we generate the config.mk recursively
# up-front in order to include it. Instead we need to use a build stamp or... maybe
# depending on the env.sh is enough? Not sure I understand the interaction of these
# rules with the subconfigs rules yet.
#
# Redux of what's going wrong:
# from a 'clean' start,
# 'make' dies with missing musl stuff
# BUT
# 'make build-libsystrap' correctly builds it
# 'make libsystrap/contrib/env.sh' correctly builds it.
build-libsystrap: libsystrap/contrib/build.stamp
	$(MAKE) -C libsystrap src lib

# XXX: used to have an env.sh rule here to, but no better than the generic rule?
libsystrap/contrib/config.mk:
	$(MAKE) -C libsystrap/contrib config.mk
libsystrap/contrib/build.stamp: libsystrap/contrib/config.mk libsystrap/contrib/env.sh
	$(MAKE) -C libsystrap/contrib build.stamp

CONFIG_MK += \nLIBRUNT_DIR := $(CONTRIB)/libsystrap/contrib/librunt\n
CONFIG_MK += \nLIBSYSTRAP_DIR := $(CONTRIB)/libsystrap\n
varlist += LIBSYSTRAP_DIR LIBRUNT_DIR
subconfigs += libsystrap/contrib/config.mk

clean::
	$(MAKE) -C libsystrap/contrib clean
	$(MAKE) -C libsystrap clean


# ----------------------------liballocstool
$(CONTRIB)/liballocstool/contrib/config.mk \
liballocstool/contrib/config.mk:
	$(MAKE) -C liballocstool/contrib config.mk
# FIXME: need the 'build.stamp' treatment here too? to ensure that the contrib/ stuff is built.
# TODO:
# change env.sh to config.sh
# always enable building the contrib configs without actually doing the contrib build
# use build.stamp for actually depending on the contrib configs, like with libsystrap
# REMEMBER we are just trying to define the structure for a build-* recipe:
# first build its contrib, then build the thing proper.
# Why does a phony target not work?
liballocstool/config.status: liballocstool/configure

liballocstool/configure: liballocstool/configure.ac
	cd liballocstool && ./autogen.sh

liballocstool/config.status: liballocstool/configure $(CONTRIB)/liballocstool/contrib/env.sh
	cd liballocstool && \
        $(MAKE) -C contrib && \
        . ./contrib/env.sh && \
        ./configure --with-librunt=$(LIBRUNT_DIR)

.PHONY: build-liballocstool
build-liballocstool: liballocstool/config.status
	$(MAKE) -C liballocstool

clean::
	$(MAKE) -C liballocstool/contrib clean
	if test -f liballocstool/Makefile; then $(MAKE) -C liballocstool clean || true; fi # fails if not configured yet
	rm -f liballocstool/config.status

LIBALLOCSTOOL_DIR := $(CONTRIB)/liballocstool
CONFIG_MK += \nLIBALLOCSTOOL_CXXFLAGS := -I$(LIBALLOCSTOOL_DIR)/include
CONFIG_MK += \nLIBALLOCSTOOL_LIBS := -L$(LIBALLOCSTOOL_DIR)/lib -lallocstool
varlist += LIBALLOCSTOOL_CXXFLAGS LIBALLOCSTOOL_LIBS
subconfigs += liballocstool/contrib/config.mk

# ----------------------------libdlbind

build-libdlbind:
	CFLAGS="-I$(LIBRUNT_DIR)/include" $(MAKE) -C libdlbind

CONFIG_MK += \nLIBDLBIND ?= $(CONTRIB)/libdlbind\n
varlist += LIBDLBIND

clean::
	if test -f libdlbind/src/*.o; then $(MAKE) -C libdlbind clean; fi

# ----------------------------cil

.PHONY: build-cil
build-cil: cil.stamp

# PROBLEM: cil's ocamlbuild takes a significant time to re-run even in the
# case where nothing's changed. So use a stamp to run around that.
cil.stamp: cil/Makefile $(shell find cil -name '*.c' -o -name '*.ml' -o -name '*.mli' -o -name '*.in' -o -name '*.mly' )
	$(MAKE) -C cil all install-local && touch $@
cil/Makefile: cil/configure
	cd cil && CC=${ALLOCSCC_CC:-${CC:-cc}} ./configure INSTALL="`which install` -p"

CONFIG_MK += \nCIL_INSTALL ?= $(CONTRIB)/cil/lib\n
varlist += CIL_INSTALL
export CIL_INSTALL

clean::
	$(MAKE) -C cil clean
	rm -f cil.stamp

# ----------------------------toolsub

.PHONY: build-toolsub
build-toolsub: build-cil
	$(MAKE) -C toolsub wrapper-recursive cilpp-recursive  # don't build clang-based cccppp
	$(MAKE) -C toolsub/wrapper/example/constructor-priority-checker dumpconstr
CONFIG_MK += \nTOOLSUB ?= $(CONTRIB)/toolsub\n
varlist += TOOLSUB

clean::
	$(MAKE) -C toolsub/wrapper clean

# ----------------------------elftin

# any librunt will do because we just need relf.h
LIBRUNT ?= $(CONTRIB)/libsystrap/contrib/librunt
# any libsrk31c++ will do because we just need closure.hpp
LIBSRK31CXX_CXXFLAGS ?= -I$(CONTRIB)/liballocstool/contrib/dwarfidl/contrib/libdwarfpp/contrib/libsrk31c++
.PHONY: build-elftin
build-elftin:
	$(MAKE) -C elftin/normrelocs normrelocs
	$(MAKE) -C elftin/abs2und abs2und sym2und
	$(MAKE) -C elftin/dynappend dynappend
	LIBRUNT="$(LIBRUNT)" CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} }${LIBSRK31CXX_CXXFLAGS}" $(MAKE) -C elftin/base-ldplugin
	LIBRUNT="$(LIBRUNT)" CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} }${LIBSRK31CXX_CXXFLAGS}" $(MAKE) -C elftin/xwrap-ldplugin xwrap-ldplugin.so
CONFIG_MK += \nELFTIN ?= $(CONTRIB)/elftin\n
varlist += ELFTIN

clean::
	cd elftin/normrelocs && rm -f normrelocs *.o
	cd elftin/abs2und && rm -f abs2und *.o
	cd elftin/dynappend && rm -f dynappend *.o
	cd elftin/base-ldplugin && rm -f *.so *.o *.a
	cd elftin/xwrap-ldplugin && rm -f *.so *.o

# ----------------------------malloc-hooks

CONFIG_MK += \nLIBMALLOCHOOKS := $(CONTRIB)/libmallochooks\n
varlist += LIBMALLOCHOOKS

# no build or clean targets -- we just pull in source files

# ----------------------------donald

CONFIG_MK += \nDONALD := $(CONTRIB)/donald\n
varlist += DONALD

# no build or clean targets -- we just pull in source files

# ----------------------------config.mk
# If the user nukes a sub-config.mk that our config.mk depends on,
# we'd like to be able to rebuild it. So we include a generic rule
# for rebuilding config.mks.
config.mk: $(subconfigs)
	(printf '%%/config.mk:\n\t$$(MAKE) -C $$* config.mk\n\n'; \
	printf "$(foreach cfg,$(subconfigs),\ninclude $(CONTRIB)/$(cfg))"; \
	printf '$(CONFIG_MK)'; echo) > "$@" || (rm -f "$@"; false)
# env.sh exports some vars
# We put $(CONTRIB)/env.sh and env.sh in the same target because $(CONTRIB) is always realpath'd
# and so when the generic env.sh rule tries to build a fully-qualified env.sh, it matches.
env.sh $(CONTRIB)/env.sh: $(foreach cfg,$(subconfigs),$(dir $(CONTRIB)/$(cfg))env.sh)
	(printf "$(foreach cfg,$(subconfigs),\n. $$(dirname $(CONTRIB)/$(cfg))/env.sh)"; \
	printf '$(foreach var,$(varlist),\nexport $(var)="$($(var))")'; echo )>"$@" || (rm -f "$@"; false)
# Similarly when we make an env.sh, have Make ensure existence of
# its depended-on env.sh too, so that we don't get 'source'-time
# failures of sub-env.sh.
$(foreach cfg,$(subconfigs),$(dir $(CONTRIB)/$(cfg))env.sh): %/env.sh:
	$(MAKE) -C $* env.sh
clean::
	rm -f config.mk env.sh
