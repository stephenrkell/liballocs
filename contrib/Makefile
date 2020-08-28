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
# - toolsub -- FIXME: build this here once we move cil from tools/... to contrib/
#
# things that just sit here, but we have to set config for:
# - libmallochooks
#
# contrib things that live elsewhere
# - everything in libsystrap/contrib, dwarfidl/contrib
# - cil (in liballocs/tools/lang/c)

# varlist is used to build env.sh (by writing a rule to config.mk)

default: $(CONTRIB)/env.sh config.mk build-libsystrap build-liballocstool build-libdlbind

OLD_CONTRIB := $(CONTRIB)
include config.mk
ifneq ($(OLD_CONTRIB),$(CONTRIB))
$(error config.mk changed CONTRIB)
endif

# ----------------------------libsystrap

.PHONY: build-libsystrap
build-libsystrap: libsystrap/contrib/config.mk
	$(MAKE) -C libsystrap

libsystrap/contrib/config.mk $(CONTRIB)/libsystrap/contrib/env.sh:
	$(MAKE) -C libsystrap/contrib default config.mk

CONFIG_MK += \nLIBRUNT_DIR := $(CONTRIB)/libsystrap/contrib/librunt\n
CONFIG_MK += \nLIBSYSTRAP_DIR := $(CONTRIB)/libsystrap\n
varlist += LIBSYSTRAP_DIR LIBRUNT_DIR
subconfigs += libsystrap/contrib/config.mk

# ----------------------------liballocstool
liballocstool/contrib/config.mk \
$(CONTRIB)/liballocstool/contrib/env.sh \
$(CONTRIB)/liballocstool/contrib/config.mk:
	$(MAKE) -C liballocstool/contrib

liballocstool/config.status: liballocstool/configure

liballocstool/configure: liballocstool/configure.ac
	cd liballocstool && ./autogen.sh

# HACK: this mess is because dwarfidl is not in contrib/ of liballocstool.
# (And also because the config script does not take a --with-foo= for
# these other libs.) Was there a reason not to put dwarfidl under liballocstool?
# sysfoot uses liballocstool and also syscall-interfaces, so we'd want to
# share their dwarfidl. I think this is doable though.
liballocstool/config.status: liballocstool/configure $(CONTRIB)/liballocstool/contrib/env.sh
	cd liballocstool && \
        . ./contrib/env.sh && \
        ./configure --with-librunt=$(LIBRUNT_DIR)

.PHONY: build-liballocstool
build-liballocstool: liballocstool/config.status
	$(MAKE) -C liballocstool

clean::
	if test -f liballocstool/Makefile; then $(MAKE) -C liballocstool clean; fi

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

# ----------------------------malloc-hooks

CONFIG_MK += \nLIBMALLOCHOOKS := $(CONTRIB)/libmallochooks\n
varlist += LIBMALLOCHOOKS

# ----------------------------config.mk
# If the user nukes a sub-config.mk that our config.mk depends on,
# we'd like to be able to rebuild it. So we include a generic rule
# for rebuilding config.mks.
config.mk: $(subconfigs)
	(printf '%%/config.mk:\n\t$$(MAKE) -C $$* config.mk\n\n'; \
	printf "$(foreach cfg,$(subconfigs),\ninclude $(CONTRIB)/$(cfg))"; \
	printf '$(CONFIG_MK)'; echo) > "$@" || (rm -f "$@"; false)
# env.sh exports some vars
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
