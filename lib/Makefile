THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
SRCROOT := $(realpath $(dir $(THIS_MAKEFILE))/..)

default: all

SYMLINKS := liballocs_preload.a liballocs_preload.so liballocs_dummyweaks.o

all: $(SYMLINKS)

$(SYMLINKS): %: $(SRCROOT)/src/%
	ln -sf "$<" "$@"
