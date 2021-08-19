THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
SRCROOT := $(realpath $(dir $(THIS_MAKEFILE))/..)

default: all

SYMLINKS := liballocs_nonshared.a liballocs_preload.a liballocs_preload.so \
    liballocs_dummyweaks.o liballocs_dummyweaks.so liballocs.a \
    liballocs.so allocsld.so

# Now that we build in '$(SRCROOT)/build/<outdir>', where <outdir> might
# be 'opt' or 'debug', we have a problem -- which one do we symlink?
# The answer is that we symlink the outdir, then make our symlinks point
# under there.
ifneq ($(TEST),)
outdir := debug
else
ifneq ($(DEBUG),)
outdir := debug
else
outdir := opt
endif
endif

all: outdir $(SYMLINKS) liballocs_systrap.o

ifneq ($(notdir $(shell readlink outdir)),$(outdir))
.PHONY: outdir
endif
outdir:
	rm -f outdir
	ln -sf ../build/$(outdir) $@

$(filter-out liballocs.so allocsld.so,$(SYMLINKS)): %: $(SRCROOT)/build/$(outdir)/%
	ln -sf outdir/$(notdir $<) "$@"

# the liballocs.so file lives in the srcdir
liballocs.so:
	ln -sf "$(SRCROOT)"/src/liballocs.so $@

# allocsld.so lives in the allocsld dir
allocsld.so:
	ln -sf "$(SRCROOT)"/allocsld/$@ $@

# the systrap one has a different name
# We export this separately because libcrunch uses it, even in its
# stubs (dummyweaks) objects, which wrap __liballocs_nudge_mmap.
# I think a better fix would be to have libcrunch pick up that
# function from liballocs.a, but that may be fiddly (FIXME), e.g.
# requiring one-function-per-object or --gc-sections.
liballocs_systrap.o: $(SRCROOT)/build/$(outdir)/systrap.o
	ln -sf outdir/$(notdir $<) "$@"

clean:
	rm -f outdir $(SYMLINKS) liballocs_systrap.o liballocs.so
