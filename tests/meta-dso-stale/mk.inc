THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
here := $(dir $(realpath $(THIS_MAKEFILE)))

meta-dso-stale: meta-dso-stale.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -o $@
	$(MAKE) -f $(LIBALLOCS)/tools/Makefile.meta META_CC=cc \
	    META_CFLAGS="$(META_CFLAGS) -DLIBALLOCS_META_ABI_VERSION_OVERRIDE=0" \
	    -W $(LIBALLOCS)/tools/meta-abi.c $(META_BASE)$(here)meta-dso-stale-meta.so
