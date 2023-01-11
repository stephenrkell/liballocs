# only for srk's hacky ld.both script
export USE_LD := ld.gold

# for normal people... but note that --push-state isn't supported
LDFLAGS += -fuse-ld=gold

LIBALLOCS_ALLOC_FNS := fail_alloc(Z)p fail_realloc(pZ)p fail_calloc(zZ)p
# HACK: export doesn't work
export LIBALLOCS_ALLOC_FNS

# GAH, commas interact with "-Wl,"

LDFLAGS += $(shell env LIBALLOCS_ALLOC_FNS="$(LIBALLOCS_ALLOC_FNS)" $(LIBALLOCS)/tools/allocs-ldflags)
$(info adding LDFLAGS $(LDFLAGS))

# HACK: use cc directly (setting plugin-hello: CC := doesn't seem to work)
plugin-hello: plugin-hello.o
	/usr/bin/cc -o "$@" $+ $(LDFLAGS) $(LDLIBS)
