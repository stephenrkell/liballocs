# only for srk's hacky ld.both script
export USE_LD := ld.gold

# for normal people... but note that --push-state isn't supported
LDFLAGS += -fuse-ld=gold 

# actually use the plugin, yes
LDFLAGS += -Wl,-plugin,$(LIBALLOCS)/tools/gold-plugin.so

export LIBALLOCS_ALLOC_FNS := fail_alloc(Z)p

# HACK: use cc directly (setting plugin-hello: CC := doesn't seem to work)
plugin-hello: plugin-hello.o
	/usr/bin/cc -o "$@" $+ $(LDFLAGS) $(LDLIBS)
