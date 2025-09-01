# For use of gold for now. (WHY? at one time, bfd's plugin impl
# did not like us, but perhaps now it does?)
# only for srk's hacky ld.both script
export USE_LD := ld.gold
# for normal people... but note that --push-state isn't supported by gold
LDFLAGS += -fuse-ld=gold

# To test the env var / plugin arg interface, our .c file contains
# some bogus always-failing allocator functions. Declare these here.
# Note that the vanilla/standard alloc functions are not being declared.
# I think doing so currently fails the link (FIXME).
LIBALLOCS_ALLOC_FNS := fail_alloc(Z)p fail_realloc(pZ)p fail_calloc(zZ)p

# HACK: export doesn't take effect for $(shell ...)
LDFLAGS += $(shell env LIBALLOCS_ALLOC_FNS="$(LIBALLOCS_ALLOC_FNS)" \
  $(LIBALLOCS)/tools/allocs-ldflags)
# Quoting problems: we use the -ldflags scripts like `pkg-config', e.g.
# CFLAGS += `/path/to/allocs-cflags`
# ... but any embedded whitespace will mean that this yields multiple words
# unintentionally. Putting quoting in the output of allocs-cflags doesn't help!
# What saves us is how 'make' assembles even multi-word vars into a command...
# allocs-cflags uses shell escaping in the output of allocs-cflags, so the
# right thing happens when CFLAGS is expanded into a command later... I think.

# debugging the above
#$(info adding LDFLAGS $(LDFLAGS))

# We don't want allocscc here, so just use plain cc
plugin-hello: CC := cc
plugin-hello: plugin-hello.o
