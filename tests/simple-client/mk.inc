# Thanks to an inline function in the liballocs headers,
# building non-PIC gets us a copy relocation against __liballocs_aborted* in the dummyweaks library.
# These symbols are protected, so that is clearly not going to work.
# I don't think copy-relocating them is a good idea.
# Just ensure we build PIC?
export CFLAGS += -pie -fPIC
export LDLIBS += -lallocs
