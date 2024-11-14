# see note in simple-client/mk.inc... for clients we need to be PIC
# to avoid copy reloc problems
export CFLAGS += -pie -fPIC
export LDLIBS += -lallocs
