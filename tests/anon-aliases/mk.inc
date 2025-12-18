anon-aliases: lib1.o lib2.o lib3.o

lib1.o lib2.o lib3.o: CC := cc

# HACK: force DWARF 4 until v5 is supported by the tools (https://github.com/stephenrkell/liballocs/issues/77)
# That this is only necessary because we use plain cc, not allocscc
lib1.o lib2.o lib3.o: CFLAGS += -gdwarf-4
