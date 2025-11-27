anon-aliases: lib1.o lib2.o lib3.o

lib1.o: CC := cc
lib2.o: CC := cc
lib3.o: CC := cc

# HACK: Force DWARF 4 until v5 is not supported (https://github.com/stephenrkell/liballocs/issues/77)
lib1.o: CFLAGS += -gdwarf-4
lib2.o: CFLAGS += -gdwarf-4
lib3.o: CFLAGS += -gdwarf-4
