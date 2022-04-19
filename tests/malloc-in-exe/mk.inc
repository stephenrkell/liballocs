malloc-in-exe: malloc-in-exe.o dlmalloc.o

dlmalloc.o: CFLAGS += -std=gnu99 -D_DEFAULT_SOURCE

malloc-in-exe: LDLIBS += -lallocs
#-Wl,test.lds \
