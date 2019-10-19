malloc-in-exe: malloc-in-exe.o dlmalloc.o
malloc-in-exe: LDFLAGS += \
-Wl,--wrap,__real_malloc \
-Wl,--wrap,__real_calloc \
-Wl,--wrap,__real_free \
-Wl,--wrap,__real_realloc \
-Wl,--wrap,__real_memalign

dlmalloc.o: CFLAGS += -std=gnu99

malloc-in-exe: LDLIBS += -lallocs
#-Wl,test.lds \
