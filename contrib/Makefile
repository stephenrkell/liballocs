THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
CONTRIB_ROOT := $(realpath $(dir $(THIS_MAKEFILE)))

# things we need to build:
# - libc++fileno
# - libsrk31c++
# - libdwarfpp
# - libcxxgen
# - libantlr3cxx
# - trap-syscalls's own contrib      (this needs antlr, I think)
# - trap-syscalls/libsystrap    (*not* the main trap-syscalls, which has other deps...)
# - dwarfidl (ignore its contrib build script)
# - binutils-gdb?
#
# things that just sit here, but we have to set config for:
# - m4ntlr
# - libmallochooks
#
# contrib things that live elsewhere
# - everything in trap-syscalls/contrib
# - cil (in liballocs/tools/lang/c)

default: config.mk trap-syscalls/libsystrap/libsystrap.a \
build-dwarfidl build-libdwarfpp build-libcxxgen build-libsrk31c++ build-libc++fileno \
build-libantlr3c++ build-libantlr3c

.PHONY: clean default

# ----------------------------antlr things
antlr-3.4.tar.gz:
	wget http://www.antlr3.org/download/antlr-3.4.tar.gz

libantlr3c-3.4/configure: antlr-3.4.tar.gz
	mkdir -p libantlr3c-3.4 && cd libantlr3c-3.4 && tar --strip-components=3 -k -xvzf "$(CONTRIB_ROOT)/$<" antlr-3.4/runtime/C
	cd libantlr3c-3.4 && patch -p1 < "$(CONTRIB_ROOT)"/libantlr3c-3.4-getparent-allow-null.patch
	cd libantlr3c-3.4 && aclocal && \
                autoconf && \
                autoheader && \
                libtoolize && \
                automake --add-missing && \
                automake
	chmod +x "$@"
	touch "$@"

antlr-3.4-complete.jar: antlr-3.4.tar.gz
	tar --strip-components=2 -k -xvzf "$(CONTRIB_ROOT)/$<" antlr-3.4/lib/antlr-3.4-complete.jar

.PHONY: build-antlr
libantlr3c-3.4/Makefile: libantlr3c-3.4/configure
	cd libantlr3c-3.4 && ./configure --enable-64bit

.PHONY: build-libantlr3c
build-libantlr3c: libantlr3c-3.4/Makefile
	$(MAKE) -C libantlr3c-3.4

clean::
	rm -f antlr-3.4.tar.gz
	rm -rf libantlr3c-3.4

CONFIG_MK += "\\nANTLR3C_DIR := $(realpath $(CONTRIB_ROOT)/libantlr3c-3.4)\#"
CONFIG_MK += "\\nCXXFLAGS += -I\$$\(ANTLR3C_DIR\)/include"

# ----------------------------other libs that are autotools'd
# ----------------------------libc++fileno

build-libc++fileno: libc++fileno/config.status
	$(MAKE) -C libc++fileno

libc++fileno/config.status:
	cd libc++fileno && aclocal && \
                autoconf && \
                libtoolize && \
                automake --add-missing && \
                automake && \
                ./configure --prefix=$(CONTRIB_ROOT)/usr

clean::
	$(MAKE) -C libc++fileno clean

CONFIG_MK += "\\nCXXFLAGS += -I$(CONTRIB_ROOT)/libc++fileno/include"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/libc++fileno/lib -Wl,-rpath,$(CONTRIB_ROOT)/libc++fileno/lib"

# ----------------------------libsrk31c++

.PHONY: build-libsrk31c++
build-libsrk31c++: libsrk31c++/config.status build-libc++fileno
	$(MAKE) -C libsrk31c++

libsrk31c++/config.status:
	cd libsrk31c++ && ./autogen.sh && \
	LIBCXXFILENO_CXXFLAGS="-I$(CONTRIB_ROOT)/libc++fileno/include" \
	LIBCXXFILENO_LIBS="-L$(CONTRIB_ROOT)/libc++fileno/lib -Wl,-rpath,$(CONTRIB_ROOT)/libc++fileno/lib" \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr

clean::
	$(MAKE) -C libsrk31c++ clean

CONFIG_MK += "\\nCXXFLAGS += -I$(CONTRIB_ROOT)/libsrk31c++/include"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/libsrk31c++/lib -Wl,-rpath,$(CONTRIB_ROOT)/libsrk31c++/lib"

# ----------------------------libdwarfpp

libdwarfpp/config.status:
	cd libdwarfpp && ./autogen.sh && \
	LIBCXXFILENO_CXXFLAGS="-I$(CONTRIB_ROOT)/libc++fileno/include" \
	LIBCXXFILENO_LIBS="-L$(CONTRIB_ROOT)/libc++fileno/lib -Wl,-rpath,$(CONTRIB_ROOT)/libc++fileno/lib" \
	LIBSRK31CXX_CXXFLAGS="-I$(CONTRIB_ROOT)/libsrk31c++/include" \
	LIBSRK31CXX_LIBS="-L$(CONTRIB_ROOT)/libsrk31c++/lib -Wl,-rpath,$(CONTRIB_ROOT)/libsrk31c++/lib" \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr

.PHONY: build-libdwarfpp
build-libdwarfpp: libdwarfpp/config.status build-libc++fileno build-libsrk31c++
	$(MAKE) -C libdwarfpp

clean::
	$(MAKE) -C libdwarfpp clean

CONFIG_MK += "\\nCXXFLAGS += -I$(CONTRIB_ROOT)/libdwarfpp/include"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/libdwarfpp/lib -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/lib"

# ----------------------------libcxxgen

libcxxgen/config.status:
	cd libcxxgen &&  aclocal && \
                autoconf && \
                libtoolize && \
                automake --add-missing && \
                automake &&  \
	LIBCXXFILENO_CXXFLAGS="-I$(CONTRIB_ROOT)/libc++fileno/include" \
	LIBCXXFILENO_LIBS="-L$(CONTRIB_ROOT)/libc++fileno/lib -Wl,-rpath,$(CONTRIB_ROOT)/libc++fileno/lib" \
	LIBSRK31CXX_CXXFLAGS="-I$(CONTRIB_ROOT)/libsrk31c++/include" \
	LIBSRK31CXX_LIBS="-L$(CONTRIB_ROOT)/libsrk31c++/lib -Wl,-rpath,$(CONTRIB_ROOT)/libsrk31c++/lib" \
	LIBDWARFPP_CXXFLAGS=-I$(CONTRIB_ROOT)/libdwarfpp/include \
	LIBDWARFPP_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/lib -ldwarfpp" \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr

.PHONY: build-libcxxgen
build-libcxxgen: libcxxgen/config.status build-libdwarfpp build-libsrk31c++ build-libc++fileno
	$(MAKE) -C libcxxgen

clean::
	$(MAKE) -C libcxxgen clean

CONFIG_MK += "\\nCXXFLAGS += -I$(CONTRIB_ROOT)/libcxxgen/include"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/libcxxgen/lib -Wl,-rpath,$(CONTRIB_ROOT)/libcxxgen/lib"

# ----------------------------libantlr3cxx

libantlr3c++/config.status:
	cd libantlr3c++ && ./autogen.sh && \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr

.PHONY: build-libantlr3cxx
build-libantlr3c++: libantlr3c++/config.status
	$(MAKE) -C libantlr3c++

clean::
	$(MAKE) -C libantlr3c++ clean

CONFIG_MK += "\\nCXXFLAGS += -I$(CONTRIB_ROOT)/libantlr3c++/include"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/libantlr3c++/lib -Wl,-rpath,$(CONTRIB_ROOT)/libantlr3c++/lib"

# ----------------------------dwarfidl

dwarfidl/config.status:
	cd dwarfidl && ./autogen.sh && \
	LIBCXXFILENO_CXXFLAGS=-I$(CONTRIB_ROOT)/libc++fileno/include \
	LIBCXXFILENO_LIBS="-L$(CONTRIB_ROOT)/libc++fileno/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libc++fileno -lc++fileno" \
	LIBSRK31CXX_CXXFLAGS=-I$(CONTRIB_ROOT)/libsrk31c++/include \
	LIBSRK31CXX_LIBS="-L$(CONTRIB_ROOT)/libsrk31c++/lib \
	-Wl,-rpath,$(CONTRIB_ROOT)/libsrk31c++/lib -lsrk31c++" \
	LIBDWARFPP_CXXFLAGS=-I$(CONTRIB_ROOT)/libdwarfpp/include \
	LIBDWARFPP_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/lib -ldwarfpp" \
	LIBCXXGEN_CXXFLAGS=-I$(CONTRIB_ROOT)/libcxxgen/include \
	LIBCXXGEN_LIBS="-L$(CONTRIB_ROOT)/libcxxgen/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libcxxgen/lib -lcxxgen" \
	LIBANTLR3CXX_CXXFLAGS=-I$(CONTRIB_ROOT)/libantlr3c++/include \
	LIBANTLR3CXX_LIBS=-Wl,-g ./configure --prefix=$(CONTRIB_ROOT)/usr

.PHONY: build-dwarfidl
build-dwarfidl: dwarfidl/config.status build-libdwarfpp build-libcxxgen build-libsrk31c++ build-libc++fileno build-libantlr3c++ build-libantlr3c antlr-3.4-complete.jar
	ANTLR_M4_PATH=$(CONTRIB_ROOT)/m4ntlr \
	ANTLR="java -classpath .:$(CONTRIB_ROOT)/antlr-3.4-complete.jar:$(CLASSPATH) org.antlr.Tool" \
	$(MAKE) -C dwarfidl

clean::
	$(MAKE) -C dwarfidl clean

CONFIG_MK += "\\nCXXFLAGS += -I$(CONTRIB_ROOT)/dwarfidl/include"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/dwarfidl/lib -Wl,-rpath,$(CONTRIB_ROOT)/dwarfidl/lib"

# ----------------------------trap-syscalls

trap-syscalls/contrib/config.mk:
	$(MAKE) -C trap-syscalls/contrib

trap-syscalls/libsystrap/libsystrap.a: trap-syscalls/contrib/config.mk
	$(MAKE) -C trap-syscalls/libsystrap

CONFIG_MK += "\\nCFLAGS += -I$(CONTRIB_ROOT)/trap-syscalls/libsystrap"
CONFIG_MK += "\\nLDFLAGS += -L$(CONTRIB_ROOT)/trap-syscalls/libsystrap"

# ----------------------------config.mk

# CONFIG_MK += "\\n\\nenv.sh:\\n\\techo \>\"\$$@\" \<\<EOF\\\\\\\nexport CXXFLAGS=\$$\(CXXFLAGS\)\;\\\\\\\nexport CFLAGS=\$$\(CFLAGS\)\;\\\\\\\nLDFLAGS=\$$\(LDFLAGS\)\;\\\\\\\nEOF"
CONFIG_MK += "\\n\\nenv.sh:\\n\\techo "'"export CXXFLAGS=\"\$$\(CXXFLAGS\)\"\; export CFLAGS=\"\$$\(CFLAGS\)\"\; export LDFLAGS=\"\$$\(LDFLAGS\)\""'" \>\"\$$@\""

config.mk:
	/bin/echo -e "$(CONFIG_MK)" > "$@" || rm -f "$@"

env.sh: config.mk
	$(MAKE) -f "$<" "$@"
