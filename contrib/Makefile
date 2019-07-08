THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
CONTRIB_ROOT := $(realpath $(dir $(THIS_MAKEFILE)))

NINJA ?= ninja
CMAKE ?= cmake

export LIBALLOCS := $(realpath $(dir $(THIS_MAKEFILE))/..)
# trap-syscalls's and libdlbind's contribs need to be able to find librunt
export LIBRUNT_BASE := $(realpath $(dir $(THIS_MAKEFILE))/librunt)

# things we need to build:
# - libdwarfpp
# - libcxxgen
# - libantlr3cxx
# - trap-syscalls's own contrib      (this needs antlr, I think)
# - trap-syscalls/libsystrap    (*not* the main trap-syscalls, which has other deps...)
# - dwarfidl (ignore its contrib build script)
# - libdlbind
# - binutils-gdb?
#
# things that just sit here, but we have to set config for:
# - libmallochooks
#
# contrib things that live elsewhere
# - everything in trap-syscalls/contrib
# - cil (in liballocs/tools/lang/c)

default: env.sh config.mk trap-syscalls/libsystrap/libsystrap.a \
build-dwarfidl build-libdwarfpp build-libcxxgen \
build-libantlr3c++ build-libantlr3c build-libdlbind build-libsystrap

.PHONY: clean default

CONFIG_MK += include $$(dir $$(lastword $$(MAKEFILE_LIST)))/libdwarfpp/contrib/config.mk
config.mk: build-libdwarfpp

# ----------------------------antlr things
antlr-3.4.tar.gz:
	wget http://www.antlr3.org/download/antlr-3.4.tar.gz

libantlr3c-3.4/configure: antlr-3.4.tar.gz
	mkdir -p libantlr3c-3.4 && cd libantlr3c-3.4 && tar --strip-components=3 --keep-newer-files -xvzf "$(CONTRIB_ROOT)/$<" antlr-3.4/runtime/C
	# HACK: if the patch fails, it's probably because we've already applied it in an earlier failed run of these rules
	cd libantlr3c-3.4 && patch -p1 < "$(CONTRIB_ROOT)"/libantlr3c-3.4-getparent-allow-null.patch </dev/null || true
	cd libantlr3c-3.4 && aclocal && \
                autoconf && \
                autoheader && \
                libtoolize && \
                automake --add-missing && \
                automake
	chmod +x "$@"
	touch "$@"

antlr-3.4-complete.jar: antlr-3.4.tar.gz
	tar --strip-components=2 --keep-newer-files -xvzf "$(CONTRIB_ROOT)/$<" antlr-3.4/lib/antlr-3.4-complete.jar

libantlr3c-3.4/Makefile: libantlr3c-3.4/configure
	cd libantlr3c-3.4 && ./configure --enable-64bit

.PHONY: build-libantlr3c
build-libantlr3c: libantlr3c-3.4/Makefile
	$(MAKE) -C libantlr3c-3.4

libantlr3c-3.4/antlr3config.h: build-libantlr3c

clean::
	rm -f antlr-3.4.tar.gz
	rm -rf libantlr3c-3.4

CONFIG_MK += \nANTLR3C_DIR := $(CONTRIB_ROOT)/libantlr3c-3.4\n
CONFIG_MK += \nCXXFLAGS += -I\$$(ANTLR3C_DIR)/include -I\$$(ANTLR3C_DIR)/\n
CONFIG_MK += \nLDFLAGS += -L\$$(ANTLR3C_DIR)/.libs -Wl,-rpath,\$$(ANTLR3C_DIR)/.libs\n

# ----------------------------other libs that are autotools'd
# ----------------------------libdwarfpp

libdwarfpp/config.status:
	cd libdwarfpp && ./autogen.sh && git submodule init && git submodule update && \
	$(MAKE) -C contrib && ( . contrib/env.sh && \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr $(LIBDWARFPP_CONFIGURE_FLAGS) )

.PHONY: build-libdwarfpp
build-libdwarfpp: libdwarfpp/config.status
	$(MAKE) -C libdwarfpp

clean::
	if test -f libdwarfpp/Makefile; then $(MAKE) -C libdwarfpp clean; fi

CONFIG_MK += \nLIBDWARFPP_CXXFLAGS += -I$(CONTRIB_ROOT)/libdwarfpp/include\n
CONFIG_MK += \nLIBDWARFPP_LIBS += -L$(CONTRIB_ROOT)/libdwarfpp/lib -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/lib -ldwarfpp\n

# ----------------------------libcxxgen

libcxxgen/config.status:
	cd libcxxgen &&  aclocal && \
                autoconf && \
                libtoolize && \
                automake --add-missing && \
                automake &&  \
	LIBCXXFILENO_CXXFLAGS="-I$(CONTRIB_ROOT)/libdwarfpp/contrib/libc++fileno/include" \
	LIBCXXFILENO_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/contrib/libc++fileno/lib -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/contrib/libc++fileno/lib" \
	LIBSRK31CXX_CXXFLAGS="-I$(CONTRIB_ROOT)/libdwarfpp/contrib/libsrk31c++/include" \
	LIBSRK31CXX_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/contrib/libsrk31c++/lib -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/contrib/libsrk31c++/lib" \
	LIBDWARFPP_CXXFLAGS=-I$(CONTRIB_ROOT)/libdwarfpp/include \
	LIBDWARFPP_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/lib -ldwarfpp" \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr $(LIBCXXGEN_CONFIGURE_FLAGS)

.PHONY: build-libcxxgen
build-libcxxgen: libcxxgen/config.status build-libdwarfpp
	$(MAKE) -C libcxxgen

clean::
	if test -e libcxxgen/Makefile; then $(MAKE) -C libcxxgen clean; fi

CONFIG_MK += \nLIBCXXGEN_CXXFLAGS += -I$(CONTRIB_ROOT)/libcxxgen/include\n
CONFIG_MK += \nLIBCXXGEN_LIBS += -L$(CONTRIB_ROOT)/libcxxgen/lib -Wl,-rpath,$(CONTRIB_ROOT)/libcxxgen/lib -lcxxgen\n

# ----------------------------libantlr3cxx

libantlr3c++/config.status:
	cd libantlr3c++ && ./autogen.sh && \
	 ./configure --prefix=$(CONTRIB_ROOT)/usr

.PHONY: build-libantlr3cxx
build-libantlr3c++: libantlr3c++/config.status
	$(MAKE) -C libantlr3c++

clean::
	if test -e libantlr3c++/Makefile; then $(MAKE) -C libantlr3c++ clean; fi

CONFIG_MK += \nLIBANTLR3CXX_CXXFLAGS += -I$(CONTRIB_ROOT)/libantlr3c++/include\n
CONFIG_MK += \nLIBANTLR3CXX_LIBS += -L$(CONTRIB_ROOT)/libantlr3c++/lib -Wl,-rpath,$(CONTRIB_ROOT)/libantlr3c++/lib\n

# ----------------------------dwarfidl

dwarfidl/config.status: libantlr3c-3.4/antlr3config.h
	cd dwarfidl && git submodule init && git submodule update && ./autogen.sh && \
	LIBCXXFILENO_CXXFLAGS=-I$(CONTRIB_ROOT)/libdwarfpp/contrib/libc++fileno/include \
	LIBCXXFILENO_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/contrib/libc++fileno/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/contrib/libc++fileno -lc++fileno" \
	LIBSRK31CXX_CXXFLAGS=-I$(CONTRIB_ROOT)/libdwarfpp/contrib/libsrk31c++/include \
	LIBSRK31CXX_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/contrib/libsrk31c++/lib \
	-Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/contrib/libsrk31c++/lib -lsrk31c++" \
	LIBDWARFPP_CXXFLAGS=-I$(CONTRIB_ROOT)/libdwarfpp/include \
	LIBDWARFPP_LIBS="-L$(CONTRIB_ROOT)/libdwarfpp/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libdwarfpp/lib -ldwarfpp" \
	LIBCXXGEN_CXXFLAGS=-I$(CONTRIB_ROOT)/libcxxgen/include \
	LIBCXXGEN_LIBS="-L$(CONTRIB_ROOT)/libcxxgen/lib \
        -Wl,-rpath,$(CONTRIB_ROOT)/libcxxgen/lib -lcxxgen" \
	LIBANTLR3CXX_CXXFLAGS=-I$(CONTRIB_ROOT)/libantlr3c++/include \
	LIBANTLR3CXX_LIBS=-Wl,-g \
	CPPFLAGS="-I$(CONTRIB_ROOT)/libantlr3c-3.4/ -I$(CONTRIB_ROOT)/libantlr3c-3.4/include $(CPPFLAGS)" \
	LDFLAGS="-L$(CONTRIB_ROOT)/libantlr3c-3.4/.libs $(LDFLAGS)" \
	ANTLR="java -classpath .:$(CONTRIB_ROOT)/antlr-3.4-complete.jar:$(CLASSPATH) org.antlr.Tool" \
	./configure --prefix=$(CONTRIB_ROOT)/usr

.PHONY: build-dwarfidl
build-dwarfidl: dwarfidl/config.status build-libdwarfpp build-libcxxgen build-libantlr3c++ build-libantlr3c antlr-3.4-complete.jar
	$(MAKE) -C dwarfidl

clean::
	if test -e dwarfidl/Makefile; then $(MAKE) -C dwarfidl clean; fi

CONFIG_MK += \nDWARFIDL_CXXFLAGS += -I$(CONTRIB_ROOT)/dwarfidl/include\n
CONFIG_MK += \nDWARFIDL_LIBS += -L$(CONTRIB_ROOT)/dwarfidl/lib -Wl,-rpath,$(CONTRIB_ROOT)/dwarfidl/lib -ldwarfidl\n

# ----------------------------trap-syscalls

trap-syscalls/contrib/config.mk:
	$(MAKE) -C trap-syscalls/contrib

trap-syscalls/libsystrap/libsystrap.a: trap-syscalls/contrib/config.mk $(wildcard trap-syscalls/libsystrap/*.[ch])
	$(MAKE) -C trap-syscalls/libsystrap

.PHONY: build-libsystrap
build-libsystrap: trap-syscalls/libsystrap/libsystrap.a

CONFIG_MK += \nTRAP_SYSCALLS := $(CONTRIB_ROOT)/trap-syscalls\n
CONFIG_MK += \nLIBSYSTRAP := $(CONTRIB_ROOT)/trap-syscalls/libsystrap\n

# ----------------------------libdlbind

build-libdlbind:
	$(MAKE) -C libdlbind

CONFIG_MK += \nLIBDLBIND ?= $(CONTRIB_ROOT)/libdlbind\n

# ----------------------------malloc-hooks

CONFIG_MK += \nMALLOC_HOOKS := $(CONTRIB_ROOT)/libmallochooks\n

# ----------------------------optional: LLVM (Chris Diamand's fork, for now)
.PHONY: llvm llvm-build
llvm: llvm/build/LLVMBuild.cmake llvm-build

# use -fuse-ld=gold because ld.bfd exhausts memory on my not-short-of-memory machine
llvm/build/LLVMBuild.cmake:
	mkdir -p "$(dir $@)" && cd "$(dir $@)" && \
    LDFLAGS="-fuse-ld=gold -Wl,--gdb-index" \
    $(CMAKE) \
    -DLLVM_USE_SPLIT_DWARF=TRUE \
    -DLLVM_ENABLE_ASSERTIONS=TRUE \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=true \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -G Ninja ..
llvm-build: llvm/build/LLVMBuild.cmake
	cd llvm/build && $(NINJA) -v

# FIXME: clean target

# this cmake argument doesn't work
# -DEXTRA_LINK_FLAGS="-fuse-ld=gold" ..

# ----------------------------config.mk

varlist := CXXFLAGS CPPFLAGS CFLAGS LDFLAGS \
TRAP_SYSCALLS MALLOC_HOOKS LIBDLBIND \
DWARFIDL_CXXFLAGS DWARFIDL_LIBS \
LIBANTLR3CXX_CXXFLAGS LIBANTLR3CXX_LIBS \
LIBCXXGEN_CXXFLAGS LIBCXXGEN_LIBS \
LIBDWARFPP_CXXFLAGS LIBDWARFPP_LIBS \
LIBCXXFILENO_CXXFLAGS LIBCXXFILENO_LIBS \
LIBSRK31CXX_CXXFLAGS LIBSRK31CXX_LIBS

CONFIG_MK += \n\nenv.sh:\n\tprintf '"'"'$(foreach var,$(varlist),export $(var)="$$($(var))"; )'"'"' >"$$@" || (rm -f "$$@"; false)

config.mk:
	printf '$(CONFIG_MK)' > "$@" || (rm -f "$@"; false)

env.sh: config.mk
	$(MAKE) -f "$<" "$@"

clean::
	rm -f config.mk env.sh
