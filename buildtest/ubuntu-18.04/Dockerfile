FROM ubuntu:18.04

RUN apt-get update && apt-get install -y bison flex texinfo git build-essential
RUN git clone https://github.com/stephenrkell/binutils-gdb.git
RUN cd binutils-gdb && \
   chmod +x configure && \
   CFLAGS="-fPIC -g -O2" ./configure --prefix=/usr/local \
     --enable-gold --enable-plugins --enable-install-libiberty && \
   make -j4 && make install
RUN cd /usr/local/bin && rm -f ld && ln -s ld.bfd ld
RUN apt-get update && \
   apt-get install -y libelf-dev libdw-dev \
       autoconf automake libtool pkg-config autoconf-archive \
       g++ ocaml ocamlbuild ocaml-findlib \
       default-jre-headless python3 python2.7 python-minimal \
       make git gawk gdb nano wget \
       libunwind-dev libc6-dev-i386 zlib1g-dev libc6-dbg \
       libboost-iostreams-dev libboost-regex-dev libboost-serialization-dev libboost-filesystem-dev
RUN git clone https://github.com/stephenrkell/liballocs.git
RUN cd liballocs && \
   git submodule update --init --recursive && \
   make -C contrib -j4
RUN cd liballocs && \
   ./autogen.sh && \
   (. contrib/env.sh && ./configure --prefix=/usr/local) && \
   make
RUN mkdir -p /usr/lib/meta && chown root:staff /usr/lib/meta && \
   chmod g+w /usr/lib/meta
RUN cd liballocs && \
   make -f tools/Makefile.meta /usr/lib/meta/lib/x86_64-linux-gnu/libc-2.27.so-meta.c
RUN cd liballocs && \
   make -f tools/Makefile.meta /usr/lib/meta/lib/x86_64-linux-gnu/libc-2.27.so-meta.so
