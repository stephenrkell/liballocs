FROM debian:stretch

RUN apt-get update && apt-get install -y bison flex texinfo git build-essential
RUN git clone https://github.com/stephenrkell/binutils-gdb.git
RUN cd binutils-gdb && \
   chmod +x configure && \
   CFLAGS="-fPIC -g -O2" ./configure --prefix=/usr/local \
     --enable-gold --enable-plugins --enable-install-libiberty && \
   make -j4 && make install
RUN apt-get update && \
   apt-get install -y libelf-dev libdw-dev \
       autoconf automake libtool pkg-config autoconf-archive \
       g++ ocaml ocaml-findlib \
       default-jre-headless \
       make git gawk gdb wget \
       libunwind-dev libc6-dev-i386 zlib1g-dev libc6-dbg \
       libboost-iostreams-dev libboost-regex-dev libboost-serialization-dev libboost-filesystem-dev
RUN git clone https://github.com/stephenrkell/liballocs.git
RUN apt-get update && apt-get install -y python
RUN cd liballocs && \
   git submodule update --init --recursive && \
   make -C contrib -j1
RUN cd liballocs && \
   ./autogen.sh && \
   (. contrib/env.sh && ./configure --prefix=/usr/local) && \
   make
