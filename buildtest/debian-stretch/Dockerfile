FROM debian:stretch

ARG user
RUN apt-get update && apt-get install -y sudo
RUN adduser ${user:-user} && \
    echo "${user:-user} ALL=(root) NOPASSWD:ALL" > /etc/sudoers && \
    chmod 0440 /etc/sudoers
RUN mkdir -p /usr/local/src && chown root:user /usr/local/src && \
   chmod g+w /usr/local/src
USER ${user:-user}
RUN sudo mkdir -p /usr/lib/meta && sudo chown root:staff /usr/lib/meta && \
   sudo chmod g+w /usr/lib/meta
RUN sudo apt-get install -y git build-essential libelf-dev libdw-dev binutils-dev \
       autoconf automake libtool pkg-config autoconf-archive \
       g++ ocaml ocaml-findlib \
       default-jdk-headless python3 python \
       make git gawk gdb wget \
       libunwind-dev libc6-dev-i386 zlib1g-dev libc6-dbg \
       libboost-iostreams-dev libboost-regex-dev libboost-serialization-dev libboost-filesystem-dev
RUN cd /usr/local/src && git clone https://github.com/stephenrkell/liballocs.git
RUN cd /usr/local/src/liballocs && \
   git submodule update --init --recursive && \
   make -C contrib -j4
RUN cd /usr/local/src/liballocs && \
   ./autogen.sh && \
   (. contrib/env.sh && ./configure --prefix=/usr/local) && \
   make -j4
RUN sudo mkdir -p /usr/lib/meta && sudo chown root:user /usr/lib/meta && \
   sudo chmod g+w /usr/lib/meta
RUN cd /usr/local/src/liballocs && \
   make -f tools/Makefile.meta \
      $(for libname in `ldd /bin/true | sed -En '/[[:blank:]]*([^[:blank:]]* => )?(.*) \(0x[0-9a-f]+\)/ {s//\2/;p}' | egrep 'libc\.so\.6|ld-linux.*\.so' | xargs readlink -f`; do echo "/usr/lib/meta${libname}-meta.so"; done)
