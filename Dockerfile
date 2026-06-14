ARG DISTRIBUTION=ubuntu:24.04
FROM ${DISTRIBUTION} AS base

ARG user=user
ARG MAKE_PARALLELISM=4

RUN apt-get update && apt-get install -y sudo adduser
RUN adduser ${user} && \
    echo "${user} ALL=(root) NOPASSWD:ALL" > /etc/sudoers && \
    chmod 0440 /etc/sudoers
RUN mkdir -p /usr/local/src && chown root:${user} /usr/local/src && \
   chmod g+w /usr/local/src
RUN mkdir -p /usr/lib/meta && chown root:staff /usr/lib/meta && \
   chmod g+w /usr/lib/meta
RUN dpkg --add-architecture i386
COPY .circleci/build-dependencies.txt /tmp/
RUN apt-get update && \
    env DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y \
    $(cat /tmp/build-dependencies.txt)
USER ${user}

FROM base AS full
ARG user=user
ARG MAKE_PARALLELISM=4

COPY --chown=${user}:${user} . /usr/local/src/liballocs/
# Initialise the OCaml environment (used to build CIL); liballocs itself does
# not manage opam switches -- it just needs one to exist here.
RUN opam init --disable-sandboxing --yes
RUN cd /usr/local/src/liballocs && \
   git submodule update --init --recursive && \
   eval $(opam env) && \
   make -C contrib -j${MAKE_PARALLELISM}
RUN cd /usr/local/src/liballocs && \
   eval $(opam env) && \
   ./autogen.sh && \
   (. contrib/env.sh && ./configure --prefix=/usr/local) && \
   make -j${MAKE_PARALLELISM}
RUN sudo mkdir -p /usr/lib/meta && sudo chown root:${user} /usr/lib/meta && \
   sudo chmod g+w /usr/lib/meta
# XXX: skip doing this for now, since the distro's pre-built libc will often
# use DWARF 5 and our tools can't hack it.
#RUN cd /usr/local/src/liballocs && \
#   make -f tools/Makefile.meta \
#      $(for libname in `ldd /bin/true | sed -En '/[[:blank:]]*([^[:blank:]]* => )?(.*) \(0x[0-9a-f]+\)/ {s//\2/;p}' | egrep 'libc\.so\.6|ld-linux.*\.so' | xargs readlink -f`; do echo "/usr/lib/meta${libname}-meta.so"; done)
