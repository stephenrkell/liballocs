liballocs is a run-time library and toolchain extension which extends
Unix-like operating systems (currently GNU/Linux) with a rich run-time
reflective model.

If you want to try it, here's how to run a simple demo in a container:

    $ git clone https://github.com/stephenrkell/liballocs.git
    $ docker build -t liballocs_built liballocs/buildtest/debian-stretch
    $ DOCKER_RUN_ARGS="--security-opt apparmor=unconfined --security-opt seccomp=unconfined"
    $ docker run ${DOCKER_RUN_ARGS} --rm -i -t --name liballocs_test liballocs_built bash
    $ export PATH=/usr/local/src/liballocs/tools/lang/c/bin:$PATH
    $ cat >test.c <<EOF
      #include <allocs.h>
      #include <stdio.h>
      int main(int argc, char **argv)
      {
        void *p = malloc(42 * sizeof(int));
        void *ptrs[] = { main, p, &p, argv, NULL };
        for (void **x = &ptrs[0]; *x; ++x)
        {
          printf("At %p is a %s-allocated object of size %u, type %s\n",
            *x,
            alloc_get_allocator(*x)->name,
            (unsigned) alloc_get_size(*x),
            UNIQTYPE_NAME(alloc_get_type(*x))
          );
        }
        return 0;
      }
    EOF
    $ allocscc -I/usr/local/src/liballocs/include -o test test.c
    $ LD_PRELOAD=/usr/local/src/liballocs/lib/liballocs_preload.so ./test

You should see something like the following. This is just a simple demo
of how liballocs knows what is in memory, having precise dynamic
information and an awareness of allocators (there are four different
allocators visible in this example).

    At 0x55d223c01436 is a static-allocated object of size 0, type __FUN_FROM___ARG0_int$32__ARG1___PTR___PTR_signed_char$8__FUN_TO_int$32
    At 0x55d2259235c0 is a __default_lib_malloc-allocated object of size 176, type __ARR0_int$32
    At 0x7ffe4e3692c8 is a stackframe-allocated object of size 128, type $2e$2ftest$2ecil$2ecmain_vaddrs_0x1436_0x154d
    At 0x7ffe4e369418 is a auxv-allocated object of size 16, type __ARR2___PTR_signed_char$8

More generally, liballocs provides the following.

* run-time type information
    - in a flexible language-agnostic in-memory format
    - derived from DWARF debugging information

* a run-time model of memory as an allocation hierarchy
    - from memory mappings right down to individual variables, objects and fields

* a run-time notion of *allocator*
    - capturing how each piece of memory is allocated and managed
    - at each level in the hierarchy!

* a reflective meta-level API answering queries about arbitrary memory
    - type, bounds, who allocated it, etc.
    - each allocator can have its own implementation of this

* a uniform base-level API for manipulating memory allocations
    - at any level in the hierarchy

It does this extension mostly transparently. In particular,

* most of the time, you don't have to change your code
    - ... or even recompile it!
    - so long as you have debugging information
    - exception: custom allocators (alloca() and obstacks are fine)
        + for these: annotate and relink, but usually no code changes (see Documentation/custom-allocators.md)

* most of the time, the slowdown is not noticeable
    - slowdowns I've seen are mostly under 5% 
    - ongoing work is reducing these further (see Documentation/projects.md)
    - some code patterns do fare worse 
        + main one: non-malloc-like custom allocators

* most of the time, the memory overheads are low
    - I don't currently have precise measurements (soon!)

What's the purpose of all this? Unix abstractions are fairly simple and
fairly general, but they are not *humane*, and they invite
*fragmentation*. By 'not humane', I mean that they are error-prone and
difficult to experiment with interactively. By 'fragmentation', I mean
they invite building higher-level abstractions in mutually opaque and
incompatible ways (think language VMs, file formats, middlewares...). To
avoid these, liballocs is a minimal extension of Unix-like abstractions
broadly in the spirit of Smalltalk-style dynamism, designed to counter
both of these problems. These provide a foundation for features such as:

* run-time type checking in C, C++ and other unsafe languages
* type-checked linking, including dynamic linking
* rich debugging/tracing tools with data visibility (think: better ltrace/strace)
* high-level I/O abstractions over memory-mapped data (think: realloc() part of a file)
* multi-language programming without foreign function interfacing APIs
* flexible "live" programming
* robust and efficient dynamic software update
* precise garbage collection across a whole address space
* efficient and flexible checkpoint/restore
* seamless debugging across native, interpreted and instrumented code
* snapshotting and fast startup via allocation-graph dump/reload
* easy serialization of arbitrary objects
* fine-grained versioning and adaptation of binary interfaces
* high-level abstractions for memory-mapped I/O
* hosting multiple ABIs in one process, interoperably
* reliable inter-process shared-memory data structures
* simplifying linking and loading mechanisms
* recompilation-based dynamic optimisation of whole processes
* robust object-level copy-on-write (+ tools based on it)
* robust shadow memory (+ tools based on it)
* orthogonal persistence
* image-based development
* your idea here!

What's novel? Although the run-time facilities of liballocs are (I
contend) richer than what has existed before in any Unix-like system,
you might counter that many of the above goals have apparently been
achieved, at least as far as proof-of-concept, by earlier research or
development prototypes. This has been through heroic efforts of many
people... but evidently these efforts have not "stuck" in the sense of
becoming part of the fabric of a commodity distribution. When this
phenomenon repeats itself, it becomes a research problem to itself --
not simply a matter of tech transfer or follow-through. Many of the
resulting prototypes lack features required for real-world use --
awareness of custom memory allocators is a common lack -- and generally
they are realised in mutually incompatible ways, for want of the right
abstractions.

To borrow Greenspun's tenth rule, this is because each of these earlier
prototypes contains an ad-hoc, bug-ridden and slow implementation of a
small fraction of liballocs. The goal of liballocs is to offer a
flexible, pluralist structure for growing these features on -- in a way
that transparently adds thse capabilities to existing codebases, rather
than requiring up-front "buy-in". It's not a framework; you don't
usually write code against its API, or port your code to it. Instead, it
extends the fabric which already builds and runs your code. The research
programme around liballocs is working towards demonstrating the
practicality of this approach, by building instances of several of the
above systems/services, at modest effort and capable of co-existence.

One idea behind liballocs is to adopt some of the same design heuristics
to which Unix owes its success: minimalism, flexibility and pluralism.
Instead of a defining a single "virtual machine" from the top down, it
permits many possible realisations of the same or similar abstractions.
Unix's free-form byte-oriented facilities allow many higher-level
semantic constructs to coexist (programming languages, structured data,
network protocols and so on). Unlike Unix, liballocs also tries fairly
hard to recognise and reconcile these duplicates after the fact. That
requires a metasystem that is *descriptive* rather than prescriptive. By
reconciling abstract commonality across the many concretely different
ways in which memory can be managed, structured and interpreted, it can
offer a platform for higher-level services which can operate correctly
across many different such schemes -- as defined by various ABIs,
language runtimes, libraries, coding styles or conventions.

There is both a toolchain component and a run-time component. The
run-time is what actually offers the services, and is in this
repository. To do so reliably, commodity toolchains must be lightly
subverted, mostly below the level of user code -- at link time, by
instrumentation, or by influencing compiler options); the basics of this
are found in the [toolsub
repository](https://github.com/stephenrkell/toolsub/ "toolsub
repository"), which is usable independently of liballocs. A minimal
core, which reflects roughly at the ELF level, but does not know about
allocators or types, is in the [librunt
repository](https://github.com/stephenrkell/librunt/ "librunt
repository").

You can read more about the system in a research paper
<http://www.cl.cam.ac.uk/~srk31/#onward15> from Onward! 2015 which
explains how liballocs generalises existing debugging infrastructure,
the contrast with VM-style debug servers, and the Unix-style descriptive
debugging which liballocs adopts and extends. The polyglot aspects of
liballocs were discussed in my talk at Strange Loop 2014
<http://www.youtube.com/watch?v=LwicN2u6Dro>.

For full disclosure, here are some additional current limitations that
will eventually go away.

* works on GNU/Linux only (some FreeBSD code exists...)
* must recompile code that calls alloca(), uses or
   provides custom allocators, and a few other cases
* when code does need to be recompiled, the toolchain is a bit slow
* it is a little fragile to churn (e.g. glibc or
   Linux kernel changes can break it)
* reflection is only as good as the available debugging information (or other ground-truth metadata).
   So, for example, if you want to find out where all the pointers
   are on your stack, you need the compiler's help --
   and today's compilers only keep a very partial record of this.
  Similarly, if you want to reflect on C preprocessor macros,
   you'll need some source of that metadata, which standard debuginfo
   builds usually omit.

To build this software on a Debian-based GNU/Linux distribution,
please see the buildtest/ directory. This has a number of
Dockerfiles which do testable and (mostly) reproducible builds,
from a bare-bones start. If you're running one of the given
distributions, you should be able to adapt the RUN commands
fairly easily to do your build. If you find any problems doing these
builds ("docker build buildtest/xxx") please report them.

If there is no buildtest Dockerfile for your distribution, it
means you'll have to pick the "closest" one and then figure out
any necessary changes for yourself. Ideally, please contribute a
Dockerfile once you've done this. Thanks to Manuel Rigger for
contributing the initial Ubuntu 18.04 one.

Note also there are submodules at many levels in this git repo,
including nested  submodules. Please make sure you pull them all. This
will happen automatically if you follow one of the buildtest recipes or
the instructions below. The following diagram shows the structure
([and was generated by this script](https://www.humprog.org/~stephen/software/git2dot "git2dot script")).

![Diagram of liballocs's depended-on subrepositories](https://raw.githubusercontent.com/stephenrkell/liballocs/b41fdc0c99411d959876594d66f6e6fc6a9b7efa/Documentation/subrepo-structure.svg)

Generic download-and-build instructions for Debian platforms
look something like the following.

    $ sudo apt-get install libelf-dev libdw-dev binutils-dev \
        autoconf automake libtool pkg-config autoconf-archive \
        g++ ocaml ocamlbuild ocaml-findlib \
        default-jre-headless python3 python \
        make git gawk gdb wget \
        libunwind-dev libc6-dev-i386 zlib1g-dev libc6-dbg \
        libboost-{iostreams,regex,serialization,filesystem}-dev && \
    git clone https://github.com/stephenrkell/liballocs.git && \
    cd liballocs && \
    git submodule update --init --recursive && \
    make -C contrib -j4 && \
    ./autogen.sh && \
    . contrib/env.sh && \
    ./configure && \
    make -j4

... where you should tune "-j4" according to your needs. After building,
you will also want to set up space to hold metadata files, and build the
metadata for your C library binary. (This is slow because libdwarf calls
`malloc()` far, far too often.)

    $ cd ..
    $ export LIBALLOCS=`pwd`/liballocs
    $ sudo mkdir /usr/lib/meta # metadata will live here
    $ sudo chown root:staff /usr/lib/meta
    $ sudo chmod g+w /usr/lib/meta
    $ make -f "$LIBALLOCS"/tools/Makefile.meta \
      /usr/lib/meta$( readlink -f /lib/x86_64-linux-gnu/libc.so.6 )-meta.so

If you've got this far, you may as well run the tests.

    $ cd liballocs/tests
    $ make                        # please report failures
