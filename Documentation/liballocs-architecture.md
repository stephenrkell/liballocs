# liballocs: Architecture and Components

> A guide for computer science students at the bachelor level.

---

## Table of Contents

1. [What Problem Does liballocs Solve?](#1-what-problem-does-liballocs-solve)
2. [The Big Picture](#2-the-big-picture)
3. [Core Abstractions](#3-core-abstractions)
   - 3.1 [uniqtype — Describing Data Layouts](#31-uniqtype--describing-data-layouts)
   - 3.2 [allocator — Who Manages a Piece of Memory](#32-allocator--who-manages-a-piece-of-memory)
   - 3.3 [big_allocation — Tracking Memory Regions](#33-big_allocation--tracking-memory-regions)
   - 3.4 [pageindex — Fast Lookup Shortcut](#34-pageindex--fast-lookup-shortcut)
4. [The Allocation Hierarchy](#4-the-allocation-hierarchy)
5. [Runtime Architecture](#5-runtime-architecture)
   - 5.1 [Library Layers](#51-library-layers)
   - 5.2 [Initialization](#52-initialization)
   - 5.3 [How a Query Works at Runtime](#53-how-a-query-works-at-runtime)
   - 5.4 [Built-in Allocators](#54-built-in-allocators)
6. [Malloc Interposition — Tracking Heap Allocations](#6-malloc-interposition--tracking-heap-allocations)
   - 6.1 [The Problem](#61-the-problem)
   - 6.2 [Caller-Side Stubs and Callee-Side Entry Points](#62-caller-side-stubs-and-callee-side-entry-points)
   - 6.3 [Preload vs. In-Executable Cases](#63-preload-vs-in-executable-cases)
7. [Toolchain Architecture](#7-toolchain-architecture)
   - 7.1 [Why the Toolchain Needs to Be Extended](#71-why-the-toolchain-needs-to-be-extended)
   - 7.2 [Compiler Wrappers](#72-compiler-wrappers)
   - 7.3 [The .i.allocs File — Allocation Site Records](#73-the-iallocs-file--allocation-site-records)
   - 7.4 [Meta-DSOs — Metadata Shared Libraries](#74-meta-dsos--metadata-shared-libraries)
   - 7.5 [The Metadata Build Pipeline](#75-the-metadata-build-pipeline)
8. [Key Tools in tools/](#8-key-tools-in-tools)
9. [Language Support](#9-language-support)
   - 9.1 [C (allocscc / CIL)](#91-c-allocscc--cil)
   - 9.2 [C++ (allocsc++ / clang-ast-parser)](#92-c-allocsc--clang-ast-parser)
10. [Source Directory Map](#10-source-directory-map)
11. [Data Flow: From Source Code to Runtime Query](#11-data-flow-from-source-code-to-runtime-query)
12. [Key Header Files and What They Define](#12-key-header-files-and-what-they-define)
13. [The Public API at a Glance](#13-the-public-api-at-a-glance)
14. [Custom Allocators](#14-custom-allocators)
15. [Submodule Dependencies](#15-submodule-dependencies)
16. [Glossary](#16-glossary)

---

## 1. What Problem Does liballocs Solve?

In a typical C or C++ program running on Linux, you cannot ask the question:

> "What is stored at this memory address?"

The operating system only knows about pages and segments. The C library only knows the size of a malloc chunk, not what type of data it holds. The compiler threw away all that type information before the program ran.

liballocs solves this by building a **unified, hierarchical model of all memory** in a running process — from OS-level memory mappings all the way down to individual heap objects and stack variables — and exposing a **query API** that can answer, for any pointer:

- What type of data is here?
- Where does this allocation begin and end (its bounds)?
- Which allocator created it (malloc, stack, static data, mmap...)?
- Where in the source code was this allocation made?

This is done **mostly transparently** — without requiring you to rewrite your program. The only requirement is that debug information (DWARF) was emitted during compilation.

---

## 2. The Big Picture

liballocs has two major parts that work together:

```
+--------------------------------------------------------------+
|                        YOUR PROGRAM                          |
|  calls malloc(), new, alloca, etc.                           |
+--------------------------------------------------------------+
         |                          |
         | (preloaded or linked)    | (at build time, metadata
         v                          v  was generated)
+-------------------+    +----------------------+
|  liballocs        |    |  Meta-DSO files       |
|  RUNTIME LIBRARY  |    |  /usr/lib/meta/...    |
|                   |    |  (type info, alloc    |
|  Answers queries  |    |   sites, frame types) |
|  about memory     |    +----------------------+
+-------------------+
         |
         v
+-------------------+     +-------------------+
|   libsystrap      |     |     librunt        |
|  (syscall hooks)  |     |  (ELF inspection)  |
+-------------------+     +-------------------+
         |
         v
+-------------------+
|  Linux kernel /   |
|  ld.so            |
+-------------------+
```

**Runtime side**: The library `liballocs_preload.so` is loaded into the process (via `LD_PRELOAD` or explicit linking). It maintains a live map of all memory, intercepts allocator calls, and answers queries.

**Toolchain side**: A set of tools processes your compiled binaries at build time, extracting type information from DWARF debug data and allocation site information from source analysis. This is stored in "meta-DSO" shared libraries loaded at startup.

---

## 3. Core Abstractions

### 3.1 `uniqtype` — Describing Data Layouts

A `struct uniqtype` is how liballocs represents a **type** at runtime. Think of it as the runtime equivalent of a C type declaration. Defined in `include/uniqtype-defs.h`.

It uses a discriminated union (a struct where one field tells you which interpretation of the rest is valid):

```c
enum uniqtype_kind {
    VOID,
    ARRAY       = 0x1,   // e.g. int[10]
    BASE        = 0x2,   // e.g. int, float, char
    ENUMERATION = 0x4,   // e.g. enum Color { RED, GREEN, BLUE }
    COMPOSITE   = 0x6,   // e.g. struct or union
    ADDRESS     = 0x8,   // a pointer type
    SUBPROGRAM  = 0xa,   // a function type
    SUBRANGE    = 0xc,   // a subrange (used in some languages)
};
```

Each `uniqtype` also holds:
- `pos_maxoff` — the size of the type in bytes
- `related[]` — an array of `uniqtype_rel_info` entries, pointing to:
  - member types and their byte offsets (for composites)
  - the element type (for arrays)
  - the pointed-to type (for pointers)
  - return/argument types (for functions)

**Uniqueness guarantee**: For any given type definition, there is at most one live `uniqtype` instance in the process. This is achieved via ELF symbol uniquing — all meta-DSOs use the same symbol name for the same type, and the dynamic linker merges them. That is why they are called "uniqtypes".

**Naming convention**: Uniqtype symbol names encode the type. Examples:
- `__uniqtype__int$$32` — a 32-bit signed integer
- `__uniqtype____PTR_signed_char$$8` — a pointer to `char`
- `__uniqtype__MyStruct` — a struct named `MyStruct`

Types are generated by processing DWARF debug info (via the `dwarftypes` tool).

---

### 3.2 `allocator` — Who Manages a Piece of Memory

A `struct allocator` represents an **allocator strategy** — a class of allocator, not a single allocation. For example, "libc's malloc" is one allocator, "the stack" is another, "mmap" is another.

Each `struct allocator` has function pointers implementing operations like:

```c
struct allocator {
    const char *name;
    // Query the metadata for a specific allocation
    liballocs_err_t (*get_info)(void *obj, struct big_allocation *,
        struct uniqtype **out_type, void **out_base,
        unsigned long *out_size, const void **out_site);
    // ... other operations
};
```

Built-in allocators include: `__mmap_allocator`, `__stack_allocator`, `__stackframe_allocator`, `__static_file_allocator`, `__static_segment_allocator`, `__static_symbol_allocator`, `__brk_allocator`, `__alloca_allocator`, and various malloc allocators.

---

### 3.3 `big_allocation` — Tracking Memory Regions

A `struct big_allocation` represents a **tracked memory region** that participates in the allocation hierarchy. Defined in `include/pageindex.h`.

```c
struct big_allocation {
    void *begin;             // start address
    void *end;               // one-past-end address
    uint16_t first_child;    // index of first nested bigalloc
    uint16_t next_sib;       // index of next sibling bigalloc
    uint16_t parent;         // index of enclosing bigalloc
    uint16_t prev_sib;
    struct allocator *allocated_by;    // which allocator created this
    struct allocator *suballocator;    // allocator parcelling out this region
    void *allocator_private;           // opaque data for allocated_by
    void *suballocator_private;        // opaque data for suballocator
};
```

There is a global fixed-size array of these: `big_allocations[NBIGALLOCS]` (up to 32,768 entries). Each entry is identified by its index, a `bigalloc_num_t` (a `uint16_t`).

**Key insight**: Not every allocation is a bigalloc. Small allocations (like individual malloc chunks or stack variables) are *not* in this table. Only "big" allocations — memory mappings, segments, sections, malloc arenas, and any region that contains nested allocations — appear here. Small allocations are managed by the `suballocator` of their containing bigalloc.

---

### 3.4 `pageindex` — Fast Lookup Shortcut

The `pageindex` is a large array, one entry per 4KB page of virtual address space:

```
pageindex[page_number] = bigalloc_num_t
```

For any given page, it stores the index of the **deepest bigalloc that completely covers that page**. This gives O(1) lookup from any address to its relevant bigalloc, avoiding a tree walk on every query.

The array lives at a fixed virtual address (`0x410000000000` on x86-64) and is maintained as bigallocs are created and destroyed.

---

## 4. The Allocation Hierarchy

All memory in a process forms a **tree** of allocations. From outermost to innermost:

```
(virtual address space)
        |
      mmap  <-- every top-level mapping is a bigalloc
     /    \
 segment  segment ...
    |
  section
    |
  symbol (global variable, function)

  OR:

      mmap
        |
      brk  (heap arena)
        |
     malloc chunks (small, non-big)

  OR:

      mmap
        |
      stack (one per thread)
        |
     stack frame (each function call)
        |
     alloca regions (if any)
     local variables (non-big, typed by DWARF)

  OR:

      mmap
        |
      static-file (a loaded .so or executable)
        |
      static-segment (LOAD segment)
        |
      static-section (.data, .text, ...)
        |
      static-symbol (each defined variable/function)
```

For any address, you can ask liballocs which allocator manages it and navigate the tree from outermost (mmap) to innermost (leaf) allocator.

The **leaf allocator** is the one with direct responsibility for the smallest allocation containing your address. Type information comes from the leaf.

**Big vs. small split**: The boundary between "bigalloc" and "small" is at the leaf level. Stack frames, individual malloc chunks, and static symbols are usually not bigallocs. However, if a malloc chunk is itself used as an arena for a nested allocator, it gets promoted to a bigalloc.

---

## 5. Runtime Architecture

### 5.1 Library Layers

```
+--------------------------------------------------+
|  liballocs (liballocs_preload.so or liballocs.so)|
|  - pageindex maintenance                         |
|  - bigalloc tree management                      |
|  - built-in allocators                           |
|  - query API (__liballocs_get_alloc_info, etc.)  |
+--------------------------------------------------+
|  libsystrap                                      |
|  - intercepts system calls (mmap, munmap, etc.)  |
|  - notifies liballocs of new/destroyed mappings  |
+--------------------------------------------------+
|  librunt                                         |
|  - introspects ELF structures in the process     |
|  - iterates loaded DSOs, segments, symbols       |
+--------------------------------------------------+
|  ld.so (the dynamic linker)                      |
|  - loads shared libraries                        |
+--------------------------------------------------+
```

### 5.2 Initialization

When the process starts, liballocs runs its constructors (before `main`):

1. `__pageindex_init()` (priority 101) — maps the pageindex array.
2. `__liballocs_main_init()` (priority 101) — placeholder, marks init started.
3. `__liballocs_global_init()` (priority 103) — main initialization:
   - Loads DWARF-based type metadata from meta-DSO files.
   - Scans `/proc/self/maps` to populate the initial bigalloc tree.
   - Sets up system call trapping for future mmap/munmap notifications.
   - Loads meta-DSOs for each already-loaded shared library.

The initialization is lazy in some respects: meta-DSOs for libraries loaded after startup are loaded on demand when those libraries are first accessed via liballocs queries.

### 5.3 How a Query Works at Runtime

When you call `__liballocs_get_alloc_info(ptr, ...)`:

```
ptr
 |
 v
pageindex[PAGENUM(ptr)]  -->  bigalloc_num
 |
 v
big_allocations[bigalloc_num]  -->  struct big_allocation
 |
 v
big_allocation->suballocator  (or allocated_by if no suballocator)
 |
 v
allocator->get_info(ptr, bigalloc, &type, &base, &size, &site)
 |
 v
Returns: type, base address, size, allocation site, allocator name
```

The entire fast path is: one array lookup (pageindex), one struct dereference (bigalloc), one indirect function call (get_info). For the common heap case, get_info then does a bitmap search to find the start of the malloc chunk.

### 5.4 Built-in Allocators

| Allocator | What it covers |
|---|---|
| `__mmap_allocator` | Top-level memory mappings (created by `mmap` syscall) |
| `__brk_allocator` | The heap arena grown by `brk`/`sbrk` |
| `__stack_allocator` | Each thread's stack region |
| `__stackframe_allocator` | Individual function call frames |
| `__alloca_allocator` | Dynamic stack allocations via `alloca()` |
| `__static_file_allocator` | A loaded ELF binary (executable or `.so`) |
| `__static_segment_allocator` | One LOAD segment within a binary |
| `__static_section_allocator` | One section within a segment |
| `__static_symbol_allocator` | One symbol (global variable or function) |
| `__auxv_allocator` | The auxiliary vector region on the initial stack |
| `__default_lib_malloc` | libc's `malloc` (and family) |

---

## 6. Malloc Interposition — Tracking Heap Allocations

### 6.1 The Problem

When a program calls `malloc(sizeof(int) * 42)`, the C library allocates 168 bytes. But liballocs needs to know:
1. That this allocation happened (to index it).
2. What **type** was intended — `int[42]` in this case.
3. The **call site** address (which instruction triggered the allocation).

The type comes from the `sizeof` expression in the source code. The call site determines the type via static analysis. This requires hooking the allocation path.

### 6.2 Caller-Side Stubs and Callee-Side Entry Points

liballocs inserts two kinds of generated wrapper code around allocator calls:

**Caller-side stubs** (`__wrap_malloc`):
- Generated at link time by `allocscompilerwrapper.py`.
- Intercept calls **at the call site** (in the calling code).
- Their job: latch the call site address into a thread-local variable so the callee-side code can record it.
- Named using the linker's `--wrap` mechanism: `malloc` calls get redirected to `__wrap_malloc`.

**Callee-side entry points** (`__wrap___real_malloc`):
- Also generated at link time, but on the **allocator's side**.
- Their job: perform the actual allocation, then call the indexing code.
- The indexing code updates the bigalloc table and bitmap for the chunk.
- Named `__wrap___real_*` and wired together by the linker script.

The pipeline looks like this:

```
[your code]           [generated]           [liballocs]          [libc]
  malloc()  ------>  __wrap_malloc  ----->  user2hook  ------>  hook2event
  (call)             (latch site)          (entry pt)          (index chunk)
                                                                    |
                                                                real malloc()
```

### 6.3 Preload vs. In-Executable Cases

**Preload case** (most common — just use `LD_PRELOAD`):
- `liballocs_preload.so` is loaded before the program.
- It defines its own `malloc` which is found by the dynamic linker before libc's.
- Caller-side stubs are inserted into the program by the compiler wrapper if the program was built with `allocscc`.
- If the program was NOT built with `allocscc` (no stubs), allocation type inference still works for direct `malloc` calls but may be wrong for wrapper functions like `xmalloc()`.

**In-executable case** (when the program defines its own `malloc`):
- Requires building with `allocscc`.
- Both caller-side stubs and callee-side entry points are linked into the executable.
- More complex two-stage link process, but fully self-contained.

There can be **multiple malloc implementations** in one process (e.g., libc malloc, a custom allocator, liballocs's own private malloc). Each gets its own `struct allocator` and its own interposition chain.

---

## 7. Toolchain Architecture

### 7.1 Why the Toolchain Needs to Be Extended

The runtime needs two kinds of information that a standard compiled binary does not provide:

1. **Type information**: What types exist in the program? What is the layout of each struct? This is in DWARF debug info, which liballocs post-processes into `uniqtype` structures.

2. **Allocation site classification**: When `malloc(sizeof(Point) * n)` is called, analysis of the source's `sizeof` expression reveals that the allocated type is `Point`. Standard binaries do not record this.

Both kinds are collected at build time and stored in **meta-DSO files**.

### 7.2 Compiler Wrappers

liballocs provides drop-in replacements for `cc` and `c++`:

| Wrapper script | Language | Location |
|---|---|---|
| `allocscc` | C | `tools/lang/c/bin/allocscc` |
| `allocsc++` | C++ | `tools/lang/c++/bin/allocsc++` → `lib/allocscxx.py` |

These are Python scripts inheriting from `AllocsCompilerWrapper` (in `tools/allocscompilerwrapper.py`), which inherits from `CompilerWrapper` (in `tools/compilerwrapper.py`).

What `allocscc` does differently from plain `cc`:
- Passes the source through **CIL** (C Intermediate Language), an OCaml-based C front-end.
- CIL runs the `dumpallocs` plugin which analyzes allocation calls and writes `.i.allocs` files.
- Adds required compiler flags: `-gdwarf-4`, `-gstrict-dwarf`, `-fno-omit-frame-pointer`, `-ffunction-sections`.
- After linking, invokes `Makefile.meta` to build the meta-DSO.

`CompilerWrapper` handles the general mechanics: parsing compiler arguments into phases (PREPROCESS, COMPILE, ASSEMBLE, LINK), managing intermediate files, injecting link-time options for symbol wrapping.

### 7.3 The `.i.allocs` File — Allocation Site Records

During compilation with `allocscc`, a `.i.allocs` file is generated alongside each source file. It is a tab-separated text file, one allocation site per line:

```
<source_file_path>  <line>  <col>  <allocator_fn>  <uniqtype_name>  <is_array>
```

Example from `tests/alloca/alloca.i.allocs`:
```
/home/.../alloca.c    12    12    __builtin_alloca    __uniqtype__int$$32    1
/home/.../alloca.c    24    24    __builtin_alloca    __uniqtype____uninterpreted_byte    1
```

The fields mean:
- **source_file_path**: Absolute path to the C/C++ source file.
- **line**: Source line number of the allocation call.
- **col**: Source column number.
- **allocator_fn**: The function called (`malloc`, `calloc`, `__builtin_alloca`, `new`, etc.).
- **uniqtype_name**: The inferred uniqtype symbol name for the allocated type.
- **is_array**: `1` if an array is being allocated, `0` otherwise.

These files are later collected by `gather-srcallocs.sh` and fed into the `allocsites` tool.

### 7.4 Meta-DSOs — Metadata Shared Libraries

For every executable and shared library in the system, liballocs can build a corresponding **meta-DSO** — a shared library stored in a mirrored hierarchy under `/usr/lib/meta/`.

For example:
```
/lib/x86_64-linux-gnu/libc.so.6
    -->  /usr/lib/meta/lib/x86_64-linux-gnu/libc.so.6-meta.so
```

A meta-DSO contains several kinds of metadata, each produced by a different tool:

| Section / symbol | Generated by | Contains |
|---|---|---|
| `dwarftypes` | `tools/dwarftypes` | All `uniqtype` structs extracted from DWARF `.debug_info` |
| `allocsites` | `tools/allocsites` | Table mapping allocation call-site addresses to `uniqtype*` |
| `alloctypes` | `tools/alloctypes` | Synthetic types inferred from `sizeof` expressions |
| `metavector` | `tools/metavector` | Type info for static/global variables in code/data segments |
| `frametypes` | `tools/frametypes2` | Stack frame layouts (local variable offsets and types) |

When liballocs loads a binary at runtime, it finds and `dlopen`s the corresponding meta-DSO, making all this metadata available through the normal dynamic symbol table.

### 7.5 The Metadata Build Pipeline

The full pipeline for building metadata for a binary:

```
Source files (.c/.cpp)
        |
        | allocscc (CIL + dumpallocs plugin)
        v
  Object files (.o) + Allocation records (*.i.allocs)
        |
        | linker (ld, via allocscc)
        v
  Linked binary (ELF) + DWARF debug info
        |
  +-----------+-----------+-----------+
  |           |           |           |
  v           v           v           v
dwarftypes  allocsites  frametypes  metavector
(DWARF in)  (.i.allocs  (DWARF      (DWARF +
            + DWARF in) .debug_frame) symbols)
  |           |           |           |
  v           v           v           v
  +-----------+-----------+-----------+
        |
        | Makefile.meta links all pieces together
        v
  <binary>-meta.so   (stored in /usr/lib/meta/...)
```

The `Makefile.meta` file (`tools/Makefile.meta`) orchestrates all these steps. Key make targets:

- `%.objallocs` — extract allocation symbols from a linked binary using `objdumpallocs`
- `%.srcallocs` — gather `.i.allocs` source records using `gather-srcallocs.sh`
- `%.allocs` — merge object-level and source-level allocation data (`merge-allocs.sh`)
- `%-meta.so` — link all metadata into the final meta-DSO

---

## 8. Key Tools in `tools/`

| Tool | Language | Purpose |
|---|---|---|
| `dwarftypes` | C++ | Reads DWARF from a binary, emits `uniqtype` struct definitions as C source or an object |
| `allocsites` | C++ | Reads `.allocs` records + DWARF, builds the allocsite table (address → type) |
| `alloctypes` | C++ | Synthesises types from `sizeof`-expressions in DWARF attributes |
| `frametypes` / `frametypes2` | C++ | Extracts stack frame variable layouts from DWARF `.debug_frame` |
| `metavector` | C++ | Builds a compact vector of type info for static symbols in each segment |
| `extrasyms` | C++ | Adds "extra symbols" not present in the normal symbol table |
| `objdumpallocs` | Shell | Extracts allocation-site symbols from a linked binary via `nm` |
| `gather-srcallocs.sh` | Bash | Dispatches per-CU (compilation unit) to language-specific gatherers |
| `merge-allocs.sh` | Bash | Combines object-level and source-level allocation records |
| `Makefile.meta` | Make | Master build rules for all metadata |
| `allocscompilerwrapper.py` | Python | Base class for compiler wrappers; handles link-time symbol wrapping |
| `compilerwrapper.py` | Python | Lower-level compiler wrapper base (phase parsing, arg management) |
| `debug-funcs.sh` | Bash | Utilities for reading DWARF from shell scripts (CU info, language, etc.) |

Most of the C++ tools are built on top of **libdwarfpp** (a C++ DWARF library) and **liballocstool** (liballocs's own helper library for type name generation and uniqtype emission), both of which live in `contrib/`.

---

## 9. Language Support

### 9.1 C (`allocscc` / CIL)

C is the primary supported language. The pipeline uses **CIL** (C Intermediate Language — `contrib/cil/`), an OCaml-based C analysis framework.

Key OCaml modules in `tools/lang/c/`:

- **`cilallocs/cilallocs.ml`**: Shared library of utilities. Maps CIL type representations to `uniqtype` name strings. Handles bitfield arithmetic, pointer types, array types, etc.
- **`dumpallocs/dumpallocs.ml`**: A CIL visitor that walks the AST, identifies allocation calls (malloc, calloc, alloca, etc.), figures out what type is being allocated from the `sizeof` expression, and writes `.i.allocs` output.
- **`monalloca/monalloca.ml`**: Instruments `alloca()` calls to notify liballocs at runtime.
- **`dumpmemacc/`**: Variant that tracks memory accesses rather than allocations.
- **`bin/c-gather-srcallocs`**: Shell script that, given a DWARF CU's source path, finds its `.i.allocs` file and outputs it.

The `allocscc` script sets up the CIL environment, passes `--load dumpallocs.cmxs --dodumpallocs` to `cilly`, and uses `--save-temps=<srcdir>` so that `.i.allocs` files appear alongside the source.

### 9.2 C++ (`allocsc++` / clang-ast-parser)

C++ support is under active development in `tools/lang/c++/`.

- **`lib/allocscxx.py`**: The `allocsc++` compiler wrapper. Inherits from `AllocsCompilerWrapper`. Currently invokes plain `c++` without CIL instrumentation. Intended to be extended to also run the clang-ast-parser.
- **`clang-ast-parser/clang-ast-parser.cpp`**: A Clang LibTooling tool that walks the Clang AST and detects `new` expressions (`CXXNewExpr`). For each, it outputs the source location, allocated type, and (eventually) writes a `.i.allocs` file.
- **`bin/link-used-types`**: Script for linking type information for C++ binaries.

The C++ integration requires additional work to:
1. Write `.i.allocs` files directly (not just stdout).
2. Format type names as uniqtype symbol names.
3. Add a `c++-gather-srcallocs` script for the metadata pipeline.
4. Dispatch on C++ DWARF language numbers (4, 26, 33, 34) in `gather-srcallocs.sh`.

---

## 10. Source Directory Map

```
liballocs/
|
+-- include/             Public headers
|   +-- liballocs.h          Main public API (query functions, inline hot path)
|   +-- allocmeta.h          struct allocator, struct big_allocation API
|   +-- pageindex.h          Pageindex and bigalloc table definitions
|   +-- uniqtype-defs.h      Core struct uniqtype definition (generated into uniqtype.h)
|   +-- uniqtype.h           Generated: complete uniqtype definitions + macros
|   +-- liballocs_cil_inlines.h  Inline helpers used by CIL-instrumented code
|   +-- memtable.h           Hash-map-style index for malloc metadata
|   +-- allocsites.h         Allocation site table structures
|
+-- src/                 Runtime library source
|   +-- init.c               Global initialization, meta-DSO loading
|   +-- pageindex.c          Pageindex maintenance, bigalloc tree operations
|   +-- preload.c            LD_PRELOAD entry points, malloc interposition
|   +-- query.c              Implementation of the query API
|   +-- allocsites.c         Allocation site lookup
|   +-- meta-dso.c           Meta-DSO loading and management
|   +-- walk.c               Walking the bigalloc tree
|   +-- uniqtype-util.c      Utilities for working with uniqtypes
|   +-- systrap.c            System call trapping (wraps libsystrap)
|   +-- liballocs_private.h  Internal declarations
|
+-- tools/               Build-time toolchain
|   +-- Makefile.meta        Master rules for building meta-DSOs
|   +-- allocscompilerwrapper.py  Python base class for compiler wrappers
|   +-- compilerwrapper.py   Lower-level Python wrapper base
|   +-- dwarftypes.cpp       DWARF -> uniqtype generator
|   +-- allocsites.cpp       Allocation site table builder
|   +-- alloctypes.cpp       Synthetic type generator
|   +-- frametypes2.cpp      Stack frame type extractor
|   +-- metavector.cpp       Static symbol type vector builder
|   +-- gather-srcallocs.sh  Source-level allocation gatherer (dispatcher)
|   +-- merge-allocs.sh      Merge object + source alloc records
|   +-- objdumpallocs        Extract allocation symbols from binary
|   +-- debug-funcs.sh       DWARF reading shell utilities
|   |
|   +-- lang/c/              C-specific toolchain
|   |   +-- bin/allocscc         C compiler wrapper (Python, calls cilly)
|   |   +-- bin/c-gather-srcallocs  Find .i.allocs for a C CU
|   |   +-- cilallocs/           OCaml: type-name utilities for CIL
|   |   +-- dumpallocs/          OCaml: CIL plugin to dump alloc sites
|   |   +-- monalloca/           OCaml: CIL plugin to instrument alloca
|   |
|   +-- lang/c++/            C++-specific toolchain
|       +-- bin/allocsc++        C++ compiler wrapper (symlink to allocscxx.py)
|       +-- lib/allocscxx.py     C++ compiler wrapper implementation
|       +-- clang-ast-parser/    Clang-based C++ allocation site finder
|
+-- allocsld/            Custom dynamic linker (allocsld)
|   +-- allocsld.so          A replacement/extension of ld.so that integrates
|                            liballocs from the very start of process init
|
+-- Documentation/       Design documents
|   +-- overview-runtime.txt     Runtime architecture overview
|   +-- overview-toolchain.txt   Toolchain architecture overview
|   +-- bigallocs.txt            Big allocation design
|   +-- malloc-overview.txt      Malloc interposition overview
|   +-- malloc-indexing.txt      Detailed malloc indexing diagrams
|   +-- custom-allocators.md     How to register custom allocators
|
+-- tests/               Integration tests (one directory per test case)
+-- contrib/             Submodules (CIL, libdwarfpp, librunt, libsystrap, ...)
+-- examples/            Example programs using the liballocs API
```

---

## 11. Data Flow: From Source Code to Runtime Query

Here is the complete story of what happens when you compile, link, and run a program with liballocs:

### Step 1: Compile (allocscc or allocsc++)

```
myfile.c  -->  allocscc  -->  myfile.o
                          -->  myfile.i.allocs   (allocation sites: file/line/type)
```

- `allocscc` calls `cilly` with `--load dumpallocs.cmxs`.
- The dumpallocs CIL plugin visits every function call.
- When it sees `malloc(sizeof(Point))`, it records: file, line, col, "malloc", "__uniqtype__Point", 0.
- These records go into `myfile.i.allocs`.
- Also: compiler flags like `-gdwarf-4` ensure rich DWARF is in the `.o`.

### Step 2: Link (allocscc invokes ld + post-link metadata build)

```
myfile.o  -->  ld  -->  myprogram (ELF with DWARF)
```

- The linker is invoked with `--wrap malloc` (and other allocators), inserting caller stubs.
- After linking, `allocscompilerwrapper.py` calls `make -f Makefile.meta`.

### Step 3: Build meta-DSO (Makefile.meta)

```
myprogram (ELF)
myfile.i.allocs
        |
        +--> dwarftypes  -->  type objects (uniqtypes for all types in DWARF)
        +--> allocsites  -->  allocsite table (address -> type mapping)
        +--> frametypes  -->  frame layout table
        +--> metavector  -->  static symbol type info
        |
        v
/usr/lib/meta/path/to/myprogram-meta.so
```

### Step 4: Runtime startup

```
LD_PRELOAD=liballocs_preload.so ./myprogram
```

1. `liballocs_preload.so` is loaded by `ld.so` before anything else.
2. `__pageindex_init()` maps the pageindex array.
3. `__liballocs_global_init()` runs:
   - Scans `/proc/self/maps`, creates bigallocs for all existing mappings.
   - For each loaded DSO, opens its meta-DSO from `/usr/lib/meta/...`.
   - Sets up syscall trapping for future `mmap`/`munmap`/`mremap` calls.
4. Your `main()` runs.

### Step 5: Query at runtime

```c
void *p = malloc(sizeof(Point));
struct uniqtype *t = __liballocs_get_alloc_type(p);
printf("type: %s\n", UNIQTYPE_NAME(t));
// prints: "Point"
```

1. `malloc` is intercepted by the liballocs-generated stub.
2. The stub latches the call site address in a thread-local.
3. The real malloc runs, returns a chunk.
4. The indexing code records the chunk in a bitmap and stores the type (looked up from the allocsite table via the call site address).
5. When `__liballocs_get_alloc_type(p)` is called later:
   - `pageindex[PAGENUM(p)]` gives the bigalloc number (the malloc arena).
   - `big_allocations[num].suballocator->get_info(p, ...)` calls the malloc allocator's get_info.
   - get_info searches the bitmap to find the chunk base and returns the stored type.

---

## 12. Key Header Files and What They Define

| Header | Key contents |
|---|---|
| `include/liballocs.h` | Public API: `__liballocs_get_alloc_info()`, type query functions, `__liballocs_walk_subobjects_spanning()`, counter externs, `__liballocs_ensure_init()` inline |
| `include/allocmeta.h` | `struct allocator`, `struct big_allocation`, `struct lifetime_policy`, allocation hierarchy diagram comment |
| `include/pageindex.h` | `struct big_allocation` definition, `pageindex` array, `bigalloc_num_t`, `NBIGALLOCS`, helper macros `BIDX`/`IDXB` |
| `include/uniqtype-defs.h` | `enum uniqtype_kind`, `struct uniqtype_rel_info`, `UNIQTYPE_DECLS` macro (the actual struct uniqtype definition) |
| `include/uniqtype.h` | Generated: includes `uniqtype-defs.h` and all accessor macros like `UNIQTYPE_IS_ARRAY_TYPE()`, `UNIQTYPE_ARRAY_LENGTH()`, `UNIQTYPE_COMPOSITE_MEMBER_COUNT()` |
| `include/liballocs_cil_inlines.h` | Inline functions injected into CIL-instrumented code: `__liballocs_notify_heap_alloc()`, etc. |
| `include/allocsites.h` | `struct allocsite_entry` (maps a code address to a `uniqtype*`) |
| `include/memtable.h` | A compact hash-table-like structure used for the malloc chunk index |
| `include/generic_malloc_index.h` | Inline functions for maintaining the per-chunk bitmap and metadata |

---

## 13. The Public API at a Glance

These are the main functions you would call in a program that uses liballocs:

```c
// The main query: get all metadata about an allocation in one call
struct liballocs_err *__liballocs_get_alloc_info(
    const void *obj,
    struct allocator    **out_allocator,    // who allocated it
    const void          **out_alloc_start,  // base address
    unsigned long        *out_alloc_size,   // size in bytes
    struct uniqtype     **out_alloc_type,   // type
    const void          **out_alloc_site    // call site address
);

// Convenience wrappers for single-field queries
struct uniqtype  *__liballocs_get_alloc_type(void *obj);
void             *__liballocs_get_alloc_base(void *obj);
struct allocator *__liballocs_get_leaf_allocator(void *obj);
const void       *__liballocs_get_alloc_site(void *obj);

// Walk the subobject tree of a type
int __liballocs_walk_subobjects_spanning(
    unsigned target_offset,
    struct uniqtype *u,
    int (*cb)(struct uniqtype *spans, unsigned span_start_offset,
              unsigned depth, struct uniqtype *containing,
              struct uniqtype_rel_info *contained_pos, ...),
    void *arg
);

// Walk the call stack
int __liballocs_walk_stack(int (*cb)(void *ip, void *sp, void *bp, void *arg), void *arg);

// Type lookup
const void *__liballocs_typestr_to_uniqtype(const char *typestr);

// Dynamic type creation (for arrays and unions)
struct uniqtype *__liballocs_get_or_create_array_type(struct uniqtype *elem, unsigned n);
```

The **allocator** and **uniqtype** APIs are described in detail in `include/allocmeta.h` and `include/uniqtype.h` respectively.

---

## 14. Custom Allocators

If your code has a custom memory allocator (e.g., `mymalloc(size_t n)`), you can register it with liballocs by setting environment variables **at build time** before linking:

```bash
# Declare the allocation functions and their signature mini-language:
#   Z = the size argument (determines type)
#   z = a size_t argument (not the primary size)
#   p = any pointer
#   P = the pointer being freed
export LIBALLOCS_ALLOC_FNS="mymalloc(Z)p mymymalloc(zZ)p"
export LIBALLOCS_FREE_FNS="myfree(P)"

# If your custom allocator is itself suballocated from another:
export LIBALLOCS_SUBALLOC_FNS="myarena_alloc(Z)p"
export LIBALLOCS_SUBFREE_FNS="myarena_free(P)->myarena_alloc"
```

The compiler wrapper reads these environment variables and:
1. Generates caller-side stubs for each function.
2. Generates callee-side indexing entry points.
3. Sets up `--wrap` linker options.

This is described further in `Documentation/custom-allocators.md`.

---

## 15. Submodule Dependencies

liballocs depends on several submodules (in `contrib/`):

```
liballocs
    |
    +-- librunt          ELF introspection; iterates DSOs, segments, symbols
    |       |
    |       +-- libsystrap     System call trapping using ptrace/seccomp/SIGSEGV tricks
    |
    +-- liballocstool    Build-time utilities: uniqtype emission, DWARF processing
    |       |
    |       +-- libdwarfpp     C++ wrapper around libdwarf; makes DWARF traversal easy
    |
    +-- cil              The OCaml C Intermediate Language (CIL) frontend for C analysis
    |
    +-- elftin           ELF-level tools, including xwrap-ldplugin for symbol interposition
    |
    +-- libdlbind        Dynamic symbol table manipulation (add symbols at runtime)
    |
    +-- libmallochooks   The malloc hook chain (user2hook, hook2event layers)
    |
    +-- toolsub          Toolchain substitution helpers (compiler wrapper base)
```

To clone everything:
```bash
git submodule update --init --recursive
```

---

## 16. Glossary

| Term | Meaning |
|---|---|
| **uniqtype** | A runtime representation of a C/C++ data type. Unique per type definition per process. |
| **allocator** | A `struct allocator` — an object encapsulating how a class of allocations behaves (malloc, stack, mmap, ...) |
| **bigalloc** | An entry in the `big_allocations[]` table — a tracked memory region forming part of the allocation tree |
| **pageindex** | A per-page array mapping page number to the deepest bigalloc covering that page; enables O(1) lookup |
| **leaf allocator** | The allocator managing the most deeply nested allocation at a given address |
| **suballocator** | An allocator that parcels out space inside a bigalloc to smaller (non-big) allocations |
| **meta-DSO** | A generated shared library in `/usr/lib/meta/` containing type and allocation-site metadata for a binary |
| **allocsite** | A source location (instruction address + source file/line) where an allocation function is called |
| **.i.allocs file** | A tab-separated text file produced during compilation listing allocation sites and their inferred types |
| **dumpallocs** | The CIL OCaml plugin that generates `.i.allocs` files during C compilation |
| **dwarftypes** | The tool that reads DWARF debug info and emits uniqtype structures |
| **DWARF** | A debugging information format embedded in ELF binaries by compilers; describes types, variables, frames |
| **CIL** | C Intermediate Language — an OCaml framework for analysing and transforming C source code |
| **caller-side stub** | A generated function (`__wrap_malloc`) that intercepts calls at the call site to latch the call-site address |
| **callee-side entry point** | A generated function (`__wrap___real_malloc`) that wraps the allocator to perform indexing |
| **allocscc** | liballocs's C compiler wrapper (replaces `cc`) |
| **allocsc++** | liballocs's C++ compiler wrapper (replaces `c++`) |
| **LD_PRELOAD** | Linux mechanism for loading a shared library into a process before all others, used to inject liballocs |
| **xwrap** | A linker plugin (`elftin/xwrap-ldplugin`) that performs symbol interposition at link time |
| **libmallochooks** | A library providing the layered hook chain between user code and the real malloc |
| **librunt** | The ELF-introspection layer underneath liballocs |
| **libsystrap** | The system-call-trapping layer underneath librunt |
