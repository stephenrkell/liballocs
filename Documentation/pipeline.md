# liballocs: Complete Tool/Module/Function Pipeline

This document traces every tool, module, and function invoked when building a program
with liballocs — from source file to runtime query.

---

## Overview: Two Parallel Pipelines

```
SOURCE CODE
    |
    |  [BUILD-TIME PIPELINE]
    v
allocscc / allocsc++          <-- compiler wrapper entry point
    |
    +--[1] PREPROCESS (CIL + dumpallocs)
    +--[2] COMPILE    (cc1 with DWARF flags)
    +--[3] ASSEMBLE   (as with symbol rewrites)
    +--[4] LINK       (ld + gold-plugin.so)
    |
    v
Linked Binary (ELF + DWARF)
    |
    +--[5] METADATA BUILD (Makefile.meta)
           |
           +--> dwarftypes, allocsites, alloctypes,
                frametypes2, metavector, extrasyms
           |
           v
    <binary>-meta.so  (in /usr/lib/meta/...)
    |
    |  [RUNTIME PIPELINE]
    v
LD_PRELOAD=liballocs_preload.so
    |
    +--[6] INIT   (__pageindex_init, __liballocs_global_init)
    +--[7] QUERY  (__liballocs_get_alloc_info)
```

---

## Stage 1: Compiler Wrapper Entry

### Entry scripts

| Script | Language | Location |
|--------|----------|----------|
| `allocscc` | Python | `tools/lang/c/bin/allocscc` |
| `allocsc++` | Python | `tools/lang/c++/bin/allocsc++` → `lib/allocscxx.py` |

### Class hierarchy

```
CompilerWrapper          (tools/compilerwrapper.py)
    |
AllocsCompilerWrapper    (tools/allocscompilerwrapper.py)
    |
    +-- AllocsCCWrapper  (tools/lang/c/bin/allocscc)
    +-- AllocsCXXWrapper (tools/lang/c++/lib/allocscxx.py)
```

### Key methods called in order

```
CompilerWrapper.__init__()
    parseCommandLine()           -- split argv into phases/files/flags
    |
    v
AllocsCompilerWrapper.getCompilerCommand()
    -- adds: -gdwarf-4 -gstrict-dwarf -fno-omit-frame-pointer
    --       -ffunction-sections -fno-eliminate-unused-debug-types
    |
    v
CompilerWrapper.runCompiler()
    -- orchestrates each phase below
```

---

## Stage 2: Preprocessing (C path via CIL)

Invoked when `allocscc` detects a C source input.

```
allocscc
    |
    v
cilly  (contrib/cil/bin/cilly)
    |
    +-- --load dumpallocs.cmxs
    +-- --dodumpallocs
    +-- --save-temps=<srcdir>
    |
    v  [OCaml modules, in load order]

cilallocs.ml    (tools/lang/c/cilallocs/)
    symnameFromSig()         -- maps CIL type → __uniqtype__ symbol name
    basetypeSymnameFromDWARFencoding()
    typeIsVoid() / typeIsPointerTo() / typeIsFunctionType()

dumpallocs.ml   (tools/lang/c/dumpallocs/)
    class allocSiteVisitor   -- CIL visitor (extends Cil.nopCilVisitor)
        vinst()              -- visits every instruction
            matchAllocCall() -- recognises malloc/calloc/alloca/...
            getSizeExpr()    -- recurses into sizeof to find allocated type
                walkSizeof() -- handles sizeof(T), n*sizeof(T), etc.
        vfunc()              -- per-function pre/post hook
    dumpAllocSite()          -- writes one tab-separated line to .i.allocs
    feature.fdec()           -- CIL feature entry point

monalloca.ml    (tools/lang/c/monalloca/)
    class monoAllocaVisitor
        vinst()              -- rewrites alloca() → __liballocs_alloca()
```

**Output**: `<source>.i.allocs` (one record per allocation call site)

Record format: `<path>\t<line>\t<col>\t<allocfn>\t<uniqtype_name>\t<is_array>`

---

## Stage 3: Compile (cc1)

Wrapper intercepts before the real compiler runs:

```
AllocsCompilerWrapper.getCompilerCommand()
    -- forces debug flags (see Stage 1)
    |
    v
my_cc()  (tools/allocs-wrapper, line 53)
    -- sets: CC, CFLAGS
    -- checks: -no-integrated-cpp -wrapper <self>
    |
    v
cc1 / clang -cc1         <-- real compiler front-end
    -- emits: .s assembly with full DWARF .debug_info
```

---

## Stage 4: Assemble

```
my_as()  (tools/allocs-wrapper, line 104)
    as -g <flags>          <-- real assembler
    |
    [for C-derived objects only]
    |
    v
symbol rewriting loop  (allocs-wrapper, lines 207-240)
    -- detects __uniqtype__ references in .s
    -- adds .symver / .weak aliases for base-type uniqtypes
    |
    v
AllocsCompilerWrapper.fixupPostAssemblyDotO()
    -- calls objcopy --globalize-symbol for wrapped allocator fns
    -- renames static allocators to __allocs_globalized_<name>
```

**Output**: `.o` object file with DWARF + any globalized allocator symbols

---

## Stage 5: Link (gold-plugin)

The linker is invoked with `-Wl,-plugin=gold-plugin.so`.

```
ld (GNU gold)
    |
    v
gold-plugin.so    (tools/gold-plugin.cpp)
    |
    allocs_plugin::claim_file()          (line 86)
        -- objcopy --globalize-symbol    for static allocators
        -- objcopy --redefine-sym        rename to __allocs_globalized_*
    |
    allocs_plugin::all_symbols_read()    (line ~200)
        |
        [a] usedtypes  (tools/usedtypes.cpp)
                main()
                    iterate all input .o files
                    read_types_from_object()
                    -- libdwarfpp: walk .debug_info
                    -- emit only types actually referenced
                Output → usedtypes.c (struct uniqtype definitions)
        |
        [b] compile usedtypes.c + allocstubs.c
                allocstubs.c is generated from LIBALLOCS_ALLOC_FNS etc.
                gcc -c usedtypes.c allocstubs.c
        |
        [c] xwrap-ldplugin  (contrib/elftin/xwrap-ldplugin)
                -- installs __wrap_<fn> caller-side stubs
                -- installs __wrap___real_<fn> callee-side entry points
                -- symbol interposition for: malloc, calloc, realloc,
                   free, posix_memalign, ... + any LIBALLOCS_ALLOC_FNS
```

**Output**: Linked ELF binary with wrapped allocator symbols

---

## Stage 6: Post-Link Metadata Build

Invoked by `AllocsCompilerWrapper.doPostLinkMetadataBuild()`:

```python
doPostLinkMetadataBuild()        # allocscompilerwrapper.py:167
    make -f tools/Makefile.meta  <output>-meta.so
```

`Makefile.meta` orchestrates these tools in parallel where possible:

### 6a. Collect allocation records

```
gather-srcallocs.sh   (tools/gather-srcallocs.sh)
    -- iterates over every DWARF compilation unit in the binary
    -- reads: DW_AT_language, DW_AT_comp_dir, DW_AT_name  (via debug-funcs.sh)
    -- dispatches on language number:
         C (1,2,12,29)  → lang/c/bin/c-gather-srcallocs
         C++ (4,26,33,34,43,44) → lang/c++/bin/c++-gather-srcallocs  [planned]
    -- c-gather-srcallocs: locates <source>.i.allocs, cats it to stdout
    Output → <binary>.srcallocs

objdumpallocs         (tools/objdumpallocs)
    -- nm on the linked binary
    -- extracts symbols matching __allocs_site_* pattern
    Output → <binary>.objallocs

merge-allocs.sh       (tools/merge-allocs.sh)
    -- concatenates .srcallocs + .objallocs
    -- deduplicates by call site address
    Output → <binary>.allocs
```

### 6b. Generate metadata C sources (all read the binary via libdwarfpp)

| Tool | Source file | Key function | Output |
|------|-------------|--------------|--------|
| `dwarftypes` | `tools/dwarftypes.cpp` | `main()` → `process_dwarf_types()` | `%-dwarftypes.c` |
| `allocsites` | `tools/allocsites.cpp` | `main()` → `read_allocsites()` → `ensure_needed_types_and_assign_to_allocsites()` | `%-allocsites.c` |
| `alloctypes` | `tools/alloctypes.cpp` | `main()` | `%-alloctypes.c` |
| `frametypes2` | `tools/frametypes2.cpp` | `main()` → `process_frame_types()` | `%-frametypes.c` |
| `metavector` | `tools/metavector.cpp` | `main()` | `%-metavector.c` |
| `extrasyms` | `tools/extrasyms.cpp` | `main()` | `%-extrasyms.c` |

All these tools are built on:
- **libdwarfpp** (`contrib/liballocstool/contrib/libdwarfpp/`) — C++ DWARF traversal
- **liballocstool** (`contrib/liballocstool/src/`) — uniqtype name generation, C code emission

Key liballocstool functions:
```
cxx_compiler.cpp:
    get_canonical_type_name()     -- maps DWARF type → uniqtype symbol name
    emit_uniqtype_section_decl()  -- emits the C __attribute__((section(...)))
    emit_uniqtype_def()           -- emits full struct uniqtype initialiser

allocsites-info.cpp:
    ensure_type_for_allocsite()   -- resolves uniqtype* for each .allocs record
```

### 6c. Link meta-DSO

```
Makefile.meta rule: %-meta.so
    $(META_CC) $(META_CFLAGS) -shared
        %-dwarftypes.c
        %-allocsites.c
        %-alloctypes.c
        %-frametypes.c
        %-metavector.c
        %-extrasyms.c
        -o $@
    ln -sf $@ ~/.build-id/<build-id>-meta.so
```

**Output**: `/usr/lib/meta/<path>-meta.so` — a shared library containing all metadata

---

## Stage 7: Runtime Initialization

```
LD_PRELOAD=liballocs_preload.so ./myprogram
    |
    v
ld.so loads liballocs_preload.so first
    |
    v
__attribute__((constructor(101)))
    __pageindex_init()         (src/pageindex.c)
        -- mmap pageindex array at fixed VA 0x410000000000
        -- one uint16_t (bigalloc_num_t) per 4KB page

__attribute__((constructor(101)))
    __liballocs_main_init()    (src/init.c)
        -- sets init_in_progress flag

__attribute__((constructor(103)))
    __liballocs_global_init()  (src/init.c)
        -- scans /proc/self/maps
        -- for each mapping: __add_bigalloc() → inserts into big_allocations[]
        -- for each loaded DSO:
               __liballocs_load_meta_objects_for_one_object()
               -- dlopen("<path>-meta.so")
               -- calls __liballocs_allocsites_init() in meta-DSO
        -- libsystrap: trap_all_mappings()
               -- intercepts future mmap/munmap/mremap syscalls
        -- malloc interposition active (via LD_PRELOAD symbol override)
```

---

## Stage 8: Runtime Query

```c
void *p = malloc(sizeof(Point));
struct uniqtype *t = __liballocs_get_alloc_type(p);
```

```
malloc() call
    |
    v  [generated caller-side stub]
__wrap_malloc()            (from allocstubs.c / libmallochooks)
    -- latches return address → __current_allocsite (thread-local)
    |
    v
user2hook layer            (contrib/libmallochooks/src/user2hook.c)
    -- calls the hook chain

hook2event layer           (contrib/libmallochooks/src/hook2event.c)
    __real_malloc()        -- actual libc malloc
    __liballocs_index_malloc_post()
        -- looks up __current_allocsite in allocsites[] table
        -- gets uniqtype* for this call site
        -- sets bit in memtable bitmap for this chunk
        -- stores uniqtype* alongside the chunk

__liballocs_get_alloc_type(p)
    |
    v
__liballocs_get_alloc_info(p, ...)     (src/query.c)
    |
    v
pageindex[PAGENUM(p)]                  -- O(1): get bigalloc_num
    |
    v
big_allocations[num]                   -- get struct big_allocation
    -- .suballocator = &__default_lib_malloc_allocator
    |
    v
__default_lib_malloc_allocator.get_info(p, bigalloc, ...)
    -- memtable_lookup(p) → find chunk start (bitmap search)
    -- retrieve stored uniqtype* for this chunk
    -- return: type, base, size, allocsite
```

---

## malloc Interposition Chain (detail)

```
[your code]            [generated stubs]        [libmallochooks]        [libc]
  malloc(n)  -------> __wrap_malloc(n)  -----> user2hook_malloc(n)
                        latch site                    |
                                              hook2event_malloc(n)
                                                      |
                                              __real_malloc(n)  -----> libc malloc
                                                      |
                                              post_hook:
                                              __liballocs_index_malloc_post()
                                                -- write bitmap bit
                                                -- store uniqtype*
```

---

## C++ Pipeline Differences (issue #90)

For C++ the CIL/OCaml path is replaced by a Clang LibTooling tool:

```
allocsc++
    |
    v
clang-ast-parser     (tools/lang/c++/clang-ast-parser/clang-ast-parser.cpp)
    RecursiveASTVisitor<NewDetector>
        VisitCXXNewExpr(E)
            -- E->getAllocatedType()       → allocated type (no sizeof analysis needed)
            -- E->isArray()               → is_array flag
            -- E->getNumPlacementArgs()   → skip placement new
            uniqtypeNameFromClangType()   → __uniqtype__<name> symbol
    Output → <source>.i.allocs   (same format as C path)

gather-srcallocs.sh
    case DW_LANG_C_plus_plus (4,26,33,34,43,44):
        lang/c++/bin/c++-gather-srcallocs  [to be created]
```

The link-time and post-link stages are identical to the C path.

---

## Key Data Structures Crossing Stage Boundaries

| Artifact | Produced by | Consumed by |
|----------|-------------|-------------|
| `<src>.i.allocs` | dumpallocs.ml / clang-ast-parser | gather-srcallocs.sh → allocsites |
| `<bin>.allocs` | merge-allocs.sh | allocsites tool |
| `%-dwarftypes.c` | dwarftypes | Makefile.meta (compile + link) |
| `%-allocsites.c` | allocsites | Makefile.meta |
| `<bin>-meta.so` | Makefile.meta | liballocs runtime (dlopen) |
| `pageindex[]` | __pageindex_init | __liballocs_get_alloc_info |
| `big_allocations[]` | __liballocs_global_init | allocator->get_info |
| chunk bitmap | index_malloc_post | get_info (malloc allocator) |
| `uniqtype*` per chunk | index_malloc_post | __liballocs_get_alloc_type |

---

## Submodule Dependency Map

```
liballocs (runtime + tools)
    |
    +-- contrib/librunt              ELF introspection (iterate DSOs/segments/symbols)
    |       +-- contrib/libsystrap   Syscall trapping (mmap/munmap/mremap hooks)
    |
    +-- contrib/liballocstool        Build-time helpers
    |       +-- contrib/libdwarfpp   C++ DWARF traversal wrapper
    |
    +-- contrib/cil                  OCaml CIL framework (C analysis only)
    |
    +-- contrib/elftin               ELF tools + xwrap-ldplugin (symbol interposition)
    |
    +-- contrib/libmallochooks       user2hook / hook2event malloc chain
    |
    +-- contrib/libdlbind            Dynamic symbol table manipulation
    |
    +-- contrib/toolsub              Generic compiler wrapper base (CompilerWrapper)
```
