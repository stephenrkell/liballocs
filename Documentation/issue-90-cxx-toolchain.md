# Issue #90: C++ Toolchain Support — Progress Tracking

## Overview

Issue #90 is about making liballocs's toolchain work for **C++ source files**. The core
problem is that the C toolchain uses a CIL (OCaml) plugin (`dumpallocs.ml`) to analyse C
source code and extract allocation site type information. CIL is a C-only framework and
**cannot process C++ source**. A C++ equivalent must be built on top of the Clang AST API.

## Current Status (2026-05-23)

| Step | Description | Status |
|---|---|---|
| 1 | Fix `clang-ast-parser`: correct output format | **DONE** |
| 2 | Hook `allocscxx.py` to invoke parser during compilation | **DONE** |
| 3 | Create `c++-gather-srcallocs` | **DONE** |
| 4 | Add C++ dispatch in `gather-srcallocs.sh` | **PARTIAL** — C++03/11/14 done; C++17/20 (43\|44) missing |
| 5 | Handle `delete`/`delete[]` free-side in `allocscxx.py` | **DONE** |
| 6 | Write a C++ test case | **PARTIAL** — `tests/cxx-new/` exists; not yet in `exit-zero-case-names` |
| 7 | Handle class-scoped `operator new` | TODO |

The original starting point (`tools/lang/c++/clang-ast-parser/`) has been refactored into
a proper `src/` tree with a separate `uniqtype-name.{h,cpp}` and a `bin/clang-ast-parser`
output binary.

---

## Background: What the C Pipeline Does (and What C++ Must Match)

### The C path (fully working)

When you compile C with `allocscc`:

1. **`allocscc`** (Python wrapper) calls `cilly` with `--load dumpallocs.cmxs`.
2. **`dumpallocs.ml`** (CIL OCaml plugin) visits every function call in the AST.
   - It analyses the size argument of allocator calls (`malloc`, `calloc`, `alloca`, ...).
   - It walks `sizeof` expressions recursively to infer the **allocated type** (e.g.
     `malloc(sizeof(Point))` → type is `Point`).
   - It handles arithmetic: `malloc(n * sizeof(T))` → type `T`, array flag `1`.
   - It outputs one tab-separated record per allocation call site to `<source>.i.allocs`.
3. At link time, `gather-srcallocs.sh` finds these `.i.allocs` files (dispatching on DWARF
   language number) and feeds them into the `allocsites` metadata builder.
4. The `allocsites` tool maps each call-site address in the linked binary to the inferred
   `uniqtype*`, which is stored in the meta-DSO.

### The `.i.allocs` format

```
<abs_path>  <line>  <col>  <allocator_fn>  <uniqtype_name>  <is_array>
```

Example:
```
/home/.../foo.c    42    42    malloc    __uniqtype__Point    0
/home/.../foo.c    57    57    malloc    __uniqtype__int$$32   1
```

- `<uniqtype_name>` must be a valid ELF symbol name for a `struct uniqtype` object
  (e.g. `__uniqtype__Point`, `__uniqtype__int$$32`).
- `<is_array>` is `1` if the allocation is a dynamically-sized array, `0` otherwise.

### What `dumpallocs.ml` does that C++ also needs

| Capability | C (dumpallocs.ml) | C++ (needed) |
|---|---|---|
| Identify allocation calls | CIL `vinst` visitor on `Call` nodes | Clang `VisitCXXNewExpr` |
| Infer allocated type from `sizeof` | `getSizeExpr` recursive analysis | Clang AST type of `CXXNewExpr::getAllocatedType()` |
| Determine array flag | size argument analysis | `CXXNewExpr::isArray()` |
| Output uniqtype symbol name | `symnameFromSig` in `cilallocs.ml` | Must implement equivalent using Clang types |
| Write to `.i.allocs` file | Direct file I/O | Output to `<source>.i.allocs` |
| Embed data in `.allocs_srcallocs` ELF section | `addAsm` call | Needs compiler flag or post-pass |

---

## The C++ Allocation Primitives

In C++, the allocation primitives are different from C:

| Expression | Underlying call | Mangled symbol | What we need |
|---|---|---|---|
| `new T` | `operator new(sizeof(T))` | `_Znwm` | type = `T`, is_array = `0` |
| `new T[n]` | `operator new[](n * sizeof(T))` | `_Znam` | type = `T`, is_array = `1` |
| `new(buf) T` | placement new (no allocation) | — | skip (no heap allocation) |
| `delete p` | `operator delete(p)` | `_ZdlPv` | free-side, handled by objdumpallocs |
| `delete[] p` | `operator delete[](p)` | `_ZdaPv` | free-side, handled by objdumpallocs |

The key insight from the issue: **at the source level, `new T` already tells us the type
directly** — it is `CXXNewExpr::getAllocatedType()` in the Clang AST. Unlike C's
`malloc(sizeof(T))`, no sizeof-expression analysis is needed. The type is unambiguous.

---

## Current State of `clang-ast-parser`

The parser lives in [tools/lang/c++/clang-ast-parser/src/](../tools/lang/c++/clang-ast-parser/src/)
and is built to `tools/lang/c++/clang-ast-parser/bin/clang-ast-parser`. It consists of:

- `clang-ast-parser.cpp` — main LibTooling driver with `VisitCXXNewExpr`
- `uniqtype-name.h` / `uniqtype-name.cpp` — `uniqtypeNameFromClangType()` helper

All of the originally identified problems have been fixed:

| Problem | Status |
|---|---|
| Column number bug (`SpellingLineNumber` used twice) | **Fixed** — uses `getSpellingColumnNumber()` |
| Missing array flag (6th column) | **Fixed** — emits `E->isArray() ? "1" : "0"` |
| Plain type names instead of uniqtype symbols | **Fixed** — `uniqtypeNameFromClangType()` in `uniqtype-name.cpp` |
| Writes to stdout | **Fixed** — writes to `<source_stem>.i.allocs` |
| Placement new not skipped | **Fixed** — `if(E->getNumPlacementArgs() > 0) return true;` |

---

## Step-by-Step Implementation Notes

### Step 1 — Fix `clang-ast-parser`: correct output format ✓ DONE

File: [tools/lang/c++/clang-ast-parser/src/clang-ast-parser.cpp](../tools/lang/c++/clang-ast-parser/src/clang-ast-parser.cpp)

All sub-steps have been applied. The visitor emits the correct 6-column format:

```cpp
bool VisitCXXNewExpr(CXXNewExpr *E) {
    if(E->getNumPlacementArgs() > 0) return true;  // skip placement new
    FullSourceLoc FullLocation = Context->getFullLoc(E->getBeginLoc());
    if (FullLocation.isValid()) {
        *OutStream << FullLocation.getFileEntry()->tryGetRealPathName() << "\t"
            << FullLocation.getSpellingLineNumber() << "\t"
            << FullLocation.getSpellingColumnNumber() << "\t"
            << "new" << "\t"
            << uniqtypeNameFromClangType(E->getAllocatedType(), Context) << "\t"
            << (E->isArray() ? "1": "0") << "\n";
    }
    return true;
}
```

`uniqtypeNameFromClangType()` is in [tools/lang/c++/clang-ast-parser/src/uniqtype-name.cpp](../tools/lang/c++/clang-ast-parser/src/uniqtype-name.cpp):
- Records (`struct`/`class`): `__uniqtype__<tag_name>`
- Built-in types: `__uniqtype__<canonName>$$<bits>`
- Pointer types: `__uniqtype____PTR_<pointee>`
- Fallback: `__uniqtype____uninterpreted_byte`

Output goes to `<source_stem>.i.allocs` via `NewDetectorAction::CreateASTConsumer()`.
The binary is built at `tools/lang/c++/clang-ast-parser/bin/clang-ast-parser`.

The canonical base type name mapping (which must match `cilallocs.ml`'s `symnameFromSig`)
is defined by the DWARF encoding. The definitive reference is
`tools/lang/c/cilallocs/cilallocs.ml`, function `symnameFromSig`, and
`contrib/liballocstool/src/cxx_compiler.cpp`.

---

### Step 2 — Hook `allocscxx.py` to invoke the parser during compilation ✓ DONE

File: [tools/lang/c++/lib/allocscxx.py](../tools/lang/c++/lib/allocscxx.py)

The hook point is `runPhasesBeforeLink()` (not `getCustomCompileArgs()` as originally
planned). After the normal compile+assemble phases complete, `runAllocsParser()` is called
for each source file:

```python
def runPhasesBeforeLink(self):
    ret = super().runPhasesBeforeLink()
    if ret == 0 and not self.onlyPreprocessing() and Phase.ASSEMBLE in self.enabledPhases:
        for src in self.getSourceInputFiles():
            self.runAllocsParser(src)
    return ret
```

`runAllocsParser()` calls `tools/lang/c++/clang-ast-parser/bin/clang-ast-parser` (note
the `bin/` subdirectory). It passes `getCompilationFlags()` (preprocessing/compile flags
from the current invocation) plus `getSystemCxxIncludes()` (system include paths queried
from the real C++ compiler via `c++ -v`) so the parser sees the same include environment.

`defaultL1AllocFns()` and `defaultFreeFns()` now include C++ operators:

```python
def defaultL1AllocFns(self):
    return ["malloc(Z)p", "calloc(zZ)p", "realloc(pZ)p", "memalign(zZ)p",
            "_Znwm(Z)p",  # new(size_t)
            "_Znam(Z)p",  # new[](size_t)
            ]

def defaultFreeFns(self):
    return ["free(P)",
            "_ZdlPv(P)",  # delete(void*)
            "_ZdaPv(P)"   # delete[](void*)
            ]
```

---

### Step 3 — Create `c++-gather-srcallocs` ✓ DONE

File: [tools/lang/c++/bin/c++-gather-srcallocs](../tools/lang/c++/bin/c++-gather-srcallocs)

Script maps `.cpp`/`.cc`/`.cxx`/`.C` → `.i.allocs` and cats the file to stdout.
Matches the design described originally.

---

### Step 4 — Add C++ dispatch in `gather-srcallocs.sh` — PARTIAL

File: [tools/gather-srcallocs.sh](../tools/gather-srcallocs.sh)

The C++ branch has been added for C++98/03/11/14 language numbers:

```bash
(4|26|33|34) # DW_LANG_C_plus_plus, DW_LANG_C_plus_plus_03,
             # DW_LANG_C_plus_plus_11, DW_LANG_C_plus_plus_14
    $(dirname "$0")/lang/c++/bin/c++-"$our_name_rewritten" \
    "$cu_sourcepath" "$obj" "$cu_fname" "$cu_compdir"
;;
```

**Still missing:** C++17 (`43` / `0x002b`) and C++20 (`44` / `0x002c`).

The DWARF language number constants:

| Constant name | Decimal | Hex | Status |
|---|---|---|---|
| `DW_LANG_C_plus_plus` | 4 | `0x0004` | ✓ handled |
| `DW_LANG_C_plus_plus_03` | 26 | `0x001a` | ✓ handled |
| `DW_LANG_C_plus_plus_11` | 33 | `0x0021` | ✓ handled |
| `DW_LANG_C_plus_plus_14` | 34 | `0x0022` | ✓ handled |
| `DW_LANG_C_plus_plus_17` | 43 | `0x002b` | **TODO** |
| `DW_LANG_C_plus_plus_20` | 44 | `0x002c` | **TODO** |

To fix, extend the case pattern to `(4|26|33|34|43|44)`.

---

### Step 5 — Handle `delete` / `delete[]` (free-side) ✓ DONE

Covered under Step 2 — `defaultFreeFns()` and `defaultL1AllocFns()` in `allocscxx.py`
now include the C++ operator mangled names.

---

### Step 6 — Write a C++ test case — PARTIAL

`tests/cxx-new/` exists with `cxx-new.cpp` and `mk.inc`.

**Still needed:** add `cxx-new` to the `exit-zero-case-names` list in
[tests/Makefile](../tests/Makefile) so the test harness runs it:

```makefile
define exit-zero-case-names
...existing cases...
cxx-new \
endef
```

Once the full pipeline works (Step 4 C++17/20 complete, confirmed `.i.allocs` generation
and meta-DSO linking), move `cxx-new` out of `exit-zero-case-names` so it uses the default
`checkrun-%` rule that verifies zero aborted queries.

Expected output after full integration:
```
p  type: Point
ps type: __ARR0_Point     (or __ARRn_Point for known-length arrays)
n  type: int$$32
```

---

### Step 7 — Handle class-scoped `operator new` (advanced)

Some classes define their own `operator new`:

```cpp
class Arena {
public:
    static void *operator new(size_t sz) { return myalloc(sz); }
};
Arena *a = new Arena;
```

This is a `CXXNewExpr` with a non-global `operator new`. The Clang AST provides
`E->getOperatorNew()` which returns the `FunctionDecl` of the called operator.

For the initial implementation, treat all `CXXNewExpr` nodes the same way and record the
allocated type regardless of which `operator new` is called. Custom allocators that differ
significantly from the standard `::operator new` can be registered separately via
`LIBALLOCS_SUBALLOC_FNS` (see `Documentation/custom-allocators.md`).

---

## Summary: Files Modified or Created

| File | Status | Notes |
|---|---|---|
| `tools/lang/c++/clang-ast-parser/src/clang-ast-parser.cpp` | **Done** | Column bug fixed; array flag added; placement new skipped; writes to `.i.allocs` |
| `tools/lang/c++/clang-ast-parser/src/uniqtype-name.{h,cpp}` | **Done** | New files implementing `uniqtypeNameFromClangType()` |
| `tools/lang/c++/lib/allocscxx.py` | **Done** | `runAllocsParser()` + `runPhasesBeforeLink()` hook; `getSystemCxxIncludes()`; updated alloc/free fn lists |
| `tools/lang/c++/bin/c++-gather-srcallocs` | **Done** | Maps `.cpp`/`.cc`/`.cxx`/`.C` → `.i.allocs` and cats contents |
| `tools/gather-srcallocs.sh` | **Partial** | C++ branch added for 4/26/33/34; C++17 (43) and C++20 (44) still missing |
| `tests/cxx-new/cxx-new.cpp` | **Done** | Test source present |
| `tests/cxx-new/mk.inc` | **Done** | Build rules present |
| `tests/Makefile` | **TODO** | Add `cxx-new` to `exit-zero-case-names` |

---

## Key Technical Challenges

### Challenge 1: Uniqtype name matching

The name written to `.i.allocs` must exactly match the ELF symbol name that `dwarftypes`
will emit when processing the same type from DWARF. If they do not match, the allocsite
table will contain a dangling symbol reference and the type query will return null.

The authoritative name mapping is in:
- `tools/lang/c/cilallocs/cilallocs.ml` → `symnameFromSig` (for C types)
- `contrib/liballocstool/src/cxx_compiler.cpp` → the C++ equivalent

For complex C++ types (templates, nested classes, lambdas), the correct names can be very
difficult to compute statically. The safe fallback is `__uniqtype____uninterpreted_byte`.

### Challenge 2: `.allocs_srcallocs` ELF section embedding

The C pipeline embeds the allocs data directly into the object file via an inline assembler
directive (`addAsm` in `dumpallocs.ml`). This creates a `.allocs_srcallocs` ELF section
that survives linking and allows `gather-srcallocs.sh` to retrieve data even if the
`.i.allocs` file is deleted.

For C++, embedding in the object file requires either:
- A post-processing step with `objcopy --add-section` after compilation, or
- Adding the data via a linker script, or
- Compiling a generated `.c` file that contains the data as a string literal in the right section.

For the initial implementation, relying on the `.i.allocs` file alone is acceptable, just
as the clang-based C path (`alloca-clang` test) does.

### Challenge 3: Non-global `new` (allocator-aware classes)

When a class defines its own `operator new`, it may use a completely different allocator.
The proper solution is to check `E->getOperatorNew()->isGlobal()` and only record entries
for global operators by default, flagging non-global ones for separate registration.

### Challenge 4: Placement new

`new(buf) T` must be skipped — it does not allocate heap memory and should not produce a
`.i.allocs` record. Check `E->getNumPlacementArgs() > 0` and return early.

### Challenge 5: `std::make_unique` / `std::make_shared` / allocator wrappers

Functions like `std::make_unique<T>()` ultimately call `::operator new` but at a call site
inside `<memory>`, not in user code. The resulting allocsite in the binary points into
the standard library headers, and the `.i.allocs` generated from user code will not cover
it.

The `dumpallocs.ml` equivalent handles this in C for `xmalloc()` style wrappers via the
`LIBALLOCS_ALLOC_FNS` environment variable. For C++, a similar mechanism is needed:
users should declare `std::make_unique` as a wrapper allocator, or liballocs should
provide a built-in list of known wrappers.

---

## Testing the Implementation Incrementally

You can test each step independently:

**Step 1 only (parser output)**:
```bash
cd tools/lang/c++/clang-ast-parser
./clang-ast-parser test/test.cpp --
cat test/test.i.allocs   # should appear after step 1e
```

**Steps 1–2 (allocscxx integration)**:
```bash
allocsc++ -o test.o test.cpp
cat test.i.allocs   # should be generated
```

**Steps 1–4 (full gather pipeline)**:
```bash
allocsc++ -o test test.cpp
make -f tools/Makefile.meta /usr/lib/meta$(readlink -f test)-meta.so
# inspect the meta-DSO for allocsite records
nm /usr/lib/meta$(readlink -f test)-meta.so | grep allocsite
```

**Step 6 (end-to-end runtime test)**:
```bash
cd tests/cxx-new
make
LD_PRELOAD=/path/to/liballocs_preload.so ./cxx-new
```

---

## References

- Issue thread: https://github.com/stephenrkell/liballocs/issues/90
- Related completed issue #167: `allocsc++` not linking with standard C++ library
- Issue #84: Meta-issue: viable student projects
- `Documentation/overview-toolchain.txt` — toolchain architecture
- `Documentation/custom-allocators.md` — declaring custom allocators
- `tools/lang/c/dumpallocs/dumpallocs.ml` — the C reference implementation (877 lines)
- `tools/lang/c/cilallocs/cilallocs.ml` — type name generation for C (864 lines)
- Clang `CXXNewExpr` API: https://clang.llvm.org/doxygen/classclang_1_1CXXNewExpr.html
- DWARF 5 language codes: Section 7.12, Table 7.17
