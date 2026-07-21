#ifndef ALLOCATORS_H
#define ALLOCATORS_H

#include <cctype>
#include <cstdlib>
#include <cxxabi.h>
#include <map>
#include <sstream>
#include <string>
#include <vector>

struct AllocFnSpec {
    int numArgs;     // expected argument count (-1 = any)
    int sizeArgIdx;  // 0-based index of the size (Z) argument
};

// Maps function name -> one spec per overload (different arg counts).
using AllocTable = std::map<std::string, std::vector<AllocFnSpec>>;

// Parse a liballocs allocator signature, e.g. "myfunc(pzZ)p".
// The first uppercase letter in the argspec is the size argument (Z).
// Returns false if the signature is malformed or has no size argument.
inline bool parseAllocSignature(const std::string& sig,
                                std::string& name, AllocFnSpec& spec) {
    size_t lp = sig.find('(');
    size_t rp = sig.find(')');
    if (lp == std::string::npos || rp == std::string::npos || rp <= lp)
        return false;

    name = sig.substr(0, lp);
    std::string argspec = sig.substr(lp + 1, rp - lp - 1);

    spec.numArgs    = static_cast<int>(argspec.size());
    spec.sizeArgIdx = -1;
    for (int i = 0; i < static_cast<int>(argspec.size()); ++i) {
        if (std::isupper(static_cast<unsigned char>(argspec[i]))) {
            spec.sizeArgIdx = i;
            break;
        }
    }
    return spec.sizeArgIdx >= 0;
}

// Build the allocator table from built-in defaults plus the three
// LIBALLOCS_*_FNS environment variables (space-separated signatures).
inline AllocTable buildAllocTable() {
    AllocTable table;

    static const char *defaults[] = {
        "malloc(Z)p",
        "calloc(zZ)p",
        "realloc(pZ)p",
        "reallocarray(pzZ)p",
        "alloca(Z)p",
        "__builtin_alloca(Z)p",
        "posix_memalign(pzZ)p",
        nullptr
    };
    for (const char **s = defaults; *s; ++s) {
        std::string name;
        AllocFnSpec spec;
        if (parseAllocSignature(*s, name, spec))
            table[name].push_back(spec);
    }

    const char *envVars[] = {
        "LIBALLOCS_ALLOC_FNS",
        "LIBALLOCS_SUBALLOC_FNS",
        "LIBALLOCS_ALLOCSZ_FNS",
        nullptr
    };
    for (const char **ev = envVars; *ev; ++ev) {
        const char *val = std::getenv(*ev);
        if (!val) continue;
        std::istringstream iss(val);
        std::string sig;
        while (iss >> sig) {
            std::string name;
            AllocFnSpec spec;
            if (!parseAllocSignature(sig, name, spec))
                continue;
            // demangle C++ function names
            if (name.size() > 2 && name[0] == '_' && name[1] == 'Z') {
                int status = 0;
                char *demangled = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
                if (status == 0 && demangled) {
                    // get name of function
                    std::string dem(demangled);
                    free(demangled);
                    size_t paren = dem.find('(');
                    if (paren != std::string::npos)
                        dem = dem.substr(0, paren);
                    name = dem;
                }
            }
            table[name].push_back(spec);
        }
    }

    return table;
}

// Look up the size argument index for a call with the given name and arg count.
// Returns -1 if the function is not a known allocator or has no matching spec.
inline int lookupSizeArgIdx(const AllocTable& table,
                            const std::string& name, int numArgs) {
    auto it = table.find(name);
    if (it == table.end()) return -1;
    for (const AllocFnSpec& spec : it->second) {
        if (spec.numArgs < 0 || spec.numArgs == numArgs)
            return spec.sizeArgIdx;
    }
    return -1;
}

#endif
