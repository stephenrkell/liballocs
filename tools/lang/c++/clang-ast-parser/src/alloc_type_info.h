#ifndef ALLOC_TYPE_INFO_H
#define ALLOC_TYPE_INFO_H

#include "clang/AST/Type.h"

struct AllocTypeInfo {
    clang::QualType type;
    // NOTE: by default we expect that type is an array. Only some cases can definitely say that we allocate 1 object
    bool is_array    = true;
    bool from_sizeof = false;
    AllocTypeInfo() = default;
    AllocTypeInfo(clang::QualType t, bool arr, bool sof) : type(t), is_array(arr), from_sizeof(sof) {}
    bool operator==(const AllocTypeInfo& o) const {
        return type == o.type && is_array == o.is_array && from_sizeof == o.from_sizeof;
    }
    bool operator!=(const AllocTypeInfo& o) const { return !(*this == o); }
};

#endif
