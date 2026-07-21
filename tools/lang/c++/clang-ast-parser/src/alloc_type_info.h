#ifndef ALLOC_TYPE_INFO_H
#define ALLOC_TYPE_INFO_H

#include "clang/AST/Type.h"
#include <vector>

struct SyntheticMember {
    clang::QualType type;
    bool is_array;
};

struct AllocTypeInfo {
    clang::QualType type;
    // NOTE: by default we expect that type is an array. Only some cases can definitely say that we allocate 1 object
    bool is_array    = true;
    bool from_sizeof = false;
    // Non-empty when this is a synthetic type (two different-typed components added together).
    std::vector<SyntheticMember> synth_members;

    AllocTypeInfo() = default;
    AllocTypeInfo(clang::QualType t, bool arr, bool sof) : type(t), is_array(arr), from_sizeof(sof) {}
    AllocTypeInfo(std::vector<SyntheticMember> members)
        : is_array(false), from_sizeof(true), synth_members(std::move(members)) {}

    bool isSynthetic() const { return !synth_members.empty(); }

    bool operator==(const AllocTypeInfo& o) const {
        if (type != o.type || is_array != o.is_array || from_sizeof != o.from_sizeof)
            return false;
        if (synth_members.size() != o.synth_members.size()) return false;
        for (size_t i = 0; i < synth_members.size(); ++i) {
            if (synth_members[i].type != o.synth_members[i].type ||
                synth_members[i].is_array != o.synth_members[i].is_array)
                return false;
        }
        return true;
    }
    bool operator!=(const AllocTypeInfo& o) const { return !(*this == o); }
};

#endif