#ifndef UNIQTYPE_NAME_H
#define UNIQTYPE_NAME_H

#include "alloc_type_info.h"
#include "clang/AST/Type.h"
#include "clang/AST/ASTContext.h"
#include <string>
#include <vector>

std::string uniqtypeNameFromClangType(clang::QualType qt, clang::ASTContext *ctx,
                                       const std::string& hint = "");

std::string syntheticTypeString(const std::vector<SyntheticMember>& members,
                                 const std::string& filepath,
                                 unsigned line, unsigned col,
                                 clang::ASTContext *ctx);

#endif
