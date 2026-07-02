#ifndef UNIQTYPE_NAME_H

#define UNIQTYPE_NAME_H

#include "clang/AST/Type.h"
#include <string>

std::string uniqtypeNameFromClangType(clang::QualType qt, clang::ASTContext *ctx);

#endif

