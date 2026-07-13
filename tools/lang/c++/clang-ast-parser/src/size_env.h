#ifndef SIZE_ENV_H
#define SIZE_ENV_H

#include "alloc_type_info.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include <map>
#include <vector>

// Maps local VarDecl* -> its inferred sizeofness at a given program point.
// Absence means Undet (we don't know the sizeofness).
using SizeEnvMap = std::map<const clang::VarDecl*, AllocTypeInfo>;

AllocTypeInfo extractTypeFromSizeOf(const clang::Expr *exp, const SizeEnvMap& env);
SizeEnvMap mergeEnvs(const SizeEnvMap& a, const SizeEnvMap& b);
void processStmt(const clang::Stmt *S, SizeEnvMap& env,
                 std::map<const clang::CallExpr*, SizeEnvMap>& callEnvs);

#endif
