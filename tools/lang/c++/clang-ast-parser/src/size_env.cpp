#include "size_env.h"

using namespace clang;

AllocTypeInfo extractTypeFromSizeOf(const Expr *exp, const SizeEnvMap& env) {
    exp = exp->IgnoreParenImpCasts();
    // extract type from sizeof(T) / sizeof(expr) / sizeof("str")
    if (const auto *e = dyn_cast<UnaryExprOrTypeTraitExpr>(exp)) {
        if (e->getKind() == UETT_SizeOf) {
            if (!e->isArgumentType()) {
                const Expr *argExpr = e->getArgumentExpr()->IgnoreParenImpCasts();
                if (isa<clang::StringLiteral>(argExpr)) {
                    // sizeof("str") -> char[N]; return type char array
                    if (const auto *AT = dyn_cast<ConstantArrayType>(argExpr->getType().getTypePtr()))
                        return AllocTypeInfo(AT->getElementType(), true, true);
                }
            }
            return AllocTypeInfo(e->getTypeOfArgument(), false, true);
        }
    }
    // process integers
    if (const auto *int_literal = dyn_cast<IntegerLiteral>(exp)) {
        return AllocTypeInfo(int_literal->getType(), false, false);
    }
    if (const auto *bo = dyn_cast<BinaryOperator>(exp)) {
        switch (bo->getOpcode()) {
            case BO_Mul: {
                AllocTypeInfo l = extractTypeFromSizeOf(bo->getLHS(), env);
                AllocTypeInfo r = extractTypeFromSizeOf(bo->getRHS(), env);
                // sizeof(T) * expression
                if (l.from_sizeof && !r.from_sizeof && !l.type.isNull())
                    return AllocTypeInfo(l.type, true, true);
                // expression * sizeof(T)
                if (!l.from_sizeof && r.from_sizeof && !r.type.isNull())
                    return AllocTypeInfo(r.type, true, true);
                // sizeof(T) * sizeof(T)
                if (l.from_sizeof && r.from_sizeof && !l.type.isNull())
                    return AllocTypeInfo(l.type, true, true);
                return AllocTypeInfo();
            }
            case BO_Add: {
                AllocTypeInfo l = extractTypeFromSizeOf(bo->getLHS(), env);
                if (!l.type.isNull()) return l;
                return extractTypeFromSizeOf(bo->getRHS(), env);
            }
            default:
                return AllocTypeInfo();
        }
    }
    if (const auto *decl_ref = dyn_cast<DeclRefExpr>(exp)) {
        if (const auto *vd = dyn_cast<VarDecl>(decl_ref->getDecl())) {
            // Consult the dataflow environment first
            auto it = env.find(vd);
            if (it != env.end()) return it->second;
            // Fallback: check the variable's initializer
            if (const Expr *init = vd->getInit())
                return extractTypeFromSizeOf(init, env);
        }
        return AllocTypeInfo(decl_ref->getDecl()->getType(), true, false);
    }
    return AllocTypeInfo();
}

// Merge two environments at a control-flow join point.
// Only keep entries where both predecessors agree on the type; disagreement -> Undet (absent).
SizeEnvMap mergeEnvs(const SizeEnvMap& a, const SizeEnvMap& b) {
    SizeEnvMap result;
    for (const auto& [vd, infoA] : a) {
        auto it = b.find(vd);
        if (it != b.end() && infoA.type == it->second.type)
            result[vd] = infoA;
    }
    return result;
}

// Collect all CallExprs reachable within a statement tree.
static void collectCalls(const Stmt *S, std::vector<const CallExpr*>& out) {
    if (!S) return;
    if (const auto *ce = dyn_cast<CallExpr>(S)) out.push_back(ce);
    for (const Stmt *child : S->children()) collectCalls(child, out);
}

// Apply a single CFG statement to the environment:
//   - snapshot env into callEnvs for every CallExpr found in S (before any update)
//   - update env for assignment / declaration effects
void processStmt(const Stmt *S, SizeEnvMap& env,
                 std::map<const CallExpr*, SizeEnvMap>& callEnvs) {
    if (!S) return;

    // Record the environment at each call site before the statement's side-effects
    std::vector<const CallExpr*> calls;
    collectCalls(S, calls);
    for (const CallExpr *ce : calls) callEnvs[ce] = env;

    // sz = sizeof(T)  or  sz = sz2  (where sz2 had sizeofness)
    if (const auto *bo = dyn_cast<BinaryOperator>(S)) {
        if (bo->getOpcode() == BO_Assign) {
            if (const auto *dr = dyn_cast<DeclRefExpr>(
                    bo->getLHS()->IgnoreParenImpCasts())) {
                if (const auto *vd = dyn_cast<VarDecl>(dr->getDecl())) {
                    AllocTypeInfo info = extractTypeFromSizeOf(bo->getRHS(), env);
                    if (info.from_sizeof)
                        env[vd] = info;
                    else
                        env.erase(vd); // kill any stale sizeofness
                }
            }
        }
    }
    // size_t sz = sizeof(T)
    else if (const auto *ds = dyn_cast<DeclStmt>(S)) {
        for (const Decl *d : ds->decls()) {
            if (const auto *vd = dyn_cast<VarDecl>(d)) {
                if (const Expr *init = vd->getInit()) {
                    AllocTypeInfo info = extractTypeFromSizeOf(init, env);
                    if (info.from_sizeof) env[vd] = info;
                }
            }
        }
    }
}
