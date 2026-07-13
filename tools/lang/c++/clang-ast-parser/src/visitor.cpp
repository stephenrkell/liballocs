#include "visitor.h"
#include "allocators.h"
#include "uniqtype-name.h"
#include "clang/Analysis/CFG.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace llvm;

NewDetectorVisitor::NewDetectorVisitor(ASTContext *Context,
                                       std::shared_ptr<raw_fd_ostream> outStream)
    : Context(Context), OutStream(outStream) {}

// Attempt to evaluate a comparison (e.g. x > 5) given known constant values for variables.
static bool tryEvaluateBoolWithValues(const Expr *cond, const ValueEnvMap& values,
                                      ASTContext& ctx, bool& result) {
    cond = cond->IgnoreParenImpCasts();
    const auto *bo = dyn_cast<BinaryOperator>(cond);
    if (!bo) return false;

    auto getInt = [&](const Expr *e, APSInt& val) -> bool {
        e = e->IgnoreParenImpCasts();
        if (const auto *dr = dyn_cast<DeclRefExpr>(e)) {
            if (const auto *vd = dyn_cast<VarDecl>(dr->getDecl())) {
                auto it = values.find(vd);
                if (it != values.end()) { val = it->second; return true; }
            }
        }
        Expr::EvalResult res;
        if (e->EvaluateAsInt(res, ctx)) { val = res.Val.getInt(); return true; }
        return false;
    };

    APSInt lval, rval;
    if (!getInt(bo->getLHS(), lval) || !getInt(bo->getRHS(), rval)) return false;

    unsigned width = std::max(lval.getBitWidth(), rval.getBitWidth());
    lval = lval.extOrTrunc(width);
    rval = rval.extOrTrunc(width);

    switch (bo->getOpcode()) {
        case BO_LT: result = lval < rval;  return true;
        case BO_GT: result = lval > rval;  return true;
        case BO_LE: result = lval <= rval; return true;
        case BO_GE: result = lval >= rval; return true;
        case BO_EQ: result = lval == rval; return true;
        case BO_NE: result = lval != rval; return true;
        default:    return false;
    }
}

std::vector<bool> NewDetectorVisitor::computeLiveBlocks(const CFG& cfg,
                                                        const ValueEnvMap& values) const {
    std::vector<bool> live(cfg.getNumBlockIDs(), false);
    std::vector<const CFGBlock*> worklist = { &cfg.getEntry() };
    while (!worklist.empty()) {
        const CFGBlock *b = worklist.back(); worklist.pop_back();
        if (live[b->getBlockID()]) continue;
        live[b->getBlockID()] = true;

        if (const auto *ifStmt = dyn_cast_or_null<IfStmt>(b->getTerminatorStmt())) {
            bool condVal;
            bool evaluated = ifStmt->getCond()->EvaluateAsBooleanCondition(condVal, *Context);
            if (!evaluated && !values.empty())
                evaluated = tryEvaluateBoolWithValues(ifStmt->getCond(), values, *Context, condVal);
            if (evaluated) {
                unsigned liveIdx = condVal ? 0 : 1;
                if (const CFGBlock *s = b->succ_begin()[liveIdx].getReachableBlock())
                    worklist.push_back(s);
                continue;
            }
        }
        for (const CFGBlock::AdjacentBlock& adj : b->succs())
            if (const CFGBlock *s = adj.getReachableBlock())
                worklist.push_back(s);
    }
    return live;
}

// Run forward dataflow over the function to populate callSiteEnvs.
bool NewDetectorVisitor::VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD->hasBody()) return true;
    callSiteEnvs.clear();

    auto cfg = CFG::buildCFG(FD, FD->getBody(), Context, CFG::BuildOptions());
    if (!cfg) return true;

    unsigned numBlocks = cfg->getNumBlockIDs();
    std::vector<SizeEnvMap> outEnv(numBlocks);
    std::vector<bool> computed(numBlocks, false);
    std::vector<bool> live = computeLiveBlocks(*cfg);

    // Phase 1: fixpoint — compute the converged out-env for every block.
    // We iterate until no block's out-env changes. Blocks with uncomputed
    // predecessors are skipped on that iteration and picked up in the next.
    bool changed = true;
    while (changed) {
        changed = false;
        for (CFGBlock *block : *cfg) {
            unsigned id = block->getBlockID();
            if (!live[id]) continue;

            // in[B] = merge of out[live preds]
            SizeEnvMap in;
            bool firstPred = true;
            for (CFGBlock::AdjacentBlock adj : block->preds()) {
                CFGBlock *pred = adj.getReachableBlock();
                if (!pred || !live[pred->getBlockID()] || !computed[pred->getBlockID()]) continue;
                if (firstPred) {
                    in = outEnv[pred->getBlockID()];
                    firstPred = false;
                } else in = mergeEnvs(in, outEnv[pred->getBlockID()]);
            }

            // out[B] = transfer(in[B], B)
            SizeEnvMap out = in;
            std::map<const CallExpr*, SizeEnvMap> dummy;
            for (CFGElement elem : *block)
                if (auto s = elem.getAs<CFGStmt>())
                    processStmt(s->getStmt(), out, dummy);

            if (!computed[id] || out != outEnv[id]) {
                outEnv[id] = out;
                computed[id] = true;
                changed = true;
            }
        }
    }

    // Phase 2: one final pass with the converged envs to snapshot the
    // environment at every call site in the function.
    for (CFGBlock *block : *cfg) {
        if (!live[block->getBlockID()]) continue;

        SizeEnvMap current;
        bool firstPred = true;
        for (CFGBlock::AdjacentBlock adj : block->preds()) {
            CFGBlock *pred = adj.getReachableBlock();
            if (!pred || !live[pred->getBlockID()] || !computed[pred->getBlockID()]) continue;
            if (firstPred) {
                current = outEnv[pred->getBlockID()];
                firstPred = false;
            } else current = mergeEnvs(current, outEnv[pred->getBlockID()]);
        }
        for (CFGElement elem : *block)
            if (auto s = elem.getAs<CFGStmt>())
                processStmt(s->getStmt(), current, callSiteEnvs);
    }

    return true;
}

// Run the callee's CFG dataflow with constant parameter values substituted in,
// and return the sizeofness that all live return statements agree on (Undet if they disagree).
AllocTypeInfo NewDetectorVisitor::computeReturnSizeofness(FunctionDecl *FD,
                                                          const ValueEnvMap& values) {
    auto cfg = CFG::buildCFG(FD, FD->getBody(), Context, CFG::BuildOptions());
    if (!cfg) return AllocTypeInfo();

    unsigned numBlocks = cfg->getNumBlockIDs();
    std::vector<SizeEnvMap> outEnv(numBlocks);
    std::vector<bool> computed(numBlocks, false);
    std::vector<bool> live = computeLiveBlocks(*cfg, values);

    // Phase 1: fixpoint
    bool changed = true;
    while (changed) {
        changed = false;
        for (CFGBlock *block : *cfg) {
            unsigned id = block->getBlockID();
            if (!live[id]) continue;

            SizeEnvMap in;
            bool firstPred = true;
            for (CFGBlock::AdjacentBlock adj : block->preds()) {
                CFGBlock *pred = adj.getReachableBlock();
                if (!pred || !live[pred->getBlockID()] || !computed[pred->getBlockID()]) continue;
                if (firstPred) { in = outEnv[pred->getBlockID()]; firstPred = false; }
                else in = mergeEnvs(in, outEnv[pred->getBlockID()]);
            }

            SizeEnvMap out = in;
            std::map<const CallExpr*, SizeEnvMap> dummy;
            for (CFGElement elem : *block)
                if (auto s = elem.getAs<CFGStmt>())
                    processStmt(s->getStmt(), out, dummy);

            if (!computed[id] || out != outEnv[id]) {
                outEnv[id] = out; computed[id] = true; changed = true;
            }
        }
    }

    // Phase 2: walk each live block statement-by-statement, capture env at ReturnStmts.
    AllocTypeInfo result;
    bool first = true;
    for (CFGBlock *block : *cfg) {
        if (!live[block->getBlockID()]) continue;

        SizeEnvMap current;
        bool firstPred = true;
        for (CFGBlock::AdjacentBlock adj : block->preds()) {
            CFGBlock *pred = adj.getReachableBlock();
            if (!pred || !live[pred->getBlockID()] || !computed[pred->getBlockID()]) continue;
            if (firstPred) { current = outEnv[pred->getBlockID()]; firstPred = false; }
            else current = mergeEnvs(current, outEnv[pred->getBlockID()]);
        }

        for (CFGElement elem : *block) {
            auto s = elem.getAs<CFGStmt>();
            if (!s) continue;
            const Stmt *stmt = s->getStmt();
            if (const auto *ret = dyn_cast<ReturnStmt>(stmt)) {
                if (const Expr *retVal = ret->getRetValue()) {
                    AllocTypeInfo info = extractTypeFromSizeOf(retVal, current);
                    if (first) { result = info; first = false; }
                    else if (result != info) return AllocTypeInfo(); // disagree → Undet
                }
            } else {
                std::map<const CallExpr*, SizeEnvMap> dummy;
                processStmt(stmt, current, dummy);
            }
        }
    }
    return result;
}

// If all arguments to a callee are compile-time constants, substitute them as
// parameter values and re-analyse the callee's CFG to determine return sizeofness.
AllocTypeInfo NewDetectorVisitor::analyzeCalleeReturn(const CallExpr *call) {
    FunctionDecl *callee = const_cast<FunctionDecl*>(call->getDirectCallee());
    if (!callee || !callee->hasBody()) return AllocTypeInfo();

    ValueEnvMap values;
    for (unsigned i = 0; i < call->getNumArgs() && i < callee->getNumParams(); ++i) {
        Expr::EvalResult res;
        if (call->getArg(i)->EvaluateAsInt(res, *Context))
            values[callee->getParamDecl(i)] = res.Val.getInt();
    }

    return computeReturnSizeofness(callee, values);
}

bool NewDetectorVisitor::VisitCXXNewExpr(CXXNewExpr *E) {
    // skip placement operator
    if (E->getNumPlacementArgs() > 0) return true;

    FullSourceLoc loc = Context->getFullLoc(E->getBeginLoc());
    if (!loc.isValid()) return true;

    *OutStream << loc.getFileEntry()->tryGetRealPathName() << "\t"
        << loc.getSpellingLineNumber() << "\t"
        << loc.getSpellingColumnNumber() << "\t"
        << "new" << "\t"
        << uniqtypeNameFromClangType(E->getAllocatedType(), Context) << "\t"
        << (E->isArray() ? "1" : "0") << "\n";
    return true;
}

bool NewDetectorVisitor::VisitCallExpr(CallExpr *E) {
    FunctionDecl *fdecl = E->getDirectCallee();
    if (!fdecl) return true;

    std::string qualifiedName = fdecl->getQualifiedNameAsString();
    if (allocator_funcs.find(qualifiedName) == allocator_funcs.end()) return true;

    FullSourceLoc loc = Context->getFullLoc(E->getBeginLoc());
    if (!loc.isValid()) return true;

    int sizeOfArgIdx = sizeOfArgIndex(qualifiedName, E->getNumArgs());
    if (sizeOfArgIdx < 0) return true;

    // Use the dataflow environment at this exact call site
    static const SizeEnvMap emptyEnv;
    auto it = callSiteEnvs.find(E);
    const SizeEnvMap& env = (it != callSiteEnvs.end()) ? it->second : emptyEnv;

    AllocTypeInfo info = extractTypeFromSizeOf(E->getArg(sizeOfArgIdx), env);

    // If the size argument is a direct function call and wasn't resolved via sizeof
    // expressions in the current env, try interprocedural constant-argument analysis.
    if (!info.from_sizeof) {
        const Expr *sizeArg = E->getArg(sizeOfArgIdx)->IgnoreParenImpCasts();
        if (const auto *innerCall = dyn_cast<CallExpr>(sizeArg))
            info = analyzeCalleeReturn(innerCall);
    }

    if (!info.from_sizeof) info = AllocTypeInfo();

    // (T*) malloc or static_cast<T*>(malloc) — cast overrides type
    auto parents = Context->getParents(*E);
    if (!parents.empty()) {
        if (auto *c_cast = parents[0].get<CStyleCastExpr>()) {
            info.type = c_cast->getType()->getPointeeType();
            info.is_array = true;
        } else if (auto *cxx_cast = parents[0].get<CXXStaticCastExpr>()) {
            info.type = cxx_cast->getType()->getPointeeType();
            info.is_array = true;
        }
    }

    *OutStream << loc.getFileEntry()->tryGetRealPathName() << "\t"
        << loc.getSpellingLineNumber() << "\t"
        << loc.getSpellingColumnNumber() << "\t"
        << qualifiedName << "\t"
        << uniqtypeNameFromClangType(info.type, Context) << "\t"
        << (info.is_array ? "1" : "0") << "\n";
    return true;
}
