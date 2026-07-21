#ifndef VISITOR_H
#define VISITOR_H

#include "allocators.h"
#include "size_env.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <memory>

// Maps a formal parameter VarDecl to its known constant integer value at a call site.
using ValueEnvMap = std::map<const clang::VarDecl*, llvm::APSInt>;

class NewDetectorVisitor : public clang::RecursiveASTVisitor<NewDetectorVisitor> {
public:
    explicit NewDetectorVisitor(clang::ASTContext *Context,
                                std::shared_ptr<llvm::raw_fd_ostream> outStream,
                                const AllocTable& allocTable);

    bool VisitFunctionDecl(clang::FunctionDecl *FD);
    bool VisitCXXNewExpr(clang::CXXNewExpr *E);
    bool VisitCallExpr(clang::CallExpr *E);

private:
    // Walk the CFG from entry, pruning dead branches at constant if-conditions.
    // values: optional map of parameter → known integer value for condition evaluation.
    std::vector<bool> computeLiveBlocks(const clang::CFG& cfg,
                                        const ValueEnvMap& values = {}) const;

    // Analyze what sizeofness a callee returns when called with constant arguments.
    AllocTypeInfo analyzeCalleeReturn(const clang::CallExpr *call);

    // Run CFG dataflow on FD with the given parameter value substitutions and
    // return the agreed-upon sizeofness of all live return statements.
    AllocTypeInfo computeReturnSizeofness(clang::FunctionDecl *FD,
                                          const ValueEnvMap& values);

    clang::ASTContext *Context;
    std::shared_ptr<llvm::raw_fd_ostream> OutStream;
    const AllocTable& allocTable;
    std::map<const clang::CallExpr*, SizeEnvMap> callSiteEnvs;
};

#endif
