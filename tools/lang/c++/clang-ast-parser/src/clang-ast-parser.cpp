#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "llvm/Support/CommandLine.h"
#include "uniqtype-name.h"
#include "allocators.h"

using namespace clang;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory MyToolCategory("my-tool-options");

// recursively find Type
QualType extractTypeFromSizeOf(Expr *exp) {
    exp = exp->IgnoreParenImpCasts(); // ignore ImplicitCastExpr and get it's child
    if (const auto *e = dyn_cast<UnaryExprOrTypeTraitExpr>(exp)) {
        if (e->getKind() == UETT_SizeOf) return e->getTypeOfArgument();
    }
    if (const auto *bo = dyn_cast<BinaryOperator>(exp)) {
        auto opCode = bo->getOpcode();
        if (opCode == BO_Mul || opCode == BO_Add) {
            QualType qt_l = extractTypeFromSizeOf(bo->getLHS());
            if (!qt_l.isNull()) return qt_l;
            return extractTypeFromSizeOf(bo->getRHS());
        }
    }
    if (const auto *decl_ref = dyn_cast<DeclRefExpr>(exp)) {
        return decl_ref->getDecl()->getType();
    };
    return QualType();
}

class NewDetectorVisitor : public RecursiveASTVisitor<NewDetectorVisitor> {
public:
    explicit NewDetectorVisitor(ASTContext *Context, std::shared_ptr<raw_fd_ostream> outStream) : Context(Context), OutStream(outStream) {}

    // visit new
    bool VisitCXXNewExpr(CXXNewExpr *E) {
        // skip placement operator
        if(E->getNumPlacementArgs() > 0) return true; 

        FullSourceLoc loc = Context->getFullLoc(E->getBeginLoc());
        if (!loc.isValid()) return true;

        std::string TypeName = E->getAllocatedType().getAsString();
        *OutStream << loc.getFileEntry()->tryGetRealPathName() << "\t"
            << loc.getSpellingLineNumber() << "\t"
            << loc.getSpellingColumnNumber() << "\t"
            << "new" << "\t"
            << uniqtypeNameFromClangType(E->getAllocatedType(), Context) << "\t"
            << (E->isArray() ? "1": "0") << "\n";
        return true;
    }

    // visit malloc, calloc, realloc, reallocarray
    bool VisitCallExpr(CallExpr *E) {
        FunctionDecl *fdecl = E->getDirectCallee();
        if (!fdecl) return true;

        std::string qualifiedName = fdecl->getQualifiedNameAsString();
        if (allocator_funcs.find(qualifiedName) == allocator_funcs.end()) return true;

        FullSourceLoc loc = Context->getFullLoc(E->getBeginLoc());
        if (!loc.isValid()) return true;

        int sizeOfArgIdx = sizeOfArgIndex(qualifiedName, E->getNumArgs());
        if (sizeOfArgIdx < 0) return true;

        QualType qt = extractTypeFromSizeOf(E->getArg(sizeOfArgIdx));
        if (qt.isNull()) {
            printf("can't parse expr: %s at line %d\n", E->getArg(sizeOfArgIdx)->getStmtClassName(), loc.getSpellingLineNumber());
            return true;
        }

        //printf("found malloc expr: %s at line %d\n", 
        //       fdecl->getQualifiedNameAsString().c_str(),
        //       loc.getSpellingLineNumber());

        // (T*) malloc or static_cast<T*>(malloc)
        auto parents = Context->getParents(*E);
        if (!parents.empty()) {
            if (auto *c_cast = parents[0].get<CStyleCastExpr>()) {
                qt = c_cast->getType()->getPointeeType();
                //printf("c-style cast: %s\n", qt.getAsString().c_str());
            } else if (auto *cxx_cast = parents[0].get<CXXStaticCastExpr>()) {
                qt = cxx_cast->getType()->getPointeeType();
                //printf("cxx static_cast: %s\n", qt.getAsString().c_str());
            }
        }

        *OutStream << loc.getFileEntry()->tryGetRealPathName() << "\t"
            << loc.getSpellingLineNumber() << "\t"
            << loc.getSpellingColumnNumber() << "\t"
            << qualifiedName << "\t"
            << uniqtypeNameFromClangType(qt, Context) << "\t"
            << "0" << "\n";
        return true;
    }

private:
    ASTContext *Context;
    std::shared_ptr<raw_fd_ostream> OutStream;
};

class NewDetectorConsumer : public ASTConsumer {
public:
    explicit NewDetectorConsumer(ASTContext *Context, std::shared_ptr<raw_fd_ostream> outStream) : Visitor(Context, outStream) {}
    void HandleTranslationUnit(ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    NewDetectorVisitor Visitor;
};

class NewDetectorAction : public ASTFrontendAction {
public:
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
        // *.cpp -> *.i.allocs
        SmallString<256> outPath(file);
        sys::path::replace_extension(outPath, "");
        std::string outputPath = std::string(outPath) + ".i.allocs";
        std::error_code ec;
        auto outStream = std::make_shared<raw_fd_ostream>(outputPath, ec);
        return std::make_unique<NewDetectorConsumer>(&CI.getASTContext(), std::move(outStream));
    }
};

int main(int argc, const char **argv) {
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, MyToolCategory);

    if (!ExpectedParser) {
        errs() << ExpectedParser.takeError();
        return 1;
    }

    CommonOptionsParser& OptionsParser = ExpectedParser.get();
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    return Tool.run(newFrontendActionFactory<NewDetectorAction>().get());
}
