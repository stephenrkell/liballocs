#include "visitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "llvm/Support/CommandLine.h"

using namespace clang;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory MyToolCategory("my-tool-options");

class NewDetectorConsumer : public ASTConsumer {
public:
    explicit NewDetectorConsumer(ASTContext *Context, std::shared_ptr<raw_fd_ostream> outStream)
        : Visitor(Context, outStream) {}
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
