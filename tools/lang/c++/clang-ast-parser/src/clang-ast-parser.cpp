#include "allocators.h"
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
    explicit NewDetectorConsumer(ASTContext *Context,
                                 std::shared_ptr<raw_fd_ostream> outStream,
                                 const AllocTable& allocTable)
        : Visitor(Context, outStream, allocTable) {}
    void HandleTranslationUnit(ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    NewDetectorVisitor Visitor;
};

class NewDetectorAction : public ASTFrontendAction {
    const AllocTable& allocTable;
public:
    explicit NewDetectorAction(const AllocTable& t) : allocTable(t) {}
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                    StringRef file) override {
        SmallString<256> outPath(file);
        sys::path::replace_extension(outPath, "");
        std::string outputPath = std::string(outPath) + ".i.allocs";
        std::error_code ec;
        auto outStream = std::make_shared<raw_fd_ostream>(outputPath, ec);
        return std::make_unique<NewDetectorConsumer>(&CI.getASTContext(),
                                                      std::move(outStream),
                                                      allocTable);
    }
};

struct NewDetectorActionFactory : public FrontendActionFactory {
    const AllocTable& allocTable;
    explicit NewDetectorActionFactory(const AllocTable& t) : allocTable(t) {}
    std::unique_ptr<FrontendAction> create() override {
        return std::make_unique<NewDetectorAction>(allocTable);
    }
};

int main(int argc, const char **argv) {
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, MyToolCategory);
    if (!ExpectedParser) {
        errs() << ExpectedParser.takeError();
        return 1;
    }

    AllocTable allocTable = buildAllocTable();

    CommonOptionsParser& OptionsParser = ExpectedParser.get();
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());
    NewDetectorActionFactory factory(allocTable);
    return Tool.run(&factory);
}
