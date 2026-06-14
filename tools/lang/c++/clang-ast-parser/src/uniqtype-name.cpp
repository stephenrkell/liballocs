#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"

using namespace clang;

std::string uniqtypeNameFromClangType(QualType qt, ASTContext *ctx) {
	const Type *T = qt.getTypePtr();

    // For records (struct/class): use tag name
    if (const RecordType *RT = T->getAs<RecordType>()) {
        std::string name = RT->getDecl()->getQualifiedNameAsString();
        if (!name.empty()) return "__uniqtype__" + name;
    }

    // For built-in types: use canonical name + bit width
    if (const BuiltinType *BT = T->getAs<BuiltinType>()) {
        uint64_t bits = ctx->getTypeSize(qt);
        std::string canonName = BT->getName(ctx->getPrintingPolicy()).str();
        // Map to DWARF canonical name (e.g. "int" → "int", "char" → "signed char")
        std::replace(canonName.begin(), canonName.end(), ' ', '_');
        return "__uniqtype__" + canonName + "$$" + std::to_string(bits);
    }

    // Pointer types
    if (T->isPointerType()) {
        QualType pointee = T->getPointeeType();
        return "__uniqtype____PTR_" + uniqtypeNameFromClangType(pointee, ctx);
    }

    // Unknown / too complex — fall back to uninterpreted byte
    return "__uniqtype____uninterpreted_byte";
}

