#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include <cstdint>

using namespace clang;

// FNV-1a hash over bytes — deterministic source-location fingerprint.
static uint32_t fnv1a(const std::string& s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

std::string uniqtypeNameFromClangType(QualType qt, ASTContext *ctx,
                                       const std::string& hint) {
    if (qt.isNull()) return "__uniqtype____uninterpreted_byte";

	const Type *T = qt.getTypePtr();

    // For records (struct/class): use tag name; for anonymous records use the typedef name
    // or, if a variable-name hint is supplied, generate __anonstruct_<hint>_<hash>.
    if (const RecordType *RT = T->getAs<RecordType>()) {
        RecordDecl *RD = RT->getDecl();
        if (!RD->getDeclName().isEmpty())
            return "__uniqtype__" + RD->getQualifiedNameAsString();
        if (const TypedefNameDecl *TND = RD->getTypedefNameForAnonDecl())
            return "__uniqtype__" + TND->getQualifiedNameAsString();
        if (!hint.empty()) {
            SourceLocation loc = RD->getBeginLoc();
            std::string file = ctx->getSourceManager().getFilename(loc).str();
            unsigned line = ctx->getSourceManager().getSpellingLineNumber(loc);
            uint32_t h = fnv1a(file + ":" + std::to_string(line));
            return "__uniqtype____anonstruct_" + hint + "_" + std::to_string(h);
        }
    }

    // For enums: use tag name; anonymous enums fall back to typedef name.
    if (const EnumType *ET = T->getAs<EnumType>()) {
        EnumDecl *ED = ET->getDecl();
        if (!ED->getDeclName().isEmpty())
            return "__uniqtype__" + ED->getQualifiedNameAsString();
        if (const TypedefNameDecl *TND = ED->getTypedefNameForAnonDecl())
            return "__uniqtype__" + TND->getQualifiedNameAsString();
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
        return "__uniqtype____PTR_" + uniqtypeNameFromClangType(pointee, ctx, hint);
    }

    // Unknown / too complex — fall back to uninterpreted byte
    return "__uniqtype____uninterpreted_byte";
}

