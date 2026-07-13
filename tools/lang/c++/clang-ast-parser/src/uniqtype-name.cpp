#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include <cstdint>
#include <cstdio>

using namespace clang;

// FNV-1a hash over bytes — deterministic source-location fingerprint.
static uint32_t fnv1a(const std::string& s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

// Encode a type-name string into a valid C identifier, matching the
// identFromString / mangle_string convention used by cilallocs.ml and
// liballocstool: existing '$' → "$$", everything outside [a-zA-Z0-9_]
// → "$XX" (lowercase two-hex-digit ASCII code).
static std::string identFromString(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '$') {
            result += "$$";
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_') {
            result += static_cast<char>(c);
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "$%02x", static_cast<unsigned>(c));
            result += buf;
        }
    }
    return result;
}

std::string uniqtypeNameFromClangType(QualType qt, ASTContext *ctx,
                                       const std::string& hint) {
    if (qt.isNull()) return "__uniqtype____uninterpreted_byte";

	const Type *T = qt.getTypePtr();

    // For records (struct/class): use tag name; for anonymous records use the typedef name
    // or, if a variable-name hint is supplied, generate __anonstruct_<hint>_<hash>.
    if (const RecordType *RT = T->getAs<RecordType>()) {
        RecordDecl *RD = RT->getDecl();
        if (!RD->getDeclName().isEmpty()) {
            // For template specialisations getQualifiedNameAsString() drops the
            // template arguments, so use the QualType printer instead — it gives
            // "Point<A>" or "std::vector<int>" — then encode to a valid symbol.
            if (isa<ClassTemplateSpecializationDecl>(RD)) {
                PrintingPolicy pp = ctx->getPrintingPolicy();
                pp.SuppressTagKeyword = true;
                return "__uniqtype__" + identFromString(qt.getAsString(pp));
            }
            return "__uniqtype__" + identFromString(RD->getQualifiedNameAsString());
        }
        if (const TypedefNameDecl *TND = RD->getTypedefNameForAnonDecl())
            return "__uniqtype__" + identFromString(TND->getQualifiedNameAsString());
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
            return "__uniqtype__" + identFromString(ED->getQualifiedNameAsString());
        if (const TypedefNameDecl *TND = ED->getTypedefNameForAnonDecl())
            return "__uniqtype__" + identFromString(TND->getQualifiedNameAsString());
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

