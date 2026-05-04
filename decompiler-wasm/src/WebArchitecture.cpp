// Pyre — MIT

#include "WebArchitecture.h"
#include "WebLoadImage.h"

#include "architecture.hh"
#include "coreaction.hh"
#include "type.hh"

namespace pyre {

using ::ghidra::Architecture;
using ::ghidra::DocumentStorage;
using ::ghidra::SleighArchitecture;
using ::ghidra::Translate;
using ::ghidra::TYPE_BOOL;
using ::ghidra::TYPE_CODE;
using ::ghidra::TYPE_FLOAT;
using ::ghidra::TYPE_INT;
using ::ghidra::TYPE_UINT;
using ::ghidra::TYPE_UNKNOWN;
using ::ghidra::TYPE_VOID;

WebArchitecture::WebArchitecture(const std::string &language_id,
                                 std::ostream *errstream)
    // First arg is the binary "filename"; we don't have one in the
    // browser, so use a placeholder. SleighArchitecture only uses it
    // for diagnostic output.
    : SleighArchitecture("pyre", language_id, errstream),
      image(new WebLoadImage()) {
    // collectSpecFiles must run after spec dirs are registered (caller
    // does that via SleighArchitecture::specpaths.addDir2Path). It
    // populates the language description registry that
    // resolveArchitecture() looks up by id.
    collectSpecFiles(*errorstream);
}

void WebArchitecture::addRegion(uint64_t addr, const uint8_t *bytes, size_t size) {
    image->addRegion(addr, bytes, size);
}

void WebArchitecture::buildLoader(DocumentStorage &store) {
    // Hand off ownership: Architecture::~Architecture deletes
    // `loader`. We hold a raw pointer in `image` but never delete
    // through it.
    loader = image;
}

void WebArchitecture::buildCoreTypes(DocumentStorage &store) {
    // Mirrors LLDBArchitecture::buildCoreTypes — these would normally
    // come from a <coretypes> XML element in the cspec, but bint/r2ghidra
    // both register them programmatically and we follow suit.
    types->setCoreType("void", 1, TYPE_VOID, false);

    types->setCoreType("bool", 1, TYPE_BOOL, false);
    types->setCoreType("bool4", 4, TYPE_BOOL, false);
    types->setCoreType("bool8", 8, TYPE_BOOL, false);

    types->setCoreType("uint8_t", 1, TYPE_UINT, false);
    types->setCoreType("uint16_t", 2, TYPE_UINT, false);
    types->setCoreType("uint32_t", 4, TYPE_UINT, false);
    types->setCoreType("uint64_t", 8, TYPE_UINT, false);
    types->setCoreType("int8_t", 1, TYPE_INT, false);
    types->setCoreType("int16_t", 2, TYPE_INT, false);
    types->setCoreType("int32_t", 4, TYPE_INT, false);
    types->setCoreType("int64_t", 8, TYPE_INT, false);
    types->setCoreType("int", sizeof(int), TYPE_INT, false);

    types->setCoreType("double", 8, TYPE_FLOAT, false);
    types->setCoreType("float", 4, TYPE_FLOAT, false);
    types->setCoreType("float8", 8, TYPE_FLOAT, false);
    types->setCoreType("float10", 10, TYPE_FLOAT, false);
    types->setCoreType("float16", 16, TYPE_FLOAT, false);

    types->setCoreType("uchar", 1, TYPE_UNKNOWN, false);
    types->setCoreType("ushort", 2, TYPE_UNKNOWN, false);
    types->setCoreType("uint", 4, TYPE_UNKNOWN, false);
    types->setCoreType("ulong", 8, TYPE_UNKNOWN, false);

    types->setCoreType("code", 1, TYPE_CODE, false);

    // `true` here flags the type as a character — printc renders char
    // arrays as string literals rather than byte arrays.
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("wchar", 2, TYPE_INT, true);
    types->setCoreType("char16_t", 2, TYPE_INT, true);
    types->setCoreType("char32_t", 4, TYPE_INT, true);

    types->cacheCoreTypes();
}

void WebArchitecture::buildAction(DocumentStorage &store) {
    // Same sequence the LLDB plugin uses. universalAction installs the
    // standard decompile passes (heritage, type prop, dead code, etc.);
    // resetDefaults primes the per-pass state.
    parseExtraRules(store);
    allacts.universalAction(this);
    allacts.resetDefaults();
}

void WebArchitecture::resolveArchitecture() {
    // Skip SleighArchitecture's binary-format-based detection — the
    // caller already handed us the SLEIGH id explicitly via getTarget(),
    // so we just publish that as archid and let the base finish the
    // load (translator instantiation, default code space wiring).
    archid = getTarget();
    SleighArchitecture::resolveArchitecture();
}

void WebArchitecture::postSpecFile() {
    // SleighArchitecture::postSpecFile assumes a binary loader that
    // populates per-section metadata; we don't have one. Fall through
    // to the grandparent's version, which is the no-op behavior we
    // actually want.
    Architecture::postSpecFile();
}

}  // namespace pyre
