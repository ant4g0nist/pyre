// Pyre — MIT
// extern "C" API exposed to the JS worker through emscripten ccall/cwrap.
// The worker owns the wasm module and serializes every call across
// requests; we don't take any locks here.

#include "WebArchitecture.h"
#include "WebLoadImage.h"
#include "libc_prototypes.h"

#include "address.hh"
#include "architecture.hh"
#include "capability.hh"
#include "database.hh"
#include "error.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "printlanguage.hh"
#include "sleigh_arch.hh"
#include "type.hh"
#include "varnode.hh"

#include <emscripten/emscripten.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

namespace {

using ::ghidra::Address;
using ::ghidra::AddrSpace;
using ::ghidra::Datatype;
using ::ghidra::DataUnavailError;
using ::ghidra::DocumentStorage;
using ::ghidra::FunctionSymbol;
using ::ghidra::Funcdata;
using ::ghidra::LowlevelError;
using ::ghidra::Range;
using ::ghidra::Scope;
using ::ghidra::SleighArchitecture;
using ::ghidra::Varnode;
using ::ghidra::int4;
using ::ghidra::startDecompilerLibrary;

bool g_initialized = false;

// One handle per binary-in-flight. The decompiler architecture owns
// its load image and symbol table; we own the architecture.
struct DecompilerHandle {
    pyre::WebArchitecture *arch;
    // Defer the libc prototype import to first decompile() — parse_C
    // binds prototypes to symbols *by name*, so running it before the
    // JS caller's add_symbol calls would silently bind to nothing.
    bool libc_imported = false;
    explicit DecompilerHandle(pyre::WebArchitecture *a) : arch(a) {}
    ~DecompilerHandle() { delete arch; }
};

// Feed the bundled libc declarations through Ghidra's C parser.
// Splits on `;` so a single malformed declaration doesn't poison the
// rest of the catalogue. Errors are intentionally swallowed — a
// missing/typo'd prototype is worse for output prettiness than for
// correctness, and the surrounding decompile() must not abort.
void import_libc_prototypes(pyre::WebArchitecture *arch) {
    std::string buf(pyre::LIBC_PROTOTYPES);
    size_t pos = 0;
    while (pos < buf.size()) {
        size_t semi = buf.find(';', pos);
        if (semi == std::string::npos) break;
        std::string decl = buf.substr(pos, semi - pos + 1);
        pos = semi + 1;
        bool has_non_ws = false;
        for (char c : decl) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
                has_non_ws = true;
                break;
            }
        }
        if (!has_non_ws) continue;
        try {
            std::istringstream is(decl);
            ::ghidra::parse_C(arch, is);
        } catch (const LowlevelError &) {
        } catch (const std::exception &) {
        }
    }
}

// One-shot SLEIGH library bring-up. Idempotent; safe to call from
// every entry point. Implementation mirrors libdecomp's
// startDecompilerLibrary(extrapaths) but skips the path bookkeeping
// since the JS worker registers spec dirs explicitly via
// pyre_add_spec_dir.
void ensure_initialized() {
    if (g_initialized) return;
    startDecompilerLibrary(std::vector<std::string>{});
    g_initialized = true;
}

}  // namespace

extern "C" {

// One-time decompiler library init, optionally seeded with one spec
// root. The JS side normally prefers add_spec_dir per-arch (lazy mount
// pattern), so this entry point is mostly here for tests that don't
// care about lazy mounting.
EMSCRIPTEN_KEEPALIVE
int pyre_init(const char *spec_root) {
    try {
        ensure_initialized();
        if (spec_root && *spec_root) {
            SleighArchitecture::specpaths.addDir2Path(spec_root);
        }
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "pyre_init: " << e.what() << std::endl;
        return 1;
    }
}

// Append one .../data/languages directory to the SLEIGH search path.
// Called once per processor as the worker lazy-mounts arch specs.
EMSCRIPTEN_KEEPALIVE
int pyre_add_spec_dir(const char *dir) {
    try {
        ensure_initialized();
        if (!dir || !*dir) return -1;
        SleighArchitecture::specpaths.addDir2Path(dir);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "pyre_add_spec_dir: " << e.what() << std::endl;
        return -1;
    }
}

// Build a decompiler handle bound to a SLEIGH language id like
// "x86:LE:64:default:gcc". The handle starts empty — the caller must
// add at least one memory region before the first decompile.
EMSCRIPTEN_KEEPALIVE
void *pyre_create(const char *language_id) {
    if (!language_id || !*language_id) return nullptr;
    pyre::WebArchitecture *arch = nullptr;
    try {
        ensure_initialized();
        arch = new pyre::WebArchitecture(language_id, &std::cerr);
        DocumentStorage store;
        arch->init(store);
    } catch (const LowlevelError &e) {
        std::cerr << "pyre_create: " << e.explain << std::endl;
        delete arch;
        return nullptr;
    } catch (const std::exception &e) {
        std::cerr << "pyre_create: " << e.what() << std::endl;
        delete arch;
        return nullptr;
    }
    return new DecompilerHandle(arch);
}

EMSCRIPTEN_KEEPALIVE
int pyre_add_region(void *handle, uint64_t addr,
                        const uint8_t *bytes, size_t size) {
    if (!handle || !bytes || size == 0) return -1;
    try {
        auto *h = static_cast<DecompilerHandle *>(handle);
        h->arch->addRegion(addr, bytes, size);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "pyre_add_region: " << e.what() << std::endl;
        return -1;
    }
}

// Register a named function symbol. Idempotent — silently skipped if
// a function is already known at this address.
EMSCRIPTEN_KEEPALIVE
int pyre_add_symbol(void *handle, uint64_t address, const char *name) {
    if (!handle || !name || !*name) return -1;
    try {
        auto *h = static_cast<DecompilerHandle *>(handle);
        AddrSpace *space = h->arch->getDefaultCodeSpace();
        Scope *scope = h->arch->symboltab->getGlobalScope();
        Address a(space, address);
        if (scope->findFunction(a) != nullptr) return 0;
        scope->addFunction(a, std::string(name));
        return 0;
    } catch (const std::exception &) {
        return -1;
    }
}

// Register a printable C string at `address` of `length` bytes (NUL
// excluded) as a `char[length]` symbol. Loads that resolve there
// render as the string literal in decompiled output.
EMSCRIPTEN_KEEPALIVE
int pyre_add_string(void *handle, uint64_t address, uint64_t length) {
    if (!handle || length == 0) return -1;
    try {
        auto *h = static_cast<DecompilerHandle *>(handle);
        AddrSpace *space = h->arch->getDefaultCodeSpace();
        Scope *scope = h->arch->symboltab->getGlobalScope();
        Address a(space, address);
        if (scope->queryContainer(a, 1, Address()) != nullptr) return 0;
        Datatype *char_t = h->arch->types->getTypeChar(1);
        // Cap absurd lengths so a corrupt input can't allocate a
        // multi-gigabyte array type.
        int4 len = static_cast<int4>(std::min<uint64_t>(length, 4096));
        Datatype *arr_t = h->arch->types->getTypeArray(len, char_t);
        std::ostringstream nm;
        nm << "s_" << std::hex << address;
        scope->addSymbol(nm.str(), arr_t, a, Address());
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "pyre_add_string: " << e.what() << std::endl;
        return -1;
    }
}

// Mark a range as readonly. The decompiler propagates this flag onto
// p-code varnodes derived from that range, which (combined with
// add_string) lets the printer render constant string loads as
// literals instead of pointer arithmetic.
EMSCRIPTEN_KEEPALIVE
int pyre_add_readonly(void *handle, uint64_t address, uint64_t size) {
    if (!handle || size == 0) return -1;
    try {
        auto *h = static_cast<DecompilerHandle *>(handle);
        AddrSpace *space = h->arch->getDefaultCodeSpace();
        h->arch->symboltab->setPropertyRange(
            Varnode::readonly,
            Range(space, address, address + size - 1));
        return 0;
    } catch (const std::exception &) {
        return -1;
    }
}

// Decompile the function at `address`. Returns a malloc'd C string —
// caller must free via pyre_free_string. Returns nullptr only on
// catastrophic failure; recoverable errors come back as a `/* error */`
// comment string so the UI always has something to show.
EMSCRIPTEN_KEEPALIVE
char *pyre_decompile(void *handle, uint64_t address, const char *name) {
    if (!handle) return nullptr;
    auto *h = static_cast<DecompilerHandle *>(handle);

    // First-decompile lazy import of the libc catalogue. Has to happen
    // AFTER the JS caller's add_symbol calls so parse_C can bind
    // "puts" etc. to the imported symbols those calls registered.
    if (!h->libc_imported) {
        import_libc_prototypes(h->arch);
        h->libc_imported = true;
    }

    auto returnError = [](const std::string &msg) -> char * {
        std::string out = "/* decompile error: " + msg + " */";
        char *buf = static_cast<char *>(std::malloc(out.size() + 1));
        if (!buf) return nullptr;
        std::memcpy(buf, out.data(), out.size() + 1);
        return buf;
    };

    try {
        AddrSpace *space = h->arch->getDefaultCodeSpace();
        Address addr(space, address);
        Scope *scope = h->arch->symboltab->getGlobalScope();

        Funcdata *fd = scope->findFunction(addr);
        if (fd == nullptr) {
            // Drop in a synthesized name so the printer has something
            // to call this function. The JS caller can pass `name` to
            // override the default `FUN_xxx` style.
            std::string nm = (name && *name) ? std::string(name) : "";
            if (nm.empty()) {
                std::ostringstream oss;
                oss << "FUN_" << std::hex << address;
                nm = oss.str();
            }
            FunctionSymbol *sym = scope->addFunction(addr, nm);
            fd = sym->getFunction();
        } else {
            // Re-decompile path: drop prior analysis so the action
            // pool starts from a clean slate. Without this, repeated
            // decompiles of the same function compound state and
            // eventually assert.
            h->arch->clearAnalysis(fd);
        }

        auto action = h->arch->allacts.getCurrent();
        action->reset(*fd);
        int res = action->perform(*fd);
        if (res < 0) return returnError("decompilation interrupted");

        std::ostringstream oss;
        h->arch->print->setOutputStream(&oss);
        h->arch->print->docFunction(fd);

        std::string out = oss.str();
        char *buf = static_cast<char *>(std::malloc(out.size() + 1));
        if (!buf) return nullptr;
        std::memcpy(buf, out.data(), out.size());
        buf[out.size()] = '\0';
        return buf;
    } catch (const LowlevelError &e) {
        return returnError(e.explain);
    } catch (const std::exception &e) {
        return returnError(e.what());
    }
}

EMSCRIPTEN_KEEPALIVE
void pyre_free_string(char *s) { std::free(s); }

EMSCRIPTEN_KEEPALIVE
void pyre_destroy(void *handle) {
    if (!handle) return;
    delete static_cast<DecompilerHandle *>(handle);
}

}  // extern "C"
