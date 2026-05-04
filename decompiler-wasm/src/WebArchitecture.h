// Pyre — MIT
// SleighArchitecture subclass for the browser. Drops every LLDB SB type;
// receives memory regions and symbols through explicit add* calls before
// the first decompile.

#ifndef PYRE_WEB_ARCHITECTURE_H
#define PYRE_WEB_ARCHITECTURE_H

#include "sleigh_arch.hh"

#include <cstdint>
#include <string>

namespace pyre {

class WebLoadImage;

class WebArchitecture : public ::ghidra::SleighArchitecture {
    WebLoadImage *image;

public:
    // `language_id` is a SLEIGH ID like "x86:LE:64:default:gcc". The
    // architecture is bound at construction; once you have a handle,
    // the language can't change.
    WebArchitecture(const std::string &language_id, std::ostream *errstream);

    // Proxies that forward to the load image. Lifetimes line up with
    // the architecture's own — calling these after the architecture is
    // destroyed is undefined.
    void addRegion(uint64_t addr, const uint8_t *bytes, size_t size);

protected:
    void buildLoader(::ghidra::DocumentStorage &store) override;
    void buildCoreTypes(::ghidra::DocumentStorage &store) override;
    void buildAction(::ghidra::DocumentStorage &store) override;
    void resolveArchitecture() override;
    void postSpecFile() override;
};

}  // namespace pyre

#endif  // PYRE_WEB_ARCHITECTURE_H
