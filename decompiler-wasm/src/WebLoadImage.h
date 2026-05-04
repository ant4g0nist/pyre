// Pyre — MIT
// Multi-region LoadImage for the browser. Holds an arbitrary set of
// memory regions keyed by virtual address; the decompiler reads bytes
// from whichever region overlaps the requested range.
//
// Why multi-region (vs. flat single-buffer + base): Mach-O segments
// sit at non-contiguous VMAs, and even ELF binaries can have entry
// points far from the first PT_LOAD page. A flat projection
// `file_offset = vaddr - base` silently aliases the wrong bytes for
// either case.

#ifndef PYRE_WEB_LOADIMAGE_H
#define PYRE_WEB_LOADIMAGE_H

#include "loadimage.hh"

#include <cstdint>
#include <vector>

namespace pyre {

class WebLoadImage : public ::ghidra::LoadImage {
    struct Region {
        uint64_t base;
        std::vector<uint8_t> bytes;
    };
    std::vector<Region> regions;

public:
    WebLoadImage();

    // Copies `bytes[0..size]` into a new region mapped at `addr`. Safe
    // to call any number of times before the first decompile.
    void addRegion(uint64_t addr, const uint8_t *bytes, size_t size);

    // LoadImage overrides
    void loadFill(::ghidra::uint1 *ptr, ::ghidra::int4 size,
                  const ::ghidra::Address &addr) override;
    std::string getArchType() const override;
    void adjustVma(long adjust) override;
};

}  // namespace pyre

#endif  // PYRE_WEB_LOADIMAGE_H
