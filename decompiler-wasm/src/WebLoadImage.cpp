// Pyre — MIT

#include "WebLoadImage.h"

#include "error.hh"

#include <cstring>
#include <sstream>

namespace pyre {

using ::ghidra::Address;
using ::ghidra::DataUnavailError;
using ::ghidra::int4;
using ::ghidra::uint1;

WebLoadImage::WebLoadImage() : LoadImage("pyre") {}

void WebLoadImage::addRegion(uint64_t addr, const uint8_t *bytes, size_t size) {
    regions.push_back({addr, std::vector<uint8_t>(bytes, bytes + size)});
}

void WebLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr) {
    if (ptr == nullptr || size <= 0) return;

    const uint64_t start = addr.getOffset();
    const uint64_t end = start + static_cast<uint64_t>(size);

    // Zero-fill any bytes not covered by a region. The decompiler's
    // string manager peeks 32 bytes at a time hunting for a NUL
    // terminator — a strict "must be in one region" check would
    // refuse to read short strings near a section boundary.
    std::memset(ptr, 0, static_cast<size_t>(size));

    bool any_filled = false;
    for (const auto &r : regions) {
        const uint64_t r_start = r.base;
        const uint64_t r_end = r.base + r.bytes.size();
        const uint64_t overlap_start = start > r_start ? start : r_start;
        const uint64_t overlap_end = end < r_end ? end : r_end;
        if (overlap_start < overlap_end) {
            std::memcpy(ptr + (overlap_start - start),
                        r.bytes.data() + (overlap_start - r_start),
                        static_cast<size_t>(overlap_end - overlap_start));
            any_filled = true;
        }
    }

    if (!any_filled) {
        std::ostringstream oss;
        oss << "bytes unavailable at 0x" << std::hex << start;
        throw DataUnavailError(oss.str());
    }
}

std::string WebLoadImage::getArchType() const { return "pyre"; }

void WebLoadImage::adjustVma(long adjust) {
    // Mirrors the LLDB plugin's behavior: reject VMA adjustment.
    // Regions carry their absolute VMAs at construction time and
    // shifting them after the fact would invalidate any addresses
    // already handed out to the decompiler.
    throw ::ghidra::LowlevelError("Cannot adjust pyre load image");
}

}  // namespace pyre
