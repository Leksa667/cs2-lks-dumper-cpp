#pragma once

#include "cs2dumper/memory/process.hpp"

#include <cstddef>
#include <cstdint>

namespace cs2dumper::memory {

inline uintptr_t resolve_rip(const ProcessMemory& process, uintptr_t base, size_t offset = 3) {
    const int32_t rel32 = process.read<int32_t>(base + offset);
    const uintptr_t instr_end = base + offset + sizeof(int32_t);
    return static_cast<uintptr_t>(static_cast<int64_t>(instr_end) + rel32);
}

} // namespace cs2dumper::memory
