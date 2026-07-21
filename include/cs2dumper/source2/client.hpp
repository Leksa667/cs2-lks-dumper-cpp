#pragma once

#include <cstdint>

namespace cs2dumper::source2 {

struct InterfaceReg {
    uintptr_t create_fn;
    uintptr_t name;
    uintptr_t next;
};

struct KeyButton {
    uint8_t pad0[0x8];
    uintptr_t name;
    uint8_t pad1[0x20];
    uint32_t state;
    uint8_t pad2[0x54];
    uintptr_t next;
};

static constexpr size_t key_button_state_offset = 0x30;

} // namespace cs2dumper::source2
