#pragma once

#include "cs2dumper/memory/address.hpp"
#include "cs2dumper/memory/process.hpp"
#include "cs2dumper/pe/pattern_scanner.hpp"
#include "cs2dumper/pe/pe_view.hpp"
#include "cs2dumper/source2/client.hpp"
#include "cs2dumper/types.hpp"

#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace cs2dumper::analysis {

using memory::ProcessMemory;
using pe::PeView;
using pe::finds_code;
using source2::KeyButton;
using source2::key_button_state_offset;

inline ButtonMap buttons(const ProcessMemory& process) {
    const auto module = process.module_by_name("client.dll");
    if (!module) {
        throw std::runtime_error("client.dll not found");
    }

    const auto buf = process.read_raw(module->base, module->size);
    const PeView view(buf);

    std::vector<uint32_t> save(2);
    if (!finds_code(view, "488b15${'} 4885d2 74? 488b02 4885c0", save)) {
        throw std::runtime_error("outdated button list pattern");
    }

    const uintptr_t list_head = process.read_addr64(module->base + save[1]);
    ButtonMap result;

    uintptr_t button_ptr = list_head;
    while (button_ptr != 0) {
        const KeyButton button = process.read<KeyButton>(button_ptr);
        const std::string name = process.read_utf8_lossy(button.name, 32);
        const uintptr_t state_addr = button_ptr + key_button_state_offset;

        if (state_addr >= module->base) {
            result[name] = state_addr - module->base;
        }

        button_ptr = button.next;
    }

    return result;
}

} // namespace cs2dumper::analysis
