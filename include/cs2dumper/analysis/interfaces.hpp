#pragma once

#include "cs2dumper/memory/address.hpp"
#include "cs2dumper/memory/process.hpp"
#include "cs2dumper/pe/pe_view.hpp"
#include "cs2dumper/source2/client.hpp"
#include "cs2dumper/types.hpp"

#include <map>
#include <stdexcept>
#include <cstddef>

namespace cs2dumper::analysis {

using memory::ProcessMemory;
using pe::PeView;
using source2::InterfaceReg;

inline InterfaceMap interfaces(const ProcessMemory& process) {
    InterfaceMap result;

    for (const auto& module : process.module_list()) {
        std::vector<uint8_t> buf;
        try {
            buf = process.read_raw(module.base, module.size);
        } catch (...) {
            continue;
        }

        try {
            PeView view(buf);
            const auto symbol = view.export_symbol_rva("CreateInterface");
            if (!symbol) {
                continue;
            }

            uintptr_t list_ptr = 0;
            try {
                list_ptr = memory::resolve_rip(process, module.base + *symbol);
            } catch (...) {
                continue;
            }

            uintptr_t list_head = 0;
            try {
                list_head = process.read_addr64(list_ptr);
            } catch (...) {
                continue;
            }

            std::map<std::string, uintptr_t> module_interfaces;
            uintptr_t reg_ptr = list_head;
            size_t safety = 0;

            while (reg_ptr != 0 && safety++ < 1024) {
                InterfaceReg reg{};
                try {
                    reg = process.read<InterfaceReg>(reg_ptr);
                } catch (...) {
                    break;
                }

                const std::string iface_name = process.read_utf8_lossy(reg.name, 128);

                try {
                    const uintptr_t instance_addr = memory::resolve_rip(process, reg.create_fn);
                    if (instance_addr >= module.base) {
                        module_interfaces[iface_name] = instance_addr - module.base;
                    }
                } catch (...) {
                }

                reg_ptr = reg.next;
            }

            if (!module_interfaces.empty()) {
                result[module.name] = std::move(module_interfaces);
            }
        } catch (...) {
            continue;
        }
    }

    return result;
}

} // namespace cs2dumper::analysis
