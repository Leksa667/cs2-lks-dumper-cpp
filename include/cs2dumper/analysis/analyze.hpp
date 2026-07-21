#pragma once

#include "cs2dumper/analysis/buttons.hpp"
#include "cs2dumper/analysis/interfaces.hpp"
#include "cs2dumper/analysis/offsets.hpp"
#include "cs2dumper/analysis/schemas.hpp"
#include "cs2dumper/memory/process.hpp"
#include "cs2dumper/types.hpp"

#include <iostream>
#include <type_traits>

namespace cs2dumper::analysis {

using memory::ProcessMemory;

template <typename F>
auto analyze(const ProcessMemory& process, F&& func) -> std::invoke_result_t<F, const ProcessMemory&> {
    using T = std::invoke_result_t<F, const ProcessMemory&>;
    try {
        return func(process);
    } catch (const std::exception& err) {
        std::cerr << "failed to read analysis: " << err.what() << '\n';
        return T{};
    }
}

inline AnalysisResult analyze_all(const ProcessMemory& process) {
    const auto buttons_result = analyze(process, buttons);
    std::cout << "found " << buttons_result.size() << " buttons\n";

    const auto interfaces_result = analyze(process, interfaces);
    size_t iface_count = 0;
    for (const auto& entry : interfaces_result) {
        iface_count += entry.second.size();
    }
    std::cout << "found " << iface_count << " interfaces across " << interfaces_result.size() << " modules\n";

    const auto offsets_result = analyze(process, offsets);
    size_t offset_count = 0;
    for (const auto& entry : offsets_result) {
        offset_count += entry.second.size();
    }
    std::cout << "found " << offset_count << " offsets across " << offsets_result.size() << " modules\n";

    const auto schemas_result = analyze(process, schemas);
    size_t class_count = 0;
    size_t enum_count = 0;
    for (const auto& entry : schemas_result) {
        class_count += entry.second.first.size();
        enum_count += entry.second.second.size();
    }
    std::cout << "found " << class_count << " classes and " << enum_count << " enums across "
              << schemas_result.size() << " modules\n";

    return AnalysisResult{
        buttons_result,
        interfaces_result,
        offsets_result,
        schemas_result,
    };
}

} // namespace cs2dumper::analysis
