#pragma once

#include "cs2dumper/memory/process.hpp"
#include "cs2dumper/pe/pattern_scanner.hpp"
#include "cs2dumper/pe/pe_view.hpp"
#include "cs2dumper/types.hpp"

#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace cs2dumper::analysis {

using memory::ProcessMemory;
using pe::PeView;
using pe::finds_code;

using OffsetCallback = std::function<void(const PeView&, std::map<std::string, Rva>&, Rva)>;

struct OffsetPattern {
    std::string name;
    std::string pattern;
    OffsetCallback callback;
};

inline void scan_module_offsets(
    const PeView& view,
    const std::vector<OffsetPattern>& patterns,
    std::map<std::string, Rva>& map) {
    for (const auto& entry : patterns) {
        std::vector<uint32_t> save;
        if (!finds_code(view, entry.pattern, save)) {
            std::cerr << "outdated pattern: " << entry.name << '\n';
            continue;
        }

        const Rva rva = save[1];
        map[entry.name] = rva;

        if (entry.callback) {
            entry.callback(view, map, rva);
        }
    }
}

inline std::map<std::string, Rva> client_offsets(const PeView& view) {
    std::map<std::string, Rva> map;

    const std::vector<OffsetPattern> patterns = {
        {"dwCSGOInput", "488905${'} 0f57c0 0f1105",
         [](const PeView& v, std::map<std::string, Rva>& m, Rva rva) {
             std::vector<uint32_t> save(2);
             if (finds_code(v, "f2420f108428u4", save)) {
                 m["dwViewAngles"] = rva + save[1];
             }
         }},
        {"dwEntityList", "48890d${'} e9${} cc", nullptr},
        {"dwGameEntitySystem", "488b1d${'} 48891d[4] 4c63b3", nullptr},
        {"dwGameEntitySystem_highestEntityIndex", "ff81u4 4885d2", nullptr},
        {"dwGameRules", "f6c1010f85${} 4c8b05${'} 4d85", nullptr},
        {"dwGlobalVars", "488915${'} 488942", nullptr},
        {"dwGlowManager", "488b05${'} c3 cccccccccccccccc 8b41", nullptr},
        {"dwLocalPlayerController", "488b05${'} 4189be", nullptr},
        {"dwPlantedC4", "488b1d${'} 4532f6", nullptr},
        {"dwPrediction", "488d05${'} c3 cccccccccccccccc 405356 4154",
         [](const PeView& v, std::map<std::string, Rva>& m, Rva rva) {
             std::vector<uint32_t> save(2);
             if (finds_code(v, "4c39b6u4 74? 4488be", save)) {
                 m["dwLocalPlayerPawn"] = rva + save[1];
             }
         }},
        {"dwSensitivity", "488d0d${[8]'} 660f6ecd",
         [](const PeView&, std::map<std::string, Rva>& m, Rva) {
             m["dwSensitivity_sensitivity"] = 0x58;
         }},
        {"dwViewMatrix", "488d0d${'} 48c1e006", nullptr},
        {"dwViewRender", "488905${'} 488bc8 4885c0", nullptr},
        {"dwWeaponC4", "488b15${'} 488b5c24? ffc0 8905${} 488bc6 488934ea 80be", nullptr},
    };

    scan_module_offsets(view, patterns, map);
    return map;
}

inline std::map<std::string, Rva> engine2_offsets(const PeView& view) {
    std::map<std::string, Rva> map;
    const std::vector<OffsetPattern> patterns = {
        {"dwBuildNumber", "8905${'} 488d0d${} ff15${} 488b0d", nullptr},
        {"dwNetworkGameClient", "48893d${'} ff87", nullptr},
        {"dwNetworkGameClient_clientTickCount",
         "8b81u4 c3 cccccccccccccccccc 8b81${} c3 cccccccccccccccccc 83b9", nullptr},
        {"dwNetworkGameClient_deltaTick", "4c8db7u4 4c897c24", nullptr},
        {"dwNetworkGameClient_isBackgroundMap",
         "0fb681u4 c3 cccccccccccccccc 0fb681${} c3 cccccccccccccccc 4883ec", nullptr},
        {"dwNetworkGameClient_localPlayer", "428b94d3u4 5b 49ffe3 32c0 5b c3 cccccccccccccccc 4053", nullptr},
        {"dwNetworkGameClient_maxClients", "8b81u4 c3????????? 8b81[4] c3????????? 8b81", nullptr},
        {"dwNetworkGameClient_serverTickCount", "8b81u4 c3 cccccccccccccccccc 83b9", nullptr},
        {"dwNetworkGameClient_signOnState", "448b81u4 488d0d", nullptr},
        {"dwWindowHeight", "8b05${'} 8903", nullptr},
        {"dwWindowWidth", "8b05${'} 8907", nullptr},
    };
    scan_module_offsets(view, patterns, map);
    return map;
}

inline std::map<std::string, Rva> input_system_offsets(const PeView& view) {
    std::map<std::string, Rva> map;
    scan_module_offsets(view, {{"dwInputSystem", "488905${'} 33c0", nullptr}}, map);
    return map;
}

inline std::map<std::string, Rva> matchmaking_offsets(const PeView& view) {
    std::map<std::string, Rva> map;
    scan_module_offsets(view, {{"dwGameTypes", "488d0d${'} ff90", nullptr}}, map);
    return map;
}

inline std::map<std::string, Rva> soundsystem_offsets(const PeView& view) {
    std::map<std::string, Rva> map;
    const std::vector<OffsetPattern> patterns = {
        {"dwSoundSystem", "488d0d${'} e8${} 488b0d${} [3] 4c8b82", nullptr},
        {"dwSoundSystem_engineViewData", "0f1147u1 0f104e? 0f118f", nullptr},
    };
    scan_module_offsets(view, patterns, map);
    return map;
}

inline OffsetMap offsets(const ProcessMemory& process) {
    OffsetMap map;

    struct ModuleEntry {
        const char* name;
        std::map<std::string, Rva> (*scanner)(const PeView&);
    };

    const ModuleEntry modules[] = {
        {"client.dll", client_offsets},
        {"engine2.dll", engine2_offsets},
        {"inputsystem.dll", input_system_offsets},
        {"matchmaking.dll", matchmaking_offsets},
        {"soundsystem.dll", soundsystem_offsets},
    };

    for (const auto& entry : modules) {
        const auto module = process.module_by_name(entry.name);
        if (!module) {
            throw std::runtime_error(std::string("module not found: ") + entry.name);
        }

        const auto buf = process.read_raw(module->base, module->size);
        const PeView view(buf);
        map[entry.name] = entry.scanner(view);
    }

    return map;
}

} // namespace cs2dumper::analysis
