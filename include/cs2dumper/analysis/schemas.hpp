#pragma once

#include "cs2dumper/memory/process.hpp"
#include "cs2dumper/pe/pattern_scanner.hpp"
#include "cs2dumper/pe/pe_view.hpp"
#include "cs2dumper/source2/schema.hpp"
#include "cs2dumper/source2/utl_ts_hash.hpp"
#include "cs2dumper/types.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace cs2dumper::analysis {

using memory::ProcessMemory;
using pe::PeView;
using pe::finds_code;
using namespace source2;

inline std::string replace_spaces(const std::string& input) {
    std::string result = input;
    result.erase(std::remove(result.begin(), result.end(), ' '), result.end());
    return result;
}

inline std::vector<ClassField> read_class_binding_fields(
    const ProcessMemory& process,
    const SchemaClassBinding& binding) {
    std::vector<ClassField> fields;
    if (binding.fields == 0) {
        return fields;
    }

    for (int16_t i = 0; i < binding.field_count; ++i) {
        const uintptr_t field_address =
            binding.fields + static_cast<uintptr_t>(i) * sizeof(SchemaClassFieldData);
        const SchemaClassFieldData field = process.read<SchemaClassFieldData>(field_address);
        if (field.type == 0) {
            continue;
        }

        const std::string name = process.read_utf8_lossy(field.name, 128);
        const SchemaType type = process.read<SchemaType>(field.type);
        const std::string type_name = replace_spaces(process.read_utf8_lossy(type.name, 128));

        fields.push_back({name, type_name, field.offset});
    }

    return fields;
}

inline std::vector<ClassMetadata> read_class_binding_metadata(
    const ProcessMemory& process,
    const SchemaClassBinding& binding) {
    std::vector<ClassMetadata> metadata;
    if (binding.static_metadata == 0) {
        return metadata;
    }

    for (int16_t i = 0; i < binding.static_metadata_count; ++i) {
        const uintptr_t metadata_address =
            binding.static_metadata + static_cast<uintptr_t>(i) * sizeof(SchemaMetadataEntryData);
        const SchemaMetadataEntryData entry = process.read<SchemaMetadataEntryData>(metadata_address);
        if (entry.network_value == 0) {
            continue;
        }

        const std::string meta_name = process.read_utf8_lossy(entry.name, 128);
        const SchemaNetworkValue network_value = process.read<SchemaNetworkValue>(entry.network_value);

        if (meta_name == "MNetworkChangeCallback") {
            const std::string name = process.read_utf8_lossy(network_value.value.name_ptr, 128);
            metadata.push_back(ClassMetadataNetworkChangeCallback{name});
        } else if (meta_name == "MNetworkVarNames") {
            const std::string name = process.read_utf8_lossy(network_value.value.var_value.name, 128);
            const std::string type_name =
                replace_spaces(process.read_utf8_lossy(network_value.value.var_value.type_name, 128));
            metadata.push_back(ClassMetadataNetworkVarNames{name, type_name});
        } else {
            metadata.push_back(ClassMetadataUnknown{meta_name});
        }
    }

    return metadata;
}

inline Class read_class_binding(const ProcessMemory& process, uintptr_t binding_ptr) {
    const SchemaClassBinding binding = process.read<SchemaClassBinding>(binding_ptr);

    std::string module_name = process.read_utf8_lossy(binding.module_name, 128);
    module_name += ".dll";

    const std::string name = process.read_utf8_lossy(binding.name, 128);
    if (name.empty()) {
        throw std::runtime_error("invalid class name");
    }

    std::optional<std::string> parent_name;
    if (binding.base_classes != 0) {
        const SchemaBaseClassInfoData base_class = process.read<SchemaBaseClassInfoData>(binding.base_classes);
        if (base_class.class_ptr != 0) {
            const SchemaBaseClass parent = process.read<SchemaBaseClass>(base_class.class_ptr);
            const std::string parent_str = process.read_utf8_lossy(parent.name, 128);
            if (!parent_str.empty()) {
                parent_name = parent_str;
            }
        }
    }

    return Class{
        name,
        module_name,
        parent_name,
        read_class_binding_metadata(process, binding),
        read_class_binding_fields(process, binding),
    };
}

inline std::vector<EnumMember> read_enum_binding_members(
    const ProcessMemory& process,
    const SchemaEnumBinding& binding) {
    std::vector<EnumMember> members;
    if (binding.enumerators == 0) {
        return members;
    }

    for (uint16_t i = 0; i < binding.enumerator_count; ++i) {
        const uintptr_t enumerator_address =
            binding.enumerators + static_cast<uintptr_t>(i) * sizeof(SchemaEnumeratorInfoData);
        const SchemaEnumeratorInfoData enumerator = process.read<SchemaEnumeratorInfoData>(enumerator_address);
        const std::string member_name = process.read_utf8_lossy(enumerator.name, 128);
        members.push_back({member_name, static_cast<int64_t>(enumerator.value.ulong)});
    }

    return members;
}

inline Enum read_enum_binding(const ProcessMemory& process, uintptr_t binding_ptr) {
    const SchemaEnumBinding binding = process.read<SchemaEnumBinding>(binding_ptr);

    const std::string name = process.read_utf8_lossy(binding.name, 128);
    if (name.empty()) {
        throw std::runtime_error("invalid enum name");
    }

    return Enum{
        name,
        binding.alignment,
        binding.enumerator_count,
        read_enum_binding_members(process, binding),
    };
}

inline SchemaSystem read_schema_system(const ProcessMemory& process) {
    const auto module = process.module_by_name("schemasystem.dll");
    if (!module) {
        throw std::runtime_error("schemasystem.dll not found");
    }

    const auto buf = process.read_raw(module->base, module->size);
    const PeView view(buf);

    std::vector<uint32_t> save(2);
    if (!finds_code(view, "4c8d35${'} 0f2845", save)) {
        throw std::runtime_error("outdated schema system pattern");
    }

    const SchemaSystem schema_system = process.read<SchemaSystem>(module->base + save[1]);
    if (schema_system.registration_count == 0) {
        throw std::runtime_error("no schema registrations");
    }

    return schema_system;
}

inline SchemaMap schemas(const ProcessMemory& process) {
    const SchemaSystem schema_system = read_schema_system(process);
    SchemaMap result;

    for (int32_t i = 0; i < schema_system.type_scopes.count; ++i) {
        const uintptr_t type_scope_ptr =
            process.read<uintptr_t>(schema_system.type_scopes.data + static_cast<uintptr_t>(i) * sizeof(uintptr_t));
        if (type_scope_ptr == 0) {
            continue;
        }

        const SchemaSystemTypeScope type_scope = process.read<SchemaSystemTypeScope>(type_scope_ptr);
        const std::string module_name(type_scope.name);

        std::vector<Class> classes;
        for (const uintptr_t ptr : UtlTsHashWalker<SchemaClassBinding>::elements(process, type_scope.class_bindings)) {
            try {
                classes.push_back(read_class_binding(process, ptr));
            } catch (...) {
            }
        }

        std::vector<Enum> enums;
        for (const uintptr_t ptr : UtlTsHashWalker<SchemaEnumBinding>::elements(process, type_scope.enum_bindings)) {
            try {
                enums.push_back(read_enum_binding(process, ptr));
            } catch (...) {
            }
        }

        if (classes.empty() && enums.empty()) {
            continue;
        }

        result[module_name] = {std::move(classes), std::move(enums)};
    }

    return result;
}

} // namespace cs2dumper::analysis
