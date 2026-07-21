#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace cs2dumper {

using Rva = uint32_t;

struct ModuleInfo {
    uintptr_t base{};
    size_t size{};
    std::string name;
};

struct ClassField {
    std::string name;
    std::string type_name;
    int32_t offset{};
};

struct EnumMember {
    std::string name;
    int64_t value{};
};

struct Enum {
    std::string name;
    uint8_t alignment{};
    uint16_t size{};
    std::vector<EnumMember> members;
};

struct ClassMetadataNetworkChangeCallback {
    std::string name;
};

struct ClassMetadataNetworkVarNames {
    std::string name;
    std::string type_name;
};

struct ClassMetadataUnknown {
    std::string name;
};

using ClassMetadata = std::variant<
    ClassMetadataNetworkChangeCallback,
    ClassMetadataNetworkVarNames,
    ClassMetadataUnknown>;

struct Class {
    std::string name;
    std::string module_name;
    std::optional<std::string> parent_name;
    std::vector<ClassMetadata> metadata;
    std::vector<ClassField> fields;
};

using ButtonMap = std::map<std::string, uintptr_t>;
using InterfaceMap = std::map<std::string, std::map<std::string, uintptr_t>>;
using OffsetMap = std::map<std::string, std::map<std::string, Rva>>;
using SchemaMap = std::map<std::string, std::pair<std::vector<Class>, std::vector<Enum>>>;

struct AnalysisResult {
    ButtonMap buttons;
    InterfaceMap interfaces;
    OffsetMap offsets;
    SchemaMap schemas;
};

} // namespace cs2dumper
