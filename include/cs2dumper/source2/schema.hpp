#pragma once

#include "cs2dumper/source2/tier1.hpp"

#include <cstddef>
#include <cstdint>

namespace cs2dumper::source2 {

struct SchemaVarName {
    uintptr_t name;
    uintptr_t type_name;
};

union SchemaNetworkValueUnion {
    uintptr_t name_ptr;
    int32_t int_value;
    float float_value;
    uintptr_t ptr_value;
    SchemaVarName var_value;
    char name_value[32];
};

struct SchemaNetworkValue {
    SchemaNetworkValueUnion value;
};

struct SchemaMetadataEntryData {
    uintptr_t name;
    uintptr_t network_value;
};

struct SchemaType;

struct SchemaClassFieldData {
    uintptr_t name;
    uintptr_t type;
    int32_t offset;
    int32_t metadata_count;
    uintptr_t metadata;
};

struct SchemaBaseClass {
    uint8_t pad0[0x10];
    uintptr_t name;
};

struct SchemaBaseClassInfoData {
    uint8_t pad0[0x18];
    uintptr_t class_ptr;
};

struct SchemaEnumeratorInfoDataUnion {
    uint64_t ulong;
};

struct SchemaEnumeratorInfoData {
    uintptr_t name;
    SchemaEnumeratorInfoDataUnion value;
    int32_t metadata_count;
    uint8_t pad0[4];
    uintptr_t metadata;
};

struct SchemaClassInfoData {
    uintptr_t base;
    uintptr_t name;
    uintptr_t binary_name;
    uintptr_t module_name;
    int32_t size;
    int16_t field_count;
    int16_t static_metadata_count;
    uint8_t pad0[2];
    uint8_t alignment;
    uint8_t has_base_class;
    int16_t total_class_size;
    int16_t derived_class_size;
    uintptr_t fields;
    uint8_t pad1[8];
    uintptr_t base_classes;
    uintptr_t static_metadata;
    uintptr_t type_scope;
    uintptr_t type;
    uint8_t pad2[0x10];
};

using SchemaClassBinding = SchemaClassInfoData;

struct SchemaEnumInfoData {
    uintptr_t base;
    uintptr_t name;
    uintptr_t module_name;
    uint8_t size;
    uint8_t alignment;
    uint8_t flags;
    uint8_t pad0;
    uint16_t enumerator_count;
    uint16_t static_metadata_count;
    uintptr_t enumerators;
    uintptr_t static_metadata;
    uintptr_t type_scope;
    int64_t min_enumerator_value;
    int64_t max_enumerator_value;
};

using SchemaEnumBinding = SchemaEnumInfoData;

struct SchemaSystemTypeScope;

struct SchemaSystem {
    uint8_t pad0[0x190];
    UtlVector<uintptr_t> type_scopes;
    uint8_t pad1[0xE0];
    int32_t registration_count;
};

struct SchemaSystemTypeScope {
    uint8_t pad0[0x8];
    char name[256];
    uintptr_t global_scope;
    uint8_t pad1[0x450];
    UtlTsHash<SchemaClassBinding> class_bindings;
    UtlTsHash<SchemaEnumBinding> enum_bindings;
};

static_assert(offsetof(SchemaSystemTypeScope, class_bindings) == 0x560);
static_assert(offsetof(SchemaSystemTypeScope, enum_bindings) == 0x1DD0);
static_assert(sizeof(UtlTsHash<SchemaClassBinding>) == 0x1870);

struct SchemaType {
    uint8_t pad0[0x8];
    uintptr_t name;
    uintptr_t type_scope;
    uint8_t type_category;
    uint8_t atomic_category;
    uint8_t pad1[6];
    uint8_t value[0x28];
};

} // namespace cs2dumper::source2
