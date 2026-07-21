#pragma once

#include "cs2dumper/source2/tier0.hpp"

#include <cstdint>

namespace cs2dumper::source2 {

template <typename T>
struct UtlVector {
    int32_t count;
    uint8_t pad0[4];
    uintptr_t data;
};

template <typename T>
struct UtlTsHashAllocatedBlob {
    uintptr_t next;
    uint8_t pad0[0x8];
    uintptr_t data;
    uint8_t pad1[0x18];
};

template <typename T, typename K = uint64_t>
struct UtlTsHashFixedData {
    K ui_key;
    uintptr_t next;
    uintptr_t data;
};

template <typename T, typename K = uint64_t>
struct UtlTsHashBucket {
    uintptr_t add_lock;
    uintptr_t first;
    uintptr_t first_uncommitted;
};

struct UtlMemoryPoolBlob {
    uintptr_t next;
    int32_t size;
    uint8_t data[1];
    uint8_t pad0[3];
};

struct UtlMemoryPool {
    int32_t block_size;
    int32_t blocks_per_blob;
    uint32_t grow_mode;
    int32_t blocks_allocated;
    int32_t peak_allocated;
    uint16_t alignment;
    uint16_t blob_count;
    uint8_t pad0[2];
    TsListBase free_blocks;
    uint8_t pad1[0x20];
    uintptr_t blob_head;
    int32_t total_size;
    uint8_t pad2[0xC];
};

template <typename T, size_t BucketCount = 256, typename K = uint64_t>
struct UtlTsHash {
    UtlMemoryPool entry_mem;
    UtlTsHashBucket<T, K> buckets[BucketCount];
    bool needs_commit;
    uint8_t pad0[3];
    int32_t contention_check;
    uint8_t pad1[8];
};

} // namespace cs2dumper::source2
