#pragma once

#include "cs2dumper/memory/process.hpp"
#include "cs2dumper/source2/tier1.hpp"

#include <cstdint>
#include <unordered_set>
#include <vector>

namespace cs2dumper::source2 {

using memory::ProcessMemory;

template <typename T, size_t BucketCount = 256, typename K = uint64_t>
class UtlTsHashWalker {
public:
    static std::vector<uintptr_t> elements(const ProcessMemory& process, const UtlTsHash<T, BucketCount, K>& hash) {
        auto allocated = allocated_elements(process, hash);
        auto unallocated = unallocated_elements(process, hash);

        std::vector<uintptr_t> result;
        result.reserve(allocated.size() + unallocated.size());
        result.insert(result.end(), allocated.begin(), allocated.end());
        result.insert(result.end(), unallocated.begin(), unallocated.end());

        std::unordered_set<uintptr_t> seen;
        seen.reserve(result.size());

        std::vector<uintptr_t> deduped;
        deduped.reserve(result.size());
        for (const uintptr_t ptr : result) {
            if (seen.insert(ptr).second) {
                deduped.push_back(ptr);
            }
        }

        return deduped;
    }

private:
    static std::vector<uintptr_t> allocated_elements(
        const ProcessMemory& process,
        const UtlTsHash<T, BucketCount, K>& hash) {
        const size_t used_count = static_cast<size_t>(hash.entry_mem.blocks_allocated);
        std::vector<uintptr_t> elements;
        elements.reserve(used_count);

        for (size_t i = 0; i < BucketCount; ++i) {
            uintptr_t node_ptr = hash.buckets[i].first_uncommitted;

            while (node_ptr != 0) {
                UtlTsHashFixedData<T, K> node{};
                try {
                    node = process.read<UtlTsHashFixedData<T, K>>(node_ptr);
                } catch (...) {
                    break;
                }

                if (node.data != 0) {
                    elements.push_back(node.data);
                }

                if (elements.size() >= used_count) {
                    return elements;
                }

                node_ptr = node.next;
            }
        }

        return elements;
    }

    static std::vector<uintptr_t> unallocated_elements(
        const ProcessMemory& process,
        const UtlTsHash<T, BucketCount, K>& hash) {
        const size_t free_count = static_cast<size_t>(hash.entry_mem.peak_allocated);
        std::vector<uintptr_t> elements;
        elements.reserve(free_count);

        uintptr_t blob_ptr = hash.entry_mem.free_blocks.head.next;

        while (blob_ptr != 0) {
            UtlTsHashAllocatedBlob<T> blob{};
            try {
                blob = process.read<UtlTsHashAllocatedBlob<T>>(blob_ptr);
            } catch (...) {
                break;
            }

            if (blob.data != 0) {
                elements.push_back(blob.data);
            }

            if (elements.size() >= free_count) {
                return elements;
            }

            blob_ptr = blob.next;
        }

        return elements;
    }
};

} // namespace cs2dumper::source2
