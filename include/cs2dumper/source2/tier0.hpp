#pragma once

#include <cstdint>

namespace cs2dumper::source2 {

struct TsListNode;

struct TsListHead {
    uintptr_t next;
};

struct TsListBase {
    TsListHead head;
};

} // namespace cs2dumper::source2
