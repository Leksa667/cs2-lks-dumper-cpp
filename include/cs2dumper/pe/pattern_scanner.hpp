#pragma once

#include "cs2dumper/pe/pe_view.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cs2dumper::pe {

enum class AtomKind : uint8_t {
    Byte,
    Save,
    Push,
    Pop,
    Fuzzy,
    Skip,
    Back,
    Rangext,
    Many,
    Jump1,
    Jump4,
    Ptr,
    Pir,
    Aligned,
    ReadU8,
    ReadU16,
    ReadU32,
    ReadI8,
    ReadI16,
    ReadI32,
    Zero,
    Case,
    Break,
    Nop,
};

struct Atom {
    AtomKind kind{};
    uint8_t arg{};
};

using Pattern = std::vector<Atom>;

inline constexpr uint8_t PTR_SKIP = 0;

class PatternParseError : public std::runtime_error {
public:
    explicit PatternParseError(const std::string& message)
        : std::runtime_error(message) {}
};

inline size_t pattern_save_len(const Pattern& pattern) {
    size_t max_slot = 0;
    for (const auto& atom : pattern) {
        switch (atom.kind) {
        case AtomKind::Save:
        case AtomKind::Pir:
        case AtomKind::Zero:
        case AtomKind::ReadU8:
        case AtomKind::ReadU16:
        case AtomKind::ReadU32:
        case AtomKind::ReadI8:
        case AtomKind::ReadI16:
        case AtomKind::ReadI32:
            max_slot = std::max(max_slot, static_cast<size_t>(atom.arg) + 1);
            break;
        default:
            break;
        }
    }
    return max_slot;
}

inline Pattern parse_pattern(std::string_view input) {
    struct SubPattern {
        size_t case_index{};
        std::vector<size_t> breaks;
        uint8_t save{};
        uint8_t save_next{};
        uint8_t depth{};
    };

    Pattern result;
    result.push_back({AtomKind::Save, 0});

    std::string pat(input);
    size_t pos = 0;
    uint8_t save = 1;
    int depth = 0;
    std::vector<SubPattern> subs;

    auto consume = [&]() -> std::optional<char> {
        if (pos >= pat.size()) return std::nullopt;
        return pat[pos++];
    };

    auto parse_hex_byte = [&]() -> uint8_t {
        const auto hi = consume();
        const auto lo = consume();
        if (!hi || !lo || !std::isxdigit(static_cast<unsigned char>(*hi)) ||
            !std::isxdigit(static_cast<unsigned char>(*lo))) {
            throw PatternParseError("unpaired hex digit");
        }
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        return static_cast<uint8_t>((nibble(*hi) << 4) | nibble(*lo));
    };

    while (pos < pat.size()) {
        char chr = *consume();

        switch (chr) {
        case '%':
            result.push_back({AtomKind::Jump1, 0});
            break;
        case '$':
            result.push_back({AtomKind::Jump4, 0});
            break;
        case '*':
            result.push_back({AtomKind::Ptr, 0});
            break;
        case '{': {
            ++depth;
            if (result.empty()) throw PatternParseError("stack invalid");
            Atom& last = result.back();
            AtomKind kind = last.kind;
            uint8_t push_arg = 0;
            if (kind == AtomKind::Jump1) push_arg = 1;
            else if (kind == AtomKind::Jump4) push_arg = 4;
            else if (kind == AtomKind::Ptr) push_arg = PTR_SKIP;
            else throw PatternParseError("stack invalid");
            const Atom replaced = last;
            last = {AtomKind::Push, push_arg};
            result.push_back(replaced);
            break;
        }
        case '}':
            if (depth <= 0) throw PatternParseError("stack error");
            --depth;
            result.push_back({AtomKind::Pop, 0});
            break;
        case '(':
            subs.push_back({});
            subs.back().save = save;
            subs.back().depth = static_cast<uint8_t>(depth);
            subs.back().case_index = result.size();
            result.push_back({AtomKind::Case, 0});
            break;
        case '|': {
            if (subs.empty()) throw PatternParseError("sub pattern error");
            auto& sub = subs.back();
            sub.save_next = std::max(sub.save_next, save);
            save = sub.save;
            depth = sub.depth;
            sub.breaks.push_back(result.size());
            result.push_back({AtomKind::Break, 0});
            const size_t case_offset = result.size() - sub.case_index - 1;
            if (case_offset >= 256) throw PatternParseError("sub pattern too large");
            result[sub.case_index] = {AtomKind::Case, static_cast<uint8_t>(case_offset)};
            sub.case_index = result.size();
            result.push_back({AtomKind::Case, 0});
            break;
        }
        case ')': {
            if (subs.empty()) throw PatternParseError("sub pattern error");
            const auto sub = subs.back();
            subs.pop_back();
            save = std::max(sub.save_next, save);
            depth = sub.depth;
            result[sub.case_index] = {AtomKind::Nop, 0};
            for (const size_t brk : sub.breaks) {
                const size_t brk_offset = result.size() - brk - 1;
                if (brk_offset >= 256) throw PatternParseError("sub pattern too large");
                result[brk] = {AtomKind::Break, static_cast<uint8_t>(brk_offset)};
            }
            break;
        }
        case '[': {
            uint32_t lower_bound = 0;
            bool at_least_one = false;
            while (true) {
                const auto ch = consume();
                if (!ch) throw PatternParseError("many invalid");
                if (*ch == '-' || *ch == ']') {
                    chr = *ch;
                    break;
                }
                if (*ch >= '0' && *ch <= '9') {
                    at_least_one = true;
                    lower_bound = lower_bound * 10 + static_cast<uint32_t>(*ch - '0');
                } else {
                    throw PatternParseError("many invalid");
                }
            }
            if (!at_least_one) throw PatternParseError("many invalid");
            if (lower_bound > 0) {
                if (lower_bound >= 256) {
                    result.push_back({AtomKind::Rangext, static_cast<uint8_t>(lower_bound >> 8)});
                }
                result.push_back({AtomKind::Skip, static_cast<uint8_t>(lower_bound & 0xFF)});
            }
            if (chr == ']') break;
            uint32_t upper_bound = 0;
            while (true) {
                const auto ch = consume();
                if (!ch) throw PatternParseError("many invalid");
                if (*ch == ']') break;
                if (*ch >= '0' && *ch <= '9') {
                    upper_bound = upper_bound * 10 + static_cast<uint32_t>(*ch - '0');
                } else {
                    throw PatternParseError("many invalid");
                }
            }
            if (lower_bound >= upper_bound) throw PatternParseError("many range");
            const uint32_t many_skip = upper_bound - lower_bound;
            if (many_skip >= 256) {
                result.push_back({AtomKind::Rangext, static_cast<uint8_t>(many_skip >> 8)});
            }
            result.push_back({AtomKind::Many, static_cast<uint8_t>(many_skip & 0xFF)});
            break;
        }
        case '\'':
            if (save >= 255) throw PatternParseError("save overflow");
            result.push_back({AtomKind::Save, save++});
            break;
        case '?':
            if (!result.empty() && result.back().kind == AtomKind::Skip && result.back().arg != PTR_SKIP &&
                result.back().arg < 255) {
                ++result.back().arg;
            } else {
                result.push_back({AtomKind::Skip, 1});
            }
            break;
        case '@': {
            const auto op = consume();
            if (!op) throw PatternParseError("aligned operand error");
            uint8_t align = 0;
            if (*op >= '0' && *op <= '9') align = static_cast<uint8_t>(*op - '0');
            else if (*op >= 'A' && *op <= 'Z') align = static_cast<uint8_t>(10 + (*op - 'A'));
            else if (*op >= 'a' && *op <= 'z') align = static_cast<uint8_t>(10 + (*op - 'a'));
            else throw PatternParseError("aligned operand error");
            result.push_back({AtomKind::Aligned, align});
            break;
        }
        case 'i': {
            const auto size_ch = consume();
            if (!size_ch) throw PatternParseError("read operand error");
            if (save >= 255) throw PatternParseError("save overflow");
            if (*size_ch == '1') result.push_back({AtomKind::ReadI8, save++});
            else if (*size_ch == '2') result.push_back({AtomKind::ReadI16, save++});
            else if (*size_ch == '4') result.push_back({AtomKind::ReadI32, save++});
            else throw PatternParseError("read operand error");
            break;
        }
        case 'u': {
            const auto size_ch = consume();
            if (!size_ch) throw PatternParseError("read operand error");
            if (save >= 255) throw PatternParseError("save overflow");
            if (*size_ch == '1') result.push_back({AtomKind::ReadU8, save++});
            else if (*size_ch == '2') result.push_back({AtomKind::ReadU16, save++});
            else if (*size_ch == '4') result.push_back({AtomKind::ReadU32, save++});
            else throw PatternParseError("read operand error");
            break;
        }
        case 'z':
            if (save >= 255) throw PatternParseError("save overflow");
            result.push_back({AtomKind::Zero, save++});
            break;
        case ' ':
        case '\n':
        case '\r':
        case '\t':
            break;
        default:
            if (std::isxdigit(static_cast<unsigned char>(chr))) {
                --pos;
                result.push_back({AtomKind::Byte, parse_hex_byte()});
            } else {
                throw PatternParseError(std::string("unknown character: ") + chr);
            }
            break;
        }
    }

    if (depth != 0) throw PatternParseError("stack error");
    if (!subs.empty()) throw PatternParseError("sub pattern error");

    while (!result.empty()) {
        const auto kind = result.back().kind;
        if (kind == AtomKind::Skip || kind == AtomKind::Rangext || kind == AtomKind::Pop || kind == AtomKind::Many) {
            result.pop_back();
        } else {
            break;
        }
    }

    return result;
}

class PatternExecutor {
public:
    explicit PatternExecutor(const std::vector<uint8_t>& data)
        : data_(data) {}

    enum class ExecStatus { Failed, Matched, Popped };

    ExecStatus exec(uint32_t cursor, const Pattern& pattern, std::vector<uint32_t>& save, size_t& pc) const {
        uint8_t mask = 0xFF;
        uint32_t ext_range = 0;

        while (pc < pattern.size()) {
            const Atom atom = pattern[pc++];

            switch (atom.kind) {
            case AtomKind::Byte: {
                const auto byte = read<uint8_t>(cursor);
                if (!byte || (*byte & mask) != (atom.arg & mask)) {
                    return ExecStatus::Failed;
                }
                mask = 0xFF;
                cursor += 1;
                break;
            }
            case AtomKind::Save:
                if (atom.arg < save.size()) {
                    save[atom.arg] = cursor;
                }
                break;
            case AtomKind::Push: {
                const uint32_t skip = ext_range + atom.arg;
                const uint32_t actual_skip = (skip == 0) ? static_cast<uint32_t>(sizeof(uintptr_t)) : skip;
                const uint32_t return_cursor = cursor + actual_skip;
                const ExecStatus push_status = exec(cursor, pattern, save, pc);
                if (push_status == ExecStatus::Failed) {
                    return ExecStatus::Failed;
                }
                mask = 0xFF;
                ext_range = 0;
                cursor = return_cursor;
                break;
            }
            case AtomKind::Pop:
                return ExecStatus::Popped;
            case AtomKind::Fuzzy:
                mask = atom.arg;
                break;
            case AtomKind::Skip: {
                const uint32_t skip = ext_range + atom.arg;
                const uint32_t actual_skip = (skip == 0) ? static_cast<uint32_t>(sizeof(uintptr_t)) : skip;
                cursor += actual_skip;
                ext_range = 0;
                break;
            }
            case AtomKind::Back: {
                const uint32_t rewind = ext_range + atom.arg;
                const uint32_t actual_rewind = (rewind == 0) ? static_cast<uint32_t>(sizeof(uintptr_t)) : rewind;
                cursor -= actual_rewind;
                ext_range = 0;
                break;
            }
            case AtomKind::Rangext:
                ext_range = static_cast<uint32_t>(atom.arg) * 256U;
                break;
            case AtomKind::Many:
                return exec_many(cursor, pattern, pc, save, ext_range + atom.arg) ? ExecStatus::Matched
                                                                                    : ExecStatus::Failed;
            case AtomKind::Jump1: {
                const auto rel = read<int8_t>(cursor);
                if (!rel) return ExecStatus::Failed;
                cursor = cursor + static_cast<uint32_t>(static_cast<int32_t>(*rel)) + 1U;
                break;
            }
            case AtomKind::Jump4: {
                const auto rel = read<int32_t>(cursor);
                if (!rel) return ExecStatus::Failed;
                cursor = cursor + static_cast<uint32_t>(*rel) + 4U;
                break;
            }
            case AtomKind::Ptr: {
                const auto ptr = read<uint64_t>(cursor);
                if (!ptr) return ExecStatus::Failed;
                cursor = static_cast<uint32_t>(*ptr);
                break;
            }
            case AtomKind::Pir: {
                const auto rel = read<int32_t>(cursor);
                if (!rel) return ExecStatus::Failed;
                const uint32_t base = (atom.arg < save.size()) ? save[atom.arg] : cursor;
                cursor = base + static_cast<uint32_t>(*rel);
                break;
            }
            case AtomKind::Aligned:
                if ((cursor & ((1U << atom.arg) - 1U)) != 0) return ExecStatus::Failed;
                break;
            case AtomKind::ReadU8: {
                const auto value = read<uint8_t>(cursor);
                if (!value) return ExecStatus::Failed;
                if (atom.arg < save.size()) save[atom.arg] = *value;
                cursor += 1;
                break;
            }
            case AtomKind::ReadU16: {
                const auto value = read<uint16_t>(cursor);
                if (!value) return ExecStatus::Failed;
                if (atom.arg < save.size()) save[atom.arg] = *value;
                cursor += 2;
                break;
            }
            case AtomKind::ReadU32:
            case AtomKind::ReadI32: {
                const auto value = read<uint32_t>(cursor);
                if (!value) return ExecStatus::Failed;
                if (atom.arg < save.size()) save[atom.arg] = *value;
                cursor += 4;
                break;
            }
            case AtomKind::ReadI8: {
                const auto value = read<int8_t>(cursor);
                if (!value) return ExecStatus::Failed;
                if (atom.arg < save.size()) save[atom.arg] = static_cast<uint32_t>(*value);
                cursor += 1;
                break;
            }
            case AtomKind::ReadI16: {
                const auto value = read<int16_t>(cursor);
                if (!value) return ExecStatus::Failed;
                if (atom.arg < save.size()) save[atom.arg] = static_cast<uint32_t>(*value);
                cursor += 2;
                break;
            }
            case AtomKind::Zero:
                if (atom.arg < save.size()) save[atom.arg] = 0;
                break;
            case AtomKind::Case: {
                const size_t saved_pc = pc;
                const uint32_t saved_cursor = cursor;
                if (exec(cursor, pattern, save, pc) == ExecStatus::Failed) {
                    pc = saved_pc + atom.arg;
                    cursor = saved_cursor;
                }
                break;
            }
            case AtomKind::Break:
                pc += atom.arg;
                return ExecStatus::Matched;
            case AtomKind::Nop:
                break;
            }
        }

        return ExecStatus::Matched;
    }

    bool finds_code(const PeView& view, const Pattern& pattern, std::vector<uint32_t>& save) const {
        const size_t needed = pattern_save_len(pattern);
        save.assign(std::max(needed, size_t{2}), 0);

        std::vector<uint32_t> matched_save;
        bool found = false;

        for (const auto& [code, size] : view.code_sections()) {
            const uint32_t base_rva = static_cast<uint32_t>(code - data_.data());
            for (size_t offset = 0; offset < size; ++offset) {
                size_t pc = 0;
                if (exec(base_rva + static_cast<uint32_t>(offset), pattern, save, pc) != ExecStatus::Matched) {
                    continue;
                }

                if (found) {
                    return false;
                }

                found = true;
                matched_save = save;
            }
        }

        if (found) {
            save = std::move(matched_save);
        }

        return found;
    }

private:
    const std::vector<uint8_t>& data_;

    template <typename T>
    std::optional<T> read(uint32_t rva) const {
        if (rva + sizeof(T) > data_.size()) {
            return std::nullopt;
        }
        T value{};
        std::memcpy(&value, data_.data() + rva, sizeof(T));
        return value;
    }

    bool exec_many(uint32_t cursor, const Pattern& pattern, size_t pc, std::vector<uint32_t>& save, uint32_t limit) const {
        if (cursor >= data_.size()) return false;
        const size_t available = data_.size() - cursor;
        const size_t scan_len = (limit == 0) ? available : std::min(static_cast<size_t>(limit), available);

        for (size_t i = 0; i < scan_len; ++i) {
            size_t local_pc = pc;
            if (exec(cursor + static_cast<uint32_t>(i), pattern, save, local_pc) == ExecStatus::Matched) {
                return true;
            }
        }
        return false;
    }
};

inline bool finds_code(const PeView& view, std::string_view pattern_str, std::vector<uint32_t>& save) {
    const Pattern pattern = parse_pattern(pattern_str);
    PatternExecutor executor(view.data());
    return executor.finds_code(view, pattern, save);
}

} // namespace cs2dumper::pe
