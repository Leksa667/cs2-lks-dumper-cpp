#pragma once

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace cs2dumper::pe {

struct SectionInfo {
    uint32_t virtual_address{};
    uint32_t virtual_size{};
    uint32_t pointer_to_raw_data{};
    uint32_t size_of_raw_data{};
    uint32_t characteristics{};
    std::string name;
};

class PeView {
public:
    explicit PeView(std::vector<uint8_t> data) : data_(std::move(data)) {
        parse();
    }

    [[nodiscard]] const std::vector<uint8_t>& data() const { return data_; }

    [[nodiscard]] uint64_t image_base() const { return image_base_; }

    [[nodiscard]] std::optional<uint32_t> export_symbol_rva(const std::string& name) const {
        if (export_rva_ == 0 || export_size_ == 0) {
            return std::nullopt;
        }

        const auto* const export_dir = rva_ptr(export_rva_);
        if (export_dir == nullptr) {
            return std::nullopt;
        }

        const auto* const dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(export_dir);
        if (dir->NumberOfNames == 0 || dir->NumberOfFunctions == 0) {
            return std::nullopt;
        }

        const auto* const name_rvas = rva_ptr_array<uint32_t>(dir->AddressOfNames, dir->NumberOfNames);
        const auto* const ordinals = rva_ptr_array<uint16_t>(dir->AddressOfNameOrdinals, dir->NumberOfNames);
        const auto* const functions = rva_ptr_array<uint32_t>(dir->AddressOfFunctions, dir->NumberOfFunctions);

        if (name_rvas == nullptr || ordinals == nullptr || functions == nullptr) {
            return std::nullopt;
        }

        for (uint32_t i = 0; i < dir->NumberOfNames; ++i) {
            const char* const export_name = reinterpret_cast<const char*>(rva_ptr(name_rvas[i]));
            if (export_name == nullptr) {
                continue;
            }

            if (name != export_name) {
                continue;
            }

            const uint16_t ordinal = ordinals[i];
            if (ordinal >= dir->NumberOfFunctions) {
                return std::nullopt;
            }

            const uint32_t function_rva = functions[ordinal];
            if (function_rva >= export_rva_ && function_rva < export_rva_ + export_size_) {
                return std::nullopt;
            }
            return function_rva;
        }

        return std::nullopt;
    }

    [[nodiscard]] std::pair<uint32_t, uint32_t> code_range() const {
        if (data_.size() < sizeof(IMAGE_DOS_HEADER)) {
            return {0, 0};
        }
        const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data_.data());
        const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + dos->e_lfanew);
        const uint32_t base = nt->OptionalHeader.BaseOfCode;
        const uint32_t size = nt->OptionalHeader.SizeOfCode;
        return {base, size};
    }

    [[nodiscard]] std::vector<std::pair<const uint8_t*, size_t>> code_sections() const {
        std::vector<std::pair<const uint8_t*, size_t>> sections;
        const auto [base, size] = code_range();
        const auto* const ptr = rva_ptr(base);
        if (ptr == nullptr || size == 0) {
            return sections;
        }
        const size_t clamped = std::min(static_cast<size_t>(size), data_.size() - base);
        sections.emplace_back(ptr, clamped);
        return sections;
    }

    [[nodiscard]] const uint8_t* rva_ptr(uint32_t rva) const {
        if (rva == 0 || rva >= data_.size()) {
            return nullptr;
        }
        return data_.data() + rva;
    }

    template <typename T>
    [[nodiscard]] const T* rva_ptr_array(uint32_t rva, size_t count) const {
        if (count == 0 || rva == 0) {
            return nullptr;
        }

        const auto* const ptr = rva_ptr(rva);
        if (ptr == nullptr) {
            return nullptr;
        }

        const size_t offset = static_cast<size_t>(ptr - data_.data());
        const size_t bytes_needed = count * sizeof(T);
        if (offset + bytes_needed > data_.size() || offset + bytes_needed < offset) {
            return nullptr;
        }

        return reinterpret_cast<const T*>(ptr);
    }

private:
    std::vector<uint8_t> data_;
    uint64_t image_base_{};
    uint32_t export_rva_{};
    uint32_t export_size_{};
    std::vector<SectionInfo> sections_;

    void parse() {
        if (data_.size() < sizeof(IMAGE_DOS_HEADER)) {
            throw std::runtime_error("invalid PE: too small");
        }

        const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data_.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            throw std::runtime_error("invalid PE: bad DOS signature");
        }

        if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > data_.size()) {
            throw std::runtime_error("invalid PE: bad NT header offset");
        }

        const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error("invalid PE: bad NT signature");
        }

        image_base_ = nt->OptionalHeader.ImageBase;

        const auto* const first_section = IMAGE_FIRST_SECTION(nt);
        sections_.reserve(nt->FileHeader.NumberOfSections);
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& sec = first_section[i];
            SectionInfo info{};
            info.virtual_address = sec.VirtualAddress;
            info.virtual_size = sec.Misc.VirtualSize;
            info.pointer_to_raw_data = sec.PointerToRawData;
            info.size_of_raw_data = sec.SizeOfRawData;
            info.characteristics = sec.Characteristics;
            info.name = std::string(reinterpret_cast<const char*>(sec.Name),
                                    strnlen(reinterpret_cast<const char*>(sec.Name), 8));
            sections_.push_back(info);
        }

        const auto& export_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        export_rva_ = export_entry.VirtualAddress;
        export_size_ = export_entry.Size;
    }
};

} // namespace cs2dumper::pe
