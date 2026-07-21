#pragma once

#include "cs2dumper/types.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace cs2dumper::memory {

class ProcessMemory {
public:
    ProcessMemory() = default;

    ~ProcessMemory() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    ProcessMemory(const ProcessMemory&) = delete;
    ProcessMemory& operator=(const ProcessMemory&) = delete;

    void attach(const std::string& process_name) {
        const DWORD pid = find_process_id(process_name);
        if (pid == 0) {
            throw std::runtime_error("process not found: " + process_name);
        }

        handle_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (handle_ == nullptr) {
            throw std::runtime_error("failed to open process");
        }
    }

    [[nodiscard]] bool is_attached() const {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    [[nodiscard]] std::optional<ModuleInfo> module_by_name(const std::string& name) const {
        for (const auto& module : module_list()) {
            if (_stricmp(module.name.c_str(), name.c_str()) == 0) {
                return module;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<ModuleInfo> module_list() const {
        std::vector<ModuleInfo> modules;
        if (!is_attached()) {
            return modules;
        }

        HMODULE module_handles[1024];
        DWORD needed = 0;
        if (!EnumProcessModules(handle_, module_handles, sizeof(module_handles), &needed)) {
            return modules;
        }

        const size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            char name_buffer[MAX_PATH]{};
            if (GetModuleBaseNameA(handle_, module_handles[i], name_buffer, MAX_PATH) == 0) {
                continue;
            }

            MODULEINFO info{};
            if (!GetModuleInformation(handle_, module_handles[i], &info, sizeof(info))) {
                continue;
            }

            modules.push_back({
                reinterpret_cast<uintptr_t>(info.lpBaseOfDll),
                info.SizeOfImage,
                name_buffer,
            });
        }

        return modules;
    }

    [[nodiscard]] std::vector<uint8_t> read_raw(uintptr_t address, size_t size) const {
        std::vector<uint8_t> buffer(size);
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytes_read)) {
            throw std::runtime_error("ReadProcessMemory failed");
        }
        buffer.resize(bytes_read);
        return buffer;
    }

    template <typename T>
    [[nodiscard]] T read(uintptr_t address) const {
        T value{};
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), &bytes_read) ||
            bytes_read != sizeof(T)) {
            throw std::runtime_error("read failed");
        }
        return value;
    }

    [[nodiscard]] uintptr_t read_addr64(uintptr_t address) const {
        return read<uintptr_t>(address);
    }

    [[nodiscard]] std::string read_utf8_lossy(uintptr_t address, size_t max_len) const {
        if (address == 0) {
            return {};
        }

        std::string result;
        result.reserve(max_len);

        for (size_t i = 0; i < max_len; ++i) {
            const char ch = read<char>(address + i);
            if (ch == '\0') {
                break;
            }
            result.push_back(ch);
        }

        return result;
    }

private:
    HANDLE handle_{nullptr};

    static DWORD find_process_id(const std::string& process_name) {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        DWORD pid = 0;
        if (Process32First(snapshot, &entry)) {
            do {
                if (_stricmp(entry.szExeFile, process_name.c_str()) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return pid;
    }
};

} // namespace cs2dumper::memory
