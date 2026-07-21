#pragma once

#include <algorithm>
#include <cctype>
#include <string>

namespace cs2dumper::utils {

inline std::string slugify(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (const char c : input) {
        result.push_back(std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    }
    return result;
}

inline std::string to_snake_case(const std::string& input) {
    if (input.empty()) {
        return input;
    }

    std::string result;
    result.reserve(input.size() * 2);

    for (size_t i = 0; i < input.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(input[i]);
        if (std::isupper(c) != 0) {
            if (i > 0) {
                result.push_back('_');
            }
            result.push_back(static_cast<char>(std::tolower(c)));
        } else if (c == '-' || c == ' ' || c == '.') {
            if (!result.empty() && result.back() != '_') {
                result.push_back('_');
            }
        } else {
            result.push_back(static_cast<char>(c));
        }
    }

    return result;
}

inline std::string to_pascal_case(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    bool capitalize_next = true;
    for (const char c : input) {
        if (c == '_' || c == '-' || c == ' ' || c == '.') {
            capitalize_next = true;
            continue;
        }

        if (capitalize_next) {
            result.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
            capitalize_next = false;
        } else {
            result.push_back(c);
        }
    }

    return result;
}

inline std::string module_namespace_name(const std::string& module_name) {
    return to_snake_case(slugify(module_name));
}

inline bool is_zig_identifier(const std::string& input) {
    if (input.empty()) {
        return false;
    }

    const char first = input.front();
    if (first != '_' && !std::isalpha(static_cast<unsigned char>(first))) {
        return false;
    }

    return std::all_of(input.begin() + 1, input.end(), [](char c) {
        return c == '_' || std::isalnum(static_cast<unsigned char>(c));
    });
}

inline bool is_zig_keyword(const std::string& input) {
    static const char* keywords[] = {
        "addrspace", "align", "allowzero", "and", "anyframe", "anytype", "asm", "async", "await",
        "break", "callconv", "catch", "comptime", "const", "continue", "defer", "else", "enum",
        "errdefer", "error", "export", "extern", "false", "fn", "for", "if", "inline", "linksection",
        "noalias", "noinline", "nosuspend", "null", "opaque", "or", "orelse", "packed", "pub",
        "resume", "return", "struct", "suspend", "switch", "test", "threadlocal", "true", "try",
        "union", "unreachable", "usingnamespace", "var", "volatile", "while",
    };

    for (const char* keyword : keywords) {
        if (input == keyword) {
            return true;
        }
    }
    return false;
}

inline std::string zig_ident(const std::string& input) {
    if (is_zig_identifier(input) && !is_zig_keyword(input)) {
        return input;
    }

    std::string escaped;
    escaped.reserve(input.size() + 4);
    for (const char c : input) {
        if (c == '\\') {
            escaped += "\\\\";
        } else if (c == '"') {
            escaped += "\\\"";
        } else {
            escaped.push_back(c);
        }
    }
    return "@\"" + escaped + "\"";
}

} // namespace cs2dumper::utils
