// =============================================================================
// cs2-lks-dumper — Counter-Strike 2 memory dumper
//
// Author  : Leksa667
// Project : https://github.com/Leksa667/cs2-lks-dumper-cpp
// =============================================================================

#include "cs2dumper/analysis/analyze.hpp"
#include "cs2dumper/output/dumper.hpp"
#include "cs2dumper/project.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Options {
    std::vector<std::string> file_types{"cs", "hpp", "json", "rs", "zig"};
    size_t indent_size{4};
    std::string output{"output"};
    std::string process_name{"cs2.exe"};
    int verbose{0};
    bool no_log_file{false};
};

void print_usage() {
    std::cout
        << cs2dumper::kProjectName << ' ' << cs2dumper::kVersion << "\n"
        << "by " << cs2dumper::kAuthor << "\n\n"
        << "Usage: " << cs2dumper::kProjectName << " [options]\n\n"
        << "Options:\n"
        << "  -f, --file-types <types>   Output formats (comma-separated)\n"
        << "  -o, --output <dir>         Output directory (default: output)\n"
        << "  -p, --process-name <name>  Process name (default: cs2.exe)\n"
        << "  -i, --indent-size <n>      Indentation size (default: 4)\n"
        << "  -v, --verbose              Increase logging verbosity\n"
        << "      --no-log-file          Do not create cs2-lks-dumper.log\n"
        << "  -h, --help                 Show this help\n";
}

std::vector<std::string> split(const std::string& input, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(input);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            parts.push_back(item);
        }
    }
    return parts;
}

bool parse_args(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage();
            return false;
        }
        if ((arg == "-f" || arg == "--file-types") && i + 1 < argc) {
            options.file_types = split(argv[++i], ',');
            continue;
        }
        if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            options.output = argv[++i];
            continue;
        }
        if ((arg == "-p" || arg == "--process-name") && i + 1 < argc) {
            options.process_name = argv[++i];
            continue;
        }
        if ((arg == "-i" || arg == "--indent-size") && i + 1 < argc) {
            options.indent_size = static_cast<size_t>(std::stoul(argv[++i]));
            continue;
        }
        if (arg == "-v" || arg == "--verbose") {
            ++options.verbose;
            continue;
        }
        if (arg == "--no-log-file") {
            options.no_log_file = true;
            continue;
        }

        std::cerr << "unknown argument: " << arg << '\n';
        print_usage();
        return false;
    }

    return true;
}

} // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_args(argc, argv, options)) {
        return 0;
    }

    std::ofstream log_file;
    if (!options.no_log_file) {
        log_file.open(std::string(cs2dumper::kProjectName) + ".log", std::ios::app);
    }

    try {
        cs2dumper::memory::ProcessMemory process;
        process.attach(options.process_name);

        const auto start = std::chrono::steady_clock::now();
        const auto result = cs2dumper::analysis::analyze_all(process);

        cs2dumper::output::OutputDumper dumper(
            options.file_types,
            options.indent_size,
            options.output,
            result);
        dumper.dump_all(process);

        const auto elapsed = std::chrono::steady_clock::now() - start;
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

        const std::string message = "analysis completed in " + std::to_string(ms) + "ms";
        std::cout << message << '\n';
        if (log_file.is_open()) {
            log_file << message << '\n';
        }

        return 0;
    } catch (const std::exception& err) {
        std::cerr << "error: " << err.what() << '\n';
        if (log_file.is_open()) {
            log_file << "error: " << err.what() << '\n';
        }
        return 1;
    }
}
