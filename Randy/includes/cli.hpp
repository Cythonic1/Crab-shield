
#pragma once
#include <CLI/CLI.hpp>
#include <cstddef>
#include <iterator>

#include "CLI/CLI.hpp"

// Handle error better.
namespace fs = std::filesystem;

struct RandyArgs {
    fs::path directory;
    bool slow{};
    size_t timeout{};
};

struct Cli {
    CLI::App app{"Randyware - A C++ Ransomware"};

    // sub commands
    RandyArgs randyArgs;

    Cli() {
        app.add_option("directory", randyArgs.directory, "Directory to encrypt")
            ->required()
            ->check(CLI::ExistingDirectory);
        app.add_flag("-s, --slow", randyArgs.slow,
                     "adding timeout between the encryption of each file")
            ->default_val(false);

        app.add_flag("-t, --timeout", randyArgs.timeout,
                     "timeout to take in nanoseconds between each stop")
            ->default_val(false);
    }
};
