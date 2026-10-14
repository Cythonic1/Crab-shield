#include "filer.hpp"

#include <filesystem>
#include <iostream>
#include <print>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace Randy {

Filer::Filer(const fs::path& startingPath) { dirs_.emplace_back(startingPath); }

// noexcept is risky here. fs::directory_iterator throws on errors like permission denied, and that
// would call std::terminate. You could drop noexcept, or use the std::error_code overload and skip
// directories that fail to open.
auto Filer::next() noexcept -> std::optional<std::monostate> {
    if (dirs_.empty()) {
        return std::nullopt;
    }
    std::error_code ec;
    auto dirIter = fs::directory_iterator{dirs_.back(), ec};
    dirs_.pop_back();

    if (ec) {
        std::println("error stoppped: {}", ec.message());
        return std::monostate{};
    }
    for (const auto& entry : dirIter) {
        if (entry.is_regular_file()) {
            files_.push_back(entry.path());
            continue;
        } else if (entry.is_directory()) {
            std::println("dir found -> {}", entry.path().c_str());
            dirs_.push_back(entry);
            continue;
        } else {
            std::println(std::cerr, "unknow file type");
            continue;
        }
    }
    return std::monostate{};
}

auto Filer::getFiles() noexcept -> std::vector<fs::path>& { return files_; }
auto Filer::takeFiles() noexcept -> std::vector<fs::path> {
    return std::exchange(files_, std::vector<fs::path>{});
};
}  // namespace Randy
