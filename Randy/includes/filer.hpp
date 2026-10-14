#pragma once

#include <filesystem>
#include <optional>
#include <variant>
#include <vector>

namespace Randy {

namespace fs = std::filesystem;

class Filer {
   public:
    explicit Filer(const fs::path& startingPath);

    Filer(Filer&& other) = default;
    Filer& operator=(Filer&& other) = delete;

    Filer(const Filer& other) = delete;
    Filer& operator=(const Filer& other) = delete;

    ~Filer() = default;

    // This will step though directories if a directory is found will append it to `dirs` if it was
    // a file it will be appended into `files`.
    auto next() noexcept -> std::optional<std::monostate>;

    // This will return a mutable reference to std::vector to the internal files
    auto getFiles() noexcept -> std::vector<fs::path>&;

    // This will move the internal files vector using std::move .
    auto takeFiles() noexcept -> std::vector<fs::path>;

   private:
    std::vector<fs::path> files_{};
    std::vector<fs::directory_entry> dirs_{};
};
}  // namespace Ransom
