#pragma once

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace Randy {

enum class SodiumError : uint8_t {
    UnableToInitSodium,
    AESUnavailable,
    EncryptionFailed,
    DecryptionFailed,
};

std::string_view to_string(SodiumError error) noexcept;

template <typename T>
using SodiumExpect = std::expected<T, SodiumError>;

class Sodium {
   public:
    Sodium(Sodium&& other) = default;
    Sodium& operator=(Sodium&& other) = delete;

    Sodium(const Sodium& other) = delete;
    Sodium& operator=(const Sodium& other) = delete;

    ~Sodium() = default;

    [[nodiscard]] static SodiumExpect<Sodium> init();

    [[nodiscard]] std::expected<std::pair<std::vector<std::byte>, uint64_t>, SodiumError> encrypt(
        const std::string& planeText) const noexcept;

    [[nodiscard]] auto decrypt(const std::vector<std::byte>& cipher,
                               const uint64_t cipherlen) const noexcept
        -> std::expected<std::string, SodiumError>;

   private:
    static constexpr size_t AES_KEY_LEN = crypto_aead_aes256gcm_KEYBYTES;
    static constexpr size_t AES_NONCE_LEN = crypto_aead_aes256gcm_NPUBBYTES;
    static constexpr size_t AES_AUTH_TAG = crypto_aead_aes256gcm_ABYTES;

    explicit Sodium(const std::array<unsigned char, AES_KEY_LEN>& key,
                    const std::array<unsigned char, AES_NONCE_LEN>& nonce)
        : key_{key}, nonce_{nonce} {}

    std::array<unsigned char, AES_KEY_LEN> key_{};
    std::array<unsigned char, AES_NONCE_LEN> nonce_{};
};

}  // namespace Randy
