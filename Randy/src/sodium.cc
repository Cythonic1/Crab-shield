#include "sodium.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <vector>

namespace Randy {

std::string_view to_string(SodiumError error) noexcept {
    switch (error) {
        case SodiumError::UnableToInitSodium:
            return "Unable to init sodium";
        case SodiumError::AESUnavailable:
            return "AES unavailable";
        case SodiumError::EncryptionFailed:
            return "Encryption failed";
        case SodiumError::DecryptionFailed:
            return "Decryption failed";
        default:
            return "Unknown error";
    }
}

SodiumExpect<Sodium> Sodium::init() {
    if (sodium_init() == -1) {
        return std::unexpected{SodiumError::UnableToInitSodium};
    }
    if (crypto_aead_aes256gcm_is_available() == 0) {
        return std::unexpected{SodiumError::AESUnavailable};
    }

    std::array<unsigned char, AES_KEY_LEN> key{};
    std::array<unsigned char, AES_NONCE_LEN> nonce{};

    crypto_aead_aes256gcm_keygen(key.data());
    randombytes_buf(nonce.data(), nonce.size());

    return Sodium{key, nonce};
}

auto Sodium::encrypt(const std::string& planeText) const noexcept
    -> std::expected<std::pair<std::vector<std::byte>, uint64_t>, SodiumError> {
    std::vector<std::byte> cipherBuffer{};
    unsigned long long cipherLength{};
    cipherBuffer.resize(planeText.length() + AES_AUTH_TAG);
    auto res = crypto_aead_aes256gcm_encrypt(
        reinterpret_cast<unsigned char*>(cipherBuffer.data()), &cipherLength,
        reinterpret_cast<const unsigned char*>(planeText.data()), planeText.length(), nullptr, 0,
        nullptr, nonce_.data(), key_.data());
    if (res != 0) {
        return std::unexpected{SodiumError::EncryptionFailed};
    }

    return std::pair{cipherBuffer, static_cast<uint64_t>(cipherLength)};
}

auto Sodium::decrypt(const std::vector<std::byte>& cipher, const uint64_t dataLen) const noexcept
    -> std::expected<std::string, SodiumError> {
    if (cipher.size() < AES_AUTH_TAG) {
        return std::unexpected{SodiumError::DecryptionFailed};
    }
    std::string planeTextBuffer{};

    planeTextBuffer.resize(dataLen);
    auto res = crypto_aead_aes256gcm_decrypt(
        reinterpret_cast<unsigned char*>(planeTextBuffer.data()), nullptr, nullptr,
        reinterpret_cast<const unsigned char*>(cipher.data()), cipher.size(), nullptr, 0,
        nonce_.data(), key_.data());
    if (res != 0) {
        return std::unexpected{SodiumError::EncryptionFailed};
    }

    return planeTextBuffer;
}
}  // namespace Randy
