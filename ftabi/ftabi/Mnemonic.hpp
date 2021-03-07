#pragma once

#include <crypto/Ed25519.h>

namespace ftabi::mnemonic {
constexpr td::Slice TON_DERIVATION_PATH = "m/44'/396'/0'/0/0";

auto recover_key(const std::vector<td::SecureString>& mnemonic, td::Slice derivation_path = TON_DERIVATION_PATH)
    -> td::Result<td::Ed25519::PrivateKey>;
auto generate_key(const std::vector<td::SecureString>& dictionary, td::Slice derivation_path = TON_DERIVATION_PATH)
    -> td::Result<std::pair<std::vector<td::SecureString>, td::Ed25519::PrivateKey>>;
}  // namespace ftabi::mnemonic
