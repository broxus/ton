/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#include "DecryptedKey.h"

#include "tonlib/keys/EncryptedKey.h"
#include "tonlib/keys/SimpleEncryption.h"

#include "td/utils/Random.h"
#include "td/utils/crypto.h"

namespace tonlib {
namespace {

auto make_secrets(td::Slice local_password, td::Slice old_secret) -> std::pair<td::SecureString, td::SecureString> {
  td::SecureString secret(32);
  if (old_secret.size() == td::as_slice(secret).size()) {
    secret.as_mutable_slice().copy_from(old_secret);
  } else {
    td::Random::secure_bytes(secret.as_mutable_slice());
  }
  td::SecureString decrypted_secret = SimpleEncryption::combine_secrets(secret, local_password);

  td::SecureString encryption_secret =
      SimpleEncryption::kdf(as_slice(decrypted_secret), "TON local key", EncryptedKey::PBKDF_ITERATIONS);

  return std::make_pair(std::move(secret), std::move(encryption_secret));
}

}  // namespace

DecryptedKey::DecryptedKey(const Mnemonic &mnemonic)
    : mnemonic_words(mnemonic.get_words()), private_key(mnemonic.to_private_key()) {
}
DecryptedKey::DecryptedKey(std::vector<td::SecureString> mnemonic_words, td::Ed25519::PrivateKey key)
    : mnemonic_words(std::move(mnemonic_words)), private_key(std::move(key)) {
}
DecryptedKey::DecryptedKey(RawDecryptedKey key)
    : DecryptedKey(std::move(key.mnemonic_words), td::Ed25519::PrivateKey(key.private_key.copy())) {
}

EncryptedKey DecryptedKey::encrypt(td::Slice local_password, td::Slice old_secret) const {
  auto [secret, encryption_secret] = make_secrets(local_password, old_secret);

  std::vector<td::SecureString> mnemonic_words_copy;
  mnemonic_words_copy.reserve(mnemonic_words.size());
  for (auto &w : mnemonic_words) {
    mnemonic_words_copy.push_back(w.copy());
  }
  auto data = td::serialize_secure(RawDecryptedKey{std::move(mnemonic_words_copy), private_key.as_octet_string()});
  auto encrypted_data = SimpleEncryption::encrypt_data(data, as_slice(encryption_secret));

  return EncryptedKey{std::move(encrypted_data), private_key.get_public_key().move_as_ok(), std::move(secret)};
}

DecryptedFtabiKey::DecryptedFtabiKey(std::vector<td::SecureString> mnemonic_words, std::string derivation_path,
                                     td::Ed25519::PrivateKey key)
    : mnemonic_words(std::move(mnemonic_words))
    , derivation_path(std::move(derivation_path))
    , private_key(std::move(key)) {
}
DecryptedFtabiKey::DecryptedFtabiKey(RawDecryptedFtabiKey key)
    : DecryptedFtabiKey(std::move(key.mnemonic_words), key.derivation_path,
                        td::Ed25519::PrivateKey(key.private_key.copy())) {
}

EncryptedKey DecryptedFtabiKey::encrypt(td::Slice local_password, td::Slice old_secret) const {
  auto [secret, encryption_secret] = make_secrets(local_password, old_secret);

  std::vector<td::SecureString> mnemonic_words_copy;
  mnemonic_words_copy.reserve(mnemonic_words.size());
  for (auto &w : mnemonic_words) {
    mnemonic_words_copy.push_back(w.copy());
  }
  auto data = td::serialize_secure(
      RawDecryptedFtabiKey{std::move(mnemonic_words_copy), derivation_path, private_key.as_octet_string()});
  auto encrypted_data = SimpleEncryption::encrypt_data(data, as_slice(encryption_secret));

  return EncryptedKey{std::move(encrypted_data), private_key.get_public_key().move_as_ok(), std::move(secret)};
}
}  // namespace tonlib
