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
#include "EncryptedKey.h"

#include "tonlib/keys/DecryptedKey.h"
#include "tonlib/keys/SimpleEncryption.h"

namespace tonlib {
namespace {

template <typename T>
td::Result<T> decrypt_raw(td::Slice encrypted_data, td::Slice secret, td::Slice local_password, bool old) {
  if (secret.size() != 32) {
    return td::Status::Error("Failed to decrypt key: invalid secret size");
  }
  td::SecureString decrypted_secret;
  if (old) {
    decrypted_secret = td::SecureString(32);
    td::SecureString local_password_hash(32);
    sha256(local_password, local_password_hash.as_mutable_slice());
    for (size_t i = 0; i < 32; i++) {
      decrypted_secret.as_mutable_slice()[i] = static_cast<char>(secret[i] ^ local_password_hash.as_slice()[i]);
    }
  } else {
    decrypted_secret = SimpleEncryption::combine_secrets(secret, local_password);
  }

  td::SecureString encryption_secret =
      SimpleEncryption::kdf(as_slice(decrypted_secret), "TON local key", EncryptedKey::PBKDF_ITERATIONS);

  TRY_RESULT(decrypted_data, SimpleEncryption::decrypt_data(encrypted_data, as_slice(encryption_secret)));

  T raw_decrypted_key;
  TRY_STATUS(td::unserialize(raw_decrypted_key, decrypted_data));
  return td::Result<T>{std::move(raw_decrypted_key)};
}

td::Status validate(const td::Ed25519::PrivateKey &private_key, const td::Ed25519::PublicKey &target_public_key,
                    bool check_public_key) {
  TRY_RESULT(public_key, private_key.get_public_key());
  if (check_public_key && public_key.as_octet_string().as_slice() != target_public_key.as_octet_string().as_slice()) {
    return td::Status::Error("Something wrong: public key of decrypted private key differs from requested public key");
  }
  return td::Status::OK();
}

}  // namespace

template <>
td::Result<DecryptedKey> EncryptedKey::decrypt(td::Slice local_password, bool check_public_key, bool old) const {
  TRY_RESULT(raw_decrypted_key, decrypt_raw<RawDecryptedKey>(encrypted_data, secret, local_password, old))
  DecryptedKey res(std::move(raw_decrypted_key));
  TRY_STATUS(validate(res.private_key, this->public_key, check_public_key))
  return std::move(res);
}

template <>
td::Result<DecryptedFtabiKey> EncryptedKey::decrypt(td::Slice local_password, bool check_public_key, bool old) const {
  TRY_RESULT(raw_decrypted_key, decrypt_raw<RawDecryptedFtabiKey>(encrypted_data, secret, local_password, old))
  DecryptedFtabiKey res(std::move(raw_decrypted_key));
  TRY_STATUS(validate(res.private_key, this->public_key, check_public_key))
  return std::move(res);
}

}  // namespace tonlib
