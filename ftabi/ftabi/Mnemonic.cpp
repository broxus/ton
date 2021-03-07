#include "Mnemonic.hpp"

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <td/utils/Random.h>
#include <td/utils/crypto.h>

namespace ftabi::mnemonic {
constexpr uint32_t SECP256K1_N_0 = 0xD0364141u;
constexpr uint32_t SECP256K1_N_1 = 0xBFD25E8Cu;
constexpr uint32_t SECP256K1_N_2 = 0xAF48A03Bu;
constexpr uint32_t SECP256K1_N_3 = 0xBAAEDCE6u;
constexpr uint32_t SECP256K1_N_4 = 0xFFFFFFFEu;
constexpr uint32_t SECP256K1_N_5 = 0xFFFFFFFFu;
constexpr uint32_t SECP256K1_N_6 = 0xFFFFFFFFu;
constexpr uint32_t SECP256K1_N_7 = 0xFFFFFFFFu;

constexpr uint32_t SECP256K1_N_C_0 = ~SECP256K1_N_0 + 1u;
constexpr uint32_t SECP256K1_N_C_1 = ~SECP256K1_N_1;
constexpr uint32_t SECP256K1_N_C_2 = ~SECP256K1_N_2;
constexpr uint32_t SECP256K1_N_C_3 = ~SECP256K1_N_3;
constexpr uint32_t SECP256K1_N_C_4 = 1u;

constexpr uint32_t HARDENED_BIT = 1u << 31u;
constexpr int PBKDF2_ROUNDS = 2048;

constexpr auto ENTROPY_OFFSET = 8u;

struct CurveSecp256k1 {
  CurveSecp256k1() noexcept {
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    CHECK(group != nullptr)
  }
  ~CurveSecp256k1() {
    EC_GROUP_free(group);
  }

  CurveSecp256k1(CurveSecp256k1 const&) = delete;
  void operator=(CurveSecp256k1 const& x) = delete;

  EC_GROUP* group{};
};

static CurveSecp256k1 secp256k1{};

struct BigNumber {
  explicit BigNumber(td::Slice data) noexcept {
    handle = BN_bin2bn(data.ubegin(), data.size(), nullptr);
    CHECK(handle != nullptr)
  }
  ~BigNumber() {
    BN_free(handle);
  }

  BigNumber(BigNumber const&) = delete;
  void operator=(BigNumber const& x) = delete;

  BigNumber(BigNumber&& other) noexcept = default;

  BIGNUM* handle{};
};

struct PrivateKey {
  explicit PrivateKey(td::Slice data) noexcept {
    handle = EC_KEY_new();
    CHECK(handle != nullptr)
    CHECK(EC_KEY_set_group(handle, secp256k1.group))

    BigNumber num{data};
    CHECK(EC_KEY_set_private_key(handle, num.handle))
  }
  ~PrivateKey() {
    EC_KEY_free(handle);
  }

  PrivateKey(PrivateKey const&) = delete;
  void operator=(PrivateKey const& x) = delete;

  PrivateKey(PrivateKey&& other) noexcept = default;

  auto reset(const BigNumber& num) -> td::Status {
    EC_KEY_free(handle);

    handle = EC_KEY_new();
    CHECK(handle != nullptr)
    CHECK(EC_KEY_set_group(handle, secp256k1.group))
    CHECK(EC_KEY_set_private_key(handle, num.handle))

    return finalize();
  }

  [[nodiscard]] auto finalize() const -> td::Status {
    auto private_key = EC_KEY_get0_private_key(handle);
    auto pub_key = EC_POINT_new(secp256k1.group);
    if (!EC_POINT_mul(secp256k1.group, pub_key, private_key, nullptr, nullptr, nullptr)) {
      EC_POINT_free(pub_key);
      return td::Status::Error("failed to create secp256k1 public key");
    }

    CHECK(EC_KEY_set_public_key(handle, pub_key))
    EC_POINT_free(pub_key);

    if (!EC_KEY_check_key(handle)) {
      return td::Status::Error("invalid secp256k1 private key");
    }

    return td::Status::OK();
  }

  [[nodiscard]] auto create_ed25519_private_key() const -> td::Result<td::Ed25519::PrivateKey> {
    td::SecureString bytes(32);

    const auto len = EC_KEY_priv2oct(handle, bytes.as_mutable_slice().ubegin(), bytes.size());
    if (len != bytes.size()) {
      return td::Status::Error("failed to export to ed25519 private key");
    }

    return td::Ed25519::PrivateKey(std::move(bytes));
  }

  [[nodiscard]] auto serialize(td::MutableSlice output) const -> td::Status {
    if (output.size() != 32 || BN_bn2binpad(data(), output.ubegin(), 32)) {
      return td::Status::OK();
    } else {
      return td::Status::Error("failed to serialize private key");
    }
  }

  [[nodiscard]] auto serialize_compressed_public(td::MutableSlice output) const -> td::Status {
    auto point = EC_KEY_get0_public_key(handle);
    if (point == nullptr) {
      return td::Status::Error("failed to get secp256k1 public key");
    }

    uint8_t* buffer{};
    auto len = EC_POINT_point2buf(secp256k1.group, point, POINT_CONVERSION_COMPRESSED, &buffer, nullptr);
    if (len != output.size()) {
      if (buffer != nullptr) {
        OPENSSL_free(buffer);
      }
      return td::Status::Error("failed to convert secp256k1 public key");
    }
    std::memcpy(output.data(), buffer, len);
    OPENSSL_free(buffer);
    return td::Status::OK();
  }

  [[nodiscard]] auto data() const -> const BIGNUM* {
    return EC_KEY_get0_private_key(handle);
  }

  EC_KEY* handle{};
};

struct Scalar {
  static auto from_bignum(const BIGNUM* num) -> td::Result<Scalar> {
    td::BufferSlice buffer(32);
    if (BN_bn2binpad(num, buffer.as_slice().ubegin(), 32) != 32) {
      return td::Status::Error("failed to construct secp256k1 scalar");
    }
    Scalar result{};
    result.set_b32(buffer.as_slice().ubegin());
    return result;
  }

  auto create_bignum() -> BigNumber {
    td::BufferSlice buffer(32);
    fill_b32(buffer.as_slice().ubegin());
    return BigNumber{buffer.as_slice()};
  }

  auto set_b32(const uint8_t* b32) -> bool {
    v[0] = static_cast<uint32_t>(b32[31]) | (static_cast<uint32_t>(b32[30]) << 8u) |
           (static_cast<uint32_t>(b32[29]) << 16u) | (static_cast<uint32_t>(b32[28]) << 24u);
    v[1] = static_cast<uint32_t>(b32[27]) | (static_cast<uint32_t>(b32[26]) << 8u) |
           (static_cast<uint32_t>(b32[25]) << 16u) | (static_cast<uint32_t>(b32[24]) << 24u);
    v[2] = static_cast<uint32_t>(b32[23]) | (static_cast<uint32_t>(b32[22]) << 8u) |
           (static_cast<uint32_t>(b32[21]) << 16u) | (static_cast<uint32_t>(b32[20]) << 24u);
    v[3] = static_cast<uint32_t>(b32[19]) | (static_cast<uint32_t>(b32[18]) << 8u) |
           (static_cast<uint32_t>(b32[17]) << 16u) | (static_cast<uint32_t>(b32[16]) << 24u);
    v[4] = static_cast<uint32_t>(b32[15]) | (static_cast<uint32_t>(b32[14]) << 8u) |
           (static_cast<uint32_t>(b32[13]) << 16u) | (static_cast<uint32_t>(b32[12]) << 24u);
    v[5] = static_cast<uint32_t>(b32[11]) | (static_cast<uint32_t>(b32[10]) << 8u) |
           (static_cast<uint32_t>(b32[9]) << 16u) | (static_cast<uint32_t>(b32[8]) << 24u);
    v[6] = static_cast<uint32_t>(b32[7]) | (static_cast<uint32_t>(b32[6]) << 8u) |
           (static_cast<uint32_t>(b32[5]) << 16u) | (static_cast<uint32_t>(b32[4]) << 24u);
    v[7] = static_cast<uint32_t>(b32[3]) | (static_cast<uint32_t>(b32[2]) << 8u) |
           (static_cast<uint32_t>(b32[1]) << 16u) | (static_cast<uint32_t>(b32[0]) << 24u);

    return reduce(check_overflow());
  }

  void fill_b32(uint8_t* bin) {
    bin[0] = (v[7] >> 24u);
    bin[1] = (v[7] >> 16u);
    bin[2] = (v[7] >> 8u);
    bin[3] = (v[7]);
    bin[4] = (v[6] >> 24u);
    bin[5] = (v[6] >> 16u);
    bin[6] = (v[6] >> 8u);
    bin[7] = (v[6]);
    bin[8] = (v[5] >> 24u);
    bin[9] = (v[5] >> 16u);
    bin[10] = (v[5] >> 8u);
    bin[11] = (v[5]);
    bin[12] = (v[4] >> 24u);
    bin[13] = (v[4] >> 16u);
    bin[14] = (v[4] >> 8u);
    bin[15] = (v[4]);
    bin[16] = (v[3] >> 24u);
    bin[17] = (v[3] >> 16u);
    bin[18] = (v[3] >> 8u);
    bin[19] = (v[3]);
    bin[20] = (v[2] >> 24u);
    bin[21] = (v[2] >> 16u);
    bin[22] = (v[2] >> 8u);
    bin[23] = (v[2]);
    bin[24] = (v[1] >> 24u);
    bin[25] = (v[1] >> 16u);
    bin[26] = (v[1] >> 8u);
    bin[27] = (v[1]);
    bin[28] = (v[0] >> 24u);
    bin[29] = (v[0] >> 16u);
    bin[30] = (v[0] >> 8u);
    bin[31] = (v[0]);
  }

  auto check_overflow() -> bool {
    auto yes = false;
    auto no = false;
    no = no || (v[7] < SECP256K1_N_7); /* No need for a > check. */
    no = no || (v[6] < SECP256K1_N_6); /* No need for a > check. */
    no = no || (v[5] < SECP256K1_N_5); /* No need for a > check. */
    no = no || (v[4] < SECP256K1_N_4);
    yes = yes || ((v[4] > SECP256K1_N_4) && !no);
    no = no || ((v[3] < SECP256K1_N_3) && !yes);
    yes = yes || ((v[3] > SECP256K1_N_3) && !no);
    no = no || ((v[2] < SECP256K1_N_2) && !yes);
    yes = yes || ((v[2] > SECP256K1_N_2) && !no);
    no = no || ((v[1] < SECP256K1_N_1) && !yes);
    yes = yes || ((v[1] > SECP256K1_N_1) && !no);
    yes = yes || ((v[0] >= SECP256K1_N_0) && !no);
    return yes;
  }

  auto reduce(bool overflow) -> bool {
    uint64_t o = overflow;
    uint64_t t;
    t = static_cast<uint64_t>(v[0]) + o * static_cast<uint64_t>(SECP256K1_N_C_0);
    v[0] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[1]) + o * static_cast<uint64_t>(SECP256K1_N_C_1);
    v[1] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[2]) + o * static_cast<uint64_t>(SECP256K1_N_C_2);
    v[2] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[3]) + o * static_cast<uint64_t>(SECP256K1_N_C_3);
    v[3] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[4]) + o * static_cast<uint64_t>(SECP256K1_N_C_4);
    v[4] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[5]);
    v[5] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[6]);
    v[6] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[7]);
    v[7] = static_cast<uint32_t>(t);
    return overflow;
  }

  auto add_in_place(const Scalar& a, const Scalar& b) -> bool {
    auto t = static_cast<uint64_t>(a.v[0]) + static_cast<uint64_t>(b.v[0]);
    v[0] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[1]) + static_cast<uint64_t>(b.v[1]);
    v[1] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[2]) + static_cast<uint64_t>(b.v[2]);
    v[2] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[3]) + static_cast<uint64_t>(b.v[3]);
    v[3] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[4]) + static_cast<uint64_t>(b.v[4]);
    v[4] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[5]) + static_cast<uint64_t>(b.v[5]);
    v[5] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[6]) + static_cast<uint64_t>(b.v[6]);
    v[6] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(a.v[7]) + static_cast<uint64_t>(b.v[7]);
    v[7] = static_cast<uint32_t>(t);
    t >>= 32u;
    auto overflow = t + static_cast<uint64_t>(check_overflow());
    CHECK(overflow == 0 || overflow == 1)
    overflow = overflow | static_cast<uint64_t>(reduce(overflow == 1));
    return overflow == 1;
  }

  std::array<uint32_t, 8> v{};
};

struct ExtendedPrivateKey {
  auto derive(uint32_t number) -> td::Status {
    td::BufferSlice hmac(64);
    td::BufferSlice hmac_input(37);

    if ((number & HARDENED_BIT) == 0) {
      TRY_STATUS(secret_key.serialize_compressed_public(hmac_input.as_slice().substr(0, 33)))
    } else {
      auto buffer = hmac_input.as_slice();
      buffer[0] = 0;
      TRY_STATUS(secret_key.serialize(buffer.substr(1, 32)))
    }

    for (uint32_t i = 0; i < 4; ++i) {
      const uint8_t shift = static_cast<uint8_t>(3u - i) << 3u;
      hmac_input.as_slice()[33 + i] = number >> shift;
    }

    td::hmac_sha512(chain_code.as_slice(), hmac_input.as_slice(), hmac.as_slice());

    PrivateKey temp_key{hmac.as_slice().substr(0, 32)};
    TRY_STATUS(temp_key.finalize())

    TRY_RESULT(source_data, Scalar::from_bignum(temp_key.data()))
    TRY_RESULT(current_data, Scalar::from_bignum(secret_key.data()))

    Scalar result{};
    result.add_in_place(source_data, current_data);
    secret_key.reset(result.create_bignum());

    chain_code = td::BufferSlice{hmac.as_slice().substr(32, 32)};

    return td::Status::OK();
  }

  PrivateKey secret_key;
  td::BufferSlice chain_code;
};

auto child_number_from_str(td::Slice str) -> td::Result<uint32_t> {
  uint32_t value;
  if (str.size() > 1 && str[str.size() - 1] == '\'') {
    TRY_RESULT_ASSIGN(value, td::to_integer_safe<uint32_t>(td::Slice{str.data(), str.size() - 1}))
    value |= HARDENED_BIT;
  } else {
    TRY_RESULT_ASSIGN(value, td::to_integer_safe<uint32_t>(str))
  }
  return value;
}

auto derivation_path_from_str(td::Slice str) -> td::Result<std::vector<uint32_t>> {
  auto path = td::full_split(str, '/');

  if (path.empty() || path[0] != "m") {
    return td::Status::Error("invalid derivation path");
  }

  std::vector<uint32_t> result;
  result.reserve(path.size() - 1);
  for (const auto& item : path) {
    if (item == "m") {
      continue;
    }

    TRY_RESULT(value, child_number_from_str(item))
    result.emplace_back(value);
  }
  return result;
}

td::SecureString join(const std::vector<td::SecureString>& words) {
  size_t res_size = 0;
  for (size_t i = 0; i < words.size(); i++) {
    if (i != 0) {
      res_size++;
    }
    res_size += words[i].size();
  }
  td::SecureString res(res_size);
  auto dst = res.as_mutable_slice();
  for (size_t i = 0; i < words.size(); i++) {
    if (i != 0) {
      dst[0] = ' ';
      dst.remove_prefix(1);
    }
    dst.copy_from(words[i].as_slice());
    dst.remove_prefix(words[i].size());
  }
  return res;
}

auto recover_key(const std::vector<td::SecureString>& mnemonic, td::Slice derivation_path)
    -> td::Result<td::Ed25519::PrivateKey> {
  const auto phrase = join(mnemonic);

  td::BufferSlice seed(64);
  td::pbkdf2_sha512(phrase, "mnemonic", PBKDF2_ROUNDS, seed.as_slice());

  td::BufferSlice hmac(64);
  td::hmac_sha512("Bitcoin seed", seed.as_slice(), hmac.as_slice());

  ExtendedPrivateKey sk{
      PrivateKey{hmac.as_slice().substr(0, 32)},
      td::BufferSlice{hmac.as_slice().substr(32, 32)},
  };
  TRY_STATUS(sk.secret_key.finalize())

  TRY_RESULT(derivation_path_parts, derivation_path_from_str(derivation_path))
  for (auto path : derivation_path) {
    TRY_STATUS(sk.derive(path))
  }

  return sk.secret_key.create_ed25519_private_key();
}

enum MnemonicType : uint32_t {
  Words12 = (128u << ENTROPY_OFFSET) | 4u,
  Words24 = (256u << ENTROPY_OFFSET) | 8u,
};

constexpr auto default_mnemonic = MnemonicType::Words12;

auto entropy_bits(MnemonicType type) -> size_t {
  return type >> ENTROPY_OFFSET;
}

auto checksum_bits(MnemonicType type) -> size_t {
  return type & 0xffu;
}

auto total_bits(MnemonicType type) -> size_t {
  return entropy_bits(type) + checksum_bits(type);
}

auto word_count(MnemonicType type) -> size_t {
  return total_bits(type) / 11u;
}

template <typename T>
inline constexpr auto make_ones(uint8_t count) -> T {
  return static_cast<T>((T{0b1u} << count) - T{0b1u});
}

auto generate_words(const std::vector<td::SecureString>& dictionary) -> std::vector<td::SecureString> {
  CHECK(dictionary.size() == 2048)

  const auto entropy_size = entropy_bits(default_mnemonic) >> 3u;
  const auto result_len = word_count(default_mnemonic);

  td::BufferSlice buffer(entropy_size + 1);
  td::Random::secure_bytes(buffer.as_slice().substr(0, entropy_size));

  auto checksum_byte = td::sha256(buffer.as_slice().substr(0, entropy_size))[0];
  buffer.as_slice()[entropy_size] = checksum_byte;

  std::vector<td::SecureString> result;
  result.reserve(result_len);

  const auto* slice = buffer.as_slice().ubegin();

  size_t offset = 0;
  for (int i = 0; i < result_len; i++) {
    const auto j = offset / 8u;

    const auto first_byte_length = static_cast<uint16_t>(8u - (offset & 0b111u));

    const auto second_byte_length = std::min(11u - first_byte_length, 8u);
    const auto second_byte_offset = static_cast<uint16_t>(8u - second_byte_length);

    const auto third_byte_length = 11u - first_byte_length - second_byte_length;
    const auto third_byte_offset = static_cast<uint16_t>(8u - third_byte_length);

    uint16_t word_i{};
    word_i |= static_cast<uint16_t>(slice[j] & make_ones<uint16_t>(first_byte_length));
    word_i <<= second_byte_length;
    word_i |= static_cast<uint16_t>(slice[j + 1] >> second_byte_offset);
    if (third_byte_length > 0) {
      word_i <<= third_byte_length;
      word_i |= static_cast<uint16_t>(slice[j + 2] >> third_byte_offset);
    }

    offset += 11u;

    result.emplace_back(dictionary[word_i].copy());
  }

  return result;
}

auto generate_key(const std::vector<td::SecureString>& dictionary, td::Slice derivation_path)
    -> td::Result<std::pair<std::vector<td::SecureString>, td::Ed25519::PrivateKey>> {
  auto mnemonic = generate_words(dictionary);
  TRY_RESULT(key, recover_key(mnemonic, derivation_path))
  return std::make_pair(std::move(mnemonic), std::move(key));
}

}  // namespace ftabi::mnemonic
