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
#include "WalletInterface.h"

#include "ftabi/Abi.hpp"

namespace ton {
namespace {
auto transfer_with_comment() -> const td::Ref<ftabi::Function>& {
  static td::Ref<ftabi::Function> function;
  if (function.is_null()) {
    function = td::Ref<ftabi::Function>{
      ftabi::Function{
        "transfer",
        {},
        ftabi::make_params(ftabi::ParamBytes{}),
        {},
        0x00000000u
      }
    };
  }
  return function;
}
} //

td::Result<td::uint64> WalletInterface::get_balance(td::uint64 account_balance, td::uint32 now) const {
  return TRY_VM([&]() -> td::Result<td::uint64> {
    Answer answer = this->run_get_method(Args().set_method_id("balance").set_balance(account_balance).set_now(now));
    if (!answer.success) {
      return td::Status::Error("balance get method failed");
    }
    return static_cast<td::uint64>(answer.stack.write().pop_long());
  }());
}

td::Result<td::Ed25519::PublicKey> WalletInterface::get_public_key() const {
  return GenericAccount::get_public_key(*this);
};

td::Result<td::uint32> WalletInterface::get_seqno() const {
  return GenericAccount::get_seqno(*this);
}

td::Result<td::uint32> WalletInterface::get_wallet_id() const {
  return GenericAccount::get_wallet_id(*this);
}

td::Result<td::Ref<vm::Cell>> WalletInterface::get_init_message(const td::Ed25519::PrivateKey &private_key,
                                                                td::uint32 valid_until) const {
  return make_a_gift_message(private_key, valid_until, {});
}

td::Ref<vm::Cell> WalletInterface::create_int_message(const Gift &gift) {
  vm::CellBuilder cbi;
  GenericAccount::store_int_message(cbi, gift.destination, gift.gramms < 0 ? 0 : gift.gramms);
  if (gift.init_state.not_null()) {
    cbi.store_ones(2);
    cbi.store_ref(gift.init_state);
  } else {
    cbi.store_zeroes(1);
  }

  vm::CellBuilder cb{};
  store_gift_message(cb, gift);
  auto body = cb.finalize();

  if (gift.body_as_ref || !((cbi.size() + 1 + body->size() <= vm::Cell::max_bits) &&
                            (cbi.size_refs() + body->size_refs() <= vm::Cell::max_refs))) {
    cbi.store_ones(1);
    cbi.store_ref(body);
  } else {
    cbi.store_zeroes(1);
    cbi.append_data_cell(body);
  }
  return cbi.finalize();
}

void WalletInterface::store_gift_message(vm::CellBuilder &cb, const Gift &gift) {
  if (gift.body.not_null()) {
    auto body = vm::load_cell_slice(gift.body);
    //TODO: handle error
    CHECK(cb.append_cellslice_bool(body));
    return;
  }

  if (gift.is_encrypted) {
    cb.store_long(1, 32);
    vm::CellString::store(cb, gift.message, 35 * 8).ensure();
  } else if (!gift.message.empty()) {
    std::vector<uint8_t> encoded_string;
    encoded_string.resize(gift.message.size());
    std::memcpy(encoded_string.data(), gift.message.data(), gift.message.size());

    const auto inputs = ftabi::ValueRef(
      ftabi::ValueBytes{ftabi::ParamRef{ftabi::ParamBytes{}}, encoded_string});

    auto body_r = transfer_with_comment()->encode_input(
      /*header*/ {}, 
      {inputs}, 
      /*internal*/ true, 
      td::optional<td::Ed25519::PrivateKey>{},
      td::optional<ftabi::FunctionCall::LedgerKey>{});

    if (body_r.is_error()) {
      std::cout << body_r.move_as_error().message().c_str() << std::endl;
    } else {
      CHECK(cb.append_cellslice_bool(body_r.move_as_ok()))
    }
  }
}
}  // namespace ton
