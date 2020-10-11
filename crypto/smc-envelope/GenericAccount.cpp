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
#include "GenericAccount.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
namespace ton {

namespace smc {
td::Ref<vm::CellSlice> pack_grams(td::uint64 amount) {
  vm::CellBuilder cb;
  block::tlb::t_Grams.store_integer_value(cb, td::BigInt256(amount));
  return vm::load_cell_slice_ref(cb.finalize());
}

bool unpack_grams(td::Ref<vm::CellSlice> cs, td::uint64& amount) {
  td::RefInt256 got;
  if (!block::tlb::t_Grams.as_integer_to(cs, got)) {
    return false;
  }
  if (!got->unsigned_fits_bits(63)) {
    return false;
  }
  auto x = got->to_long();
  if (x < 0) {
    return false;
  }
  amount = x;
  return true;
}
}  // namespace smc

td::Ref<vm::Cell> GenericAccount::get_init_state(const td::Ref<vm::Cell>& code,
                                                 const td::Ref<vm::Cell>& data) noexcept {
  return vm::CellBuilder()
      .store_zeroes(2)
      .store_ones(2)
      .store_zeroes(1)
      .store_ref(std::move(code))
      .store_ref(std::move(data))
      .finalize();
}

block::StdAddress GenericAccount::get_address(ton::WorkchainId workchain_id,
                                              const td::Ref<vm::Cell>& init_state) noexcept {
  return block::StdAddress(workchain_id, init_state->get_hash().bits(), true /*bounce*/);
}

void GenericAccount::store_int_message(vm::CellBuilder& cb, const block::StdAddress& dest_address, td::int64 gramms) {
  td::BigInt256 dest_addr;
  dest_addr.import_bits(dest_address.addr.as_bitslice());
  cb.store_zeroes(1)
      .store_ones(1)
      .store_long(dest_address.bounceable, 1)
      .store_zeroes(3)
      .store_ones(1)
      .store_zeroes(2)
      .store_long(dest_address.workchain, 8)
      .store_int256(dest_addr, 256);
  block::tlb::t_Grams.store_integer_value(cb, td::BigInt256(gramms));
  cb.store_zeroes(9 + 64 + 32);
}

td::Ref<vm::Cell> GenericAccount::create_ext_message(const block::StdAddress& address, const td::Ref<vm::Cell>& new_state,
                                                     const td::Ref<vm::Cell>& body) noexcept {
  vm::CellBuilder message{};

  /*info*/ {
    block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
    /* src */
    tlb::csr_pack(info.src, block::gen::MsgAddressExt::Record_addr_none{});
    /* dest */ {
      block::gen::MsgAddressInt::Record_addr_std dest;
      dest.anycast = vm::CellBuilder().store_zeroes(1).as_cellslice_ref();
      dest.workchain_id = address.workchain;
      dest.address = address.addr;

      tlb::csr_pack(info.dest, dest);
    }
    /* import_fee */ {
      vm::CellBuilder cb;
      block::tlb::t_Grams.store_integer_value(cb, td::BigInt256(0));
      info.import_fee = cb.as_cellslice_ref();
    }

    vm::Ref<vm::CellSlice> info_cs;
    CHECK(tlb::csr_pack(info_cs, info) && message.append_cellslice_bool(info_cs))
  }

  // prepare init
  td::Ref<vm::CellSlice> init_cs{};
  if (new_state.not_null()) {
    message.store_ones(1);
    init_cs = vm::load_cell_slice_ref(new_state);
  } else {
    message.store_zeroes(1);
    init_cs = vm::CellBuilder{}.as_cellslice_ref();
  }

  // prepare body
  td::Ref<vm::CellSlice> body_cs{};
  if (body.not_null()) {
    body_cs = vm::load_cell_slice_ref(body);
  } else {
    body_cs = vm::CellBuilder{}.as_cellslice_ref();
  }

  // calculate layout
  bool init_as_ref, body_as_ref;
  if (message.size() + init_cs->size() + body_cs->size() <= vm::Cell::max_bits &&
      message.size_refs() + init_cs->size_refs() + body_cs->size_refs() <= vm::Cell::max_refs) {
    // add fits in one cell
    body_as_ref = false;
    init_as_ref = false;
  } else {
    if (message.size() + init_cs->size() <= vm::Cell::max_bits &&
        message.size_refs() + init_cs->size_refs() + 1 <= vm::Cell::max_refs) {  // + body cell ref
      // header & state fit
      init_as_ref = false;
      body_as_ref = true;
    } else if (message.size() + body_cs->size() <= vm::Cell::max_bits &&
               message.size_refs() + body_cs->size_refs() + 1 <= vm::Cell::max_refs) {  // + init cell ref
      // header & body fit
      init_as_ref = true;
      body_as_ref = false;
    } else {
      // only header fit
      init_as_ref = true;
      body_as_ref = true;
    }
  }

  if (new_state.not_null()) {
    if (init_as_ref) {
      message.store_ones(1).store_ref(new_state);
    } else {
      message.store_zeroes(1).append_cellslice(init_cs);
    }
  }

  if (body_as_ref && body.not_null()) {
    message.store_ones(1).store_ref(body);
  } else {
    message.store_zeroes(1).append_cellslice(body_cs);
  }

  auto res = message.finalize();
  CHECK(res.not_null())

  return res;
}

td::Result<td::Ed25519::PublicKey> GenericAccount::get_public_key(const SmartContract& sc) {
  auto answer = sc.run_get_method("get_public_key");
  if (!answer.success) {
    return td::Status::Error("get_public_key failed");
  }
  auto do_get_public_key = [&]() -> td::Result<td::Ed25519::PublicKey> {
    auto key = answer.stack.write().pop_int_finite();
    td::SecureString bytes(32);
    if (!key->export_bytes(bytes.as_mutable_slice().ubegin(), bytes.size(), false)) {
      return td::Status::Error("get_public_key failed");
    }
    return td::Ed25519::PublicKey(std::move(bytes));
  };
  return TRY_VM(do_get_public_key());
}

td::Result<td::uint32> GenericAccount::get_seqno(const SmartContract& sc) {
  return TRY_VM([&]() -> td::Result<td::uint32> {
    auto answer = sc.run_get_method("seqno");
    if (!answer.success) {
      return td::Status::Error("seqno get method failed");
    }
    return static_cast<td::uint32>(answer.stack.write().pop_long_range(std::numeric_limits<td::uint32>::max()));
  }());
}

td::Result<td::uint32> GenericAccount::get_wallet_id(const SmartContract& sc) {
  return TRY_VM([&]() -> td::Result<td::uint32> {
    auto answer = sc.run_get_method("wallet_id");
    if (!answer.success) {
      return td::Status::Error("seqno get method failed");
    }
    return static_cast<td::uint32>(answer.stack.write().pop_long_range(std::numeric_limits<td::uint32>::max()));
  }());
}
}  // namespace ton
