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

    Copyright 2017-2019 Telegram Systems LLP
*/
#include "tonlib/GenericAccount.h"
#include "tonlib/utils.h"
#include "block/block-auto.h"
namespace tonlib {
td::Ref<vm::Cell> GenericAccount::get_init_state(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data) noexcept {
  return vm::CellBuilder()
      .append_cellslice(binary_bitstring_to_cellslice("b{00110}").move_as_ok())
      .store_ref(std::move(code))
      .store_ref(std::move(data))
      .finalize();
}

block::StdAddress GenericAccount::get_address(ton::WorkchainId workchain_id,
                                              const td::Ref<vm::Cell>& init_state) noexcept {
  return block::StdAddress(workchain_id, init_state->get_hash().bits(), true /*bounce*/);
}

td::Ref<vm::Cell> GenericAccount::create_ext_message(const block::StdAddress& address,
                                                     const td::Ref<vm::Cell>& new_state,
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
    message.store_ones(1);  // Some(init)
    init_cs = vm::load_cell_slice_ref(new_state);
  } else {
    message.store_zeroes(1);  // None
    init_cs = td::Ref<vm::CellSlice>{vm::CellSlice{}};
  }

  // prepare body
  td::Ref<vm::CellSlice> body_cs{};
  if (body.not_null()) {
    body_cs = vm::load_cell_slice_ref(body);
  } else {
    body_cs = td::Ref<vm::CellSlice>{vm::CellSlice{}};
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
      // header & state fits
      init_as_ref = false;
      body_as_ref = true;
    } else if (message.size() + body_cs->size() <= vm::Cell::max_bits &&
               message.size_refs() + body_cs->size_refs() + 1 <= vm::Cell::max_refs) {  // + init cell ref
      // header & body fits
      init_as_ref = true;
      body_as_ref = false;
    } else {
      // only header fits
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
}  // namespace tonlib
