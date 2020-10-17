#include "LiteServerUtils.h"

#include "crypto/block/mc-config.h"

namespace tonlib {

auto parse_grams(td::Ref<vm::CellSlice>& grams) -> td::Result<std::string> {
  td::BufferSlice bytes(32);
  td::RefInt256 value;
  if (!block::tlb::t_Grams.as_integer_to(grams, value) ||
      !value->export_bytes(reinterpret_cast<unsigned char*>(bytes.data()), 32, false)) {
    return td::Status::Error("failed to unpack grams");
  }
  return bytes.as_slice().str();
}

auto parse_msg_anycast(td::Ref<vm::CellSlice>& anycast)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_messageAnycast>> {
  block::gen::Anycast::Record info;
  if (!tlb::unpack(anycast.write(), info)) {
    return td::Status::Error("failed to unpack anycast");
  }
  return tonlib_api::make_object<tonlib_api::liteServer_messageAnycast>(
      info.depth, td::Slice(info.rewrite_pfx->bits().get_byte_ptr(), info.rewrite_pfx->byte_size()).str());
}

auto parse_msg_address_ext(td::Ref<vm::CellSlice>& addr)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_MessageAddressExt>> {
  auto tag = block::gen::t_MsgAddressExt.get_tag(*addr);
  switch (tag) {
    case block::gen::MsgAddressExt::addr_none: {
      block::gen::MsgAddressExt::Record_addr_none info;
      if (!tlb::unpack(addr.write(), info)) {
        return td::Status::Error("failed to unpack external none message address");
      }
      return tonlib_api::make_object<tonlib_api::liteServer_messageAddressExtNone>();
    }
    case block::gen::MsgAddressExt::addr_extern: {
      block::gen::MsgAddressExt::Record_addr_extern info;
      if (!tlb::unpack(addr.write(), info)) {
        return td::Status::Error("failed to unpack external message address");
      }
      return tonlib_api::make_object<tonlib_api::liteServer_messageAddressExtSome>(
          info.len, td::Slice(info.external_address->bits().get_byte_ptr(), info.external_address->byte_size()).str());
    }
    default:
      return td::Status::Error("failed to unpack ext message address");
  }
}

auto parse_msg_address_int(td::Ref<vm::CellSlice>& addr)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_MessageAddressInt>> {
  auto tag = block::gen::t_MsgAddressInt.get_tag(*addr);
  switch (tag) {
    case block::gen::MsgAddressInt::addr_std: {
      block::gen::MsgAddressInt::Record_addr_std info;
      if (!tlb::unpack(addr.write(), info)) {
        return td::Status::Error("failed to unpack internal std message address");
      }
      if (info.anycast->prefetch_ulong(1) == 0) {
        return tonlib_api::make_object<tonlib_api::liteServer_messageAddressIntStd>(info.workchain_id,
                                                                                    info.address.as_slice().str());
      } else {
        TRY_RESULT(anycast, parse_msg_anycast(info.anycast))
        return tonlib_api::make_object<tonlib_api::liteServer_messageAddressIntStdAnycast>(
            std::move(anycast), info.workchain_id, info.address.as_slice().str());
      }
    }
    case block::gen::MsgAddressInt::addr_var: {
      block::gen::MsgAddressInt::Record_addr_var info;
      if (!tlb::unpack(addr.write(), info)) {
        return td::Status::Error("failed to unpack internal var message address");
      }
      if (info.anycast.is_null()) {
        return tonlib_api::make_object<tonlib_api::liteServer_messageAddressIntVar>(
            info.workchain_id, info.addr_len,
            td::Slice(info.address->bits().get_byte_ptr(), info.address->byte_size()).str());
      } else {
        TRY_RESULT(anycast, parse_msg_anycast(info.anycast))
        return tonlib_api::make_object<tonlib_api::liteServer_messageAddressIntVarAnycast>(
            std::move(anycast), info.workchain_id, info.addr_len,
            td::Slice(info.address->bits().get_byte_ptr(), info.address->byte_size()).str());
      }
    }
    default:
      return td::Status::Error("failed to unpack int message address");
  }
}

auto parse_message_info(td::Ref<vm::CellSlice>& msg) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_MessageInfo>> {
  auto tag = block::gen::t_CommonMsgInfo.get_tag(*msg);
  switch (tag) {
    case block::gen::CommonMsgInfo::ext_in_msg_info: {
      block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
      if (!tlb::unpack(msg.write(), info)) {
        return td::Status::Error("failed to unpack ext_in message info");
      }
      TRY_RESULT(src, parse_msg_address_ext(info.src))
      TRY_RESULT(dest, parse_msg_address_int(info.dest))
      TRY_RESULT(import_fee, parse_grams(info.import_fee))
      return tonlib_api::make_object<tonlib_api::liteServer_messageInfoExtIn>(std::move(src), std::move(dest),
                                                                              import_fee);
    }
    case block::gen::CommonMsgInfo::ext_out_msg_info: {
      block::gen::CommonMsgInfo::Record_ext_out_msg_info info;
      if (!tlb::unpack(msg.write(), info)) {
        return td::Status::Error("failed to unpack ext_out message info");
      }
      TRY_RESULT(src, parse_msg_address_int(info.src))
      TRY_RESULT(dest, parse_msg_address_ext(info.dest))
      return tonlib_api::make_object<tonlib_api::liteServer_messageInfoExtOut>(std::move(src), std::move(dest),
                                                                               info.created_lt, info.created_at);
    }
    case block::gen::CommonMsgInfo::int_msg_info: {
      block::gen::CommonMsgInfo::Record_int_msg_info info;
      if (!tlb::unpack(msg.write(), info)) {
        return td::Status::Error("failed to unpack internal message info");
      }
      TRY_RESULT(src, parse_msg_address_int(info.src))
      TRY_RESULT(dest, parse_msg_address_int(info.dest))
      block::CurrencyCollection value_currency_collection;
      if (!value_currency_collection.validate_unpack(info.value)) {
        return td::Status::Error("failed to unpack internal message value");
      }
      TRY_RESULT(value, to_tonlib_api(value_currency_collection.grams))
      TRY_RESULT(ihr_fee, parse_grams(info.ihr_fee))
      TRY_RESULT(fwd_fee, parse_grams(info.fwd_fee))
      return tonlib_api::make_object<tonlib_api::liteServer_messageInfoInt>(
          info.ihr_disabled, info.bounce, info.bounced, std::move(src), std::move(dest), value, ihr_fee, fwd_fee,
          info.created_lt, info.created_at);
    }
    default:
      return td::Status::Error("failed to unpack transaction incoming message");
  }
}

auto parse_optional_cs(td::Ref<vm::CellSlice>&& cs) -> td::Result<std::string> {
  if (cs.is_null()) {
    return std::string{};
  }
  if (cs->prefetch_long(1) == 0) {
    cs.write().advance(1);
    TRY_RESULT(data, vm::std_boc_serialize(vm::CellBuilder{}.append_cellslice(cs).finalize()))
    return data.as_slice().str();
  } else {
    auto ref = cs->prefetch_ref();
    if (ref.is_null()) {
      return std::string{};
    }
    TRY_RESULT(data, vm::std_boc_serialize(ref))
    return data.as_slice().str();
  }
}

auto parse_message(td::Ref<vm::Cell>&& msg) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_message>> {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg, block::gen::t_Message_Any, message)) {
    return td::Status::Error("failed to unpack message");
  }

  TRY_RESULT(info, parse_message_info(message.info))
  TRY_RESULT(init, parse_optional_cs(std::move(message.info)))
  TRY_RESULT(body, parse_optional_cs(std::move(message.body)))

  return tonlib_api::make_object<tonlib_api::liteServer_message>(msg->get_hash().as_slice().str(), std::move(info),
                                                                 init, body);
}

auto check_special_addr(const tonlib_api::liteServer_messageAddressIntStd* addr, char byte) -> bool {
  if (addr->workchain_ != ton::masterchainId) {
    return false;
  }
  for (const auto& c : addr->address_) {
    if (c != byte) {
      return false;
    }
  }
  return true;
}

auto check_internal_message(const tonlib_api_ptr<tonlib_api::liteServer_message>& msg)
    -> std::tuple<const tonlib_api::liteServer_messageInfoInt*, const tonlib_api::liteServer_messageAddressIntStd*,
                  const tonlib_api::liteServer_messageAddressIntStd*> {
  if (msg == nullptr || msg->info_ == nullptr || msg->info_->get_id() != tonlib_api::liteServer_messageInfoInt::ID) {
    return std::make_tuple(nullptr, nullptr, nullptr);
  }
  const auto* msg_info = reinterpret_cast<const tonlib_api::liteServer_messageInfoInt*>(msg->info_.get());
  if (msg_info->src_->get_id() != tonlib_api::liteServer_messageAddressIntStd::ID ||
      msg_info->dest_->get_id() != tonlib_api::liteServer_messageAddressIntStd::ID) {
    return std::make_tuple(nullptr, nullptr, nullptr);
  }
  const auto* src = reinterpret_cast<const tonlib_api::liteServer_messageAddressIntStd*>(msg_info->src_.get());
  const auto* dest = reinterpret_cast<const tonlib_api::liteServer_messageAddressIntStd*>(msg_info->dest_.get());
  return std::make_tuple(msg_info, src, dest);
}

enum SpecialMessageId {
  StakeSendRequest = 0x4e73744bu,
  StakeSendResponseSuccess = 0xf374484cu,
  StakeSendResponseError = 0xee6f454c,
  StakeRecoverRequest = 0x47657424u,
  StakeRecoverResponseSuccess = 0xf96f7324u,
  StakeRecoverResponseError = 0xfffffffeu,
};

auto check_special_transaction(const tonlib_api_ptr<tonlib_api::liteServer_message>& msg_in,
                               const std::vector<tonlib_api_ptr<tonlib_api::liteServer_message>>& msgs_out)
    -> tonlib_api_ptr<tonlib_api::liteServer_TransactionAdditionalInfo> {
  const auto [msg_in_info, msg_in_src, msg_in_dst] = check_internal_message(msg_in);
  if (!msg_in_info || !msg_in_src || !msg_in_dst || msgs_out.size() != 1) {
    return nullptr;
  }

  const auto& msg_out = msgs_out[0];
  const auto [msg_out_info, msg_out_src, msg_out_dst] = check_internal_message(msg_out);
  if (!msg_out_info || !msg_out_src || !msg_out_dst) {
    return nullptr;
  }

  constexpr auto elector_addr_byte = 0x33;   // -1:3333...333
  constexpr auto emission_addr_byte = 0x00;  // -1:0000...000
  constexpr auto special_addr_byte = 0x35;   // -1:5555...555

  if (!check_special_addr(msg_in_dst, elector_addr_byte) || check_special_addr(msg_in_src, emission_addr_byte) ||
      check_special_addr(msg_in_dst, special_addr_byte)) {
    return nullptr;
  }

  auto msg_in_body_r = vm::std_boc_deserialize(msg_in->body_);
  if (msg_in_body_r.is_error()) {
    return nullptr;
  }
  auto msg_in_body = vm::load_cell_slice_ref(msg_in_body_r.move_as_ok());

  const auto msg_in_id = msg_in_body->prefetch_ulong(32);
  if (msg_in_id != SpecialMessageId::StakeSendRequest && msg_in_id != SpecialMessageId::StakeRecoverRequest) {
    return nullptr;
  }

  auto msg_out_body_r = vm::std_boc_deserialize(msg_out->body_);
  if (msg_out_body_r.is_error()) {
    return nullptr;
  }
  auto msg_out_body = vm::load_cell_slice_ref(msg_out_body_r.move_as_ok());

  const auto msg_out_id = msg_out_body->prefetch_ulong(32);
  if (msg_in_id == SpecialMessageId::StakeSendRequest && (msg_out_id == SpecialMessageId::StakeSendResponseSuccess ||
                                                          msg_out_id == SpecialMessageId::StakeSendResponseError)) {
    return parse_stake_send_transaction(std::move(msg_in_body), std::move(msg_out_body));
  } else if (msg_in_id == SpecialMessageId::StakeRecoverRequest &&
             (msg_out_id == SpecialMessageId::StakeRecoverResponseSuccess ||
              msg_out_id == SpecialMessageId::StakeRecoverResponseError)) {
    return parse_stake_recover_transaction(std::move(msg_in_body), std::move(msg_out_body));
  } else {
    return nullptr;
  }
}

auto parse_stake_send_transaction(td::Ref<vm::CellSlice>&& msg_in, td::Ref<vm::CellSlice>&& msg_out)
    -> tonlib_api_ptr<tonlib_api::liteServer_transactionAdditionalInfoStakeSend> {
  auto& msg_in_body = msg_in.write();
  auto& msg_out_body = msg_out.write();

  td::Bits256 validator_pubkey{}, adnl_addr{};
  td::uint32 stake_at{}, max_factor{};
  unsigned long long query_id{};
  const auto msg_in_valid = msg_in_body.advance(32) &&                      //
                            msg_in_body.fetch_ulong_bool(64, query_id) &&   //
                            msg_in_body.fetch_bits_to(validator_pubkey) &&  //
                            msg_in_body.fetch_uint_to(32, stake_at) &&      //
                            msg_in_body.fetch_uint_to(32, max_factor) &&    //
                            msg_in_body.fetch_bits_to(adnl_addr);
  if (!msg_in_valid) {
    return nullptr;
  }

  td::uint32 msg_out_id{};
  unsigned long long response_query_id{};
  if (!msg_out_body.fetch_uint_to(32, msg_out_id) || !msg_out_body.fetch_ulong_bool(64, response_query_id) ||
      query_id != response_query_id) {
    return nullptr;
  }

  td::int32 status;
  if (msg_out_id == SpecialMessageId::StakeSendResponseSuccess) {
    status = -1;
  } else if (msg_out_id != SpecialMessageId::StakeSendResponseError || msg_out_body.fetch_int_to(32, status)) {
    return nullptr;
  }

  return tonlib_api::make_object<tonlib_api::liteServer_transactionAdditionalInfoStakeSend>(
      status, validator_pubkey.as_slice().str(), stake_at, max_factor, adnl_addr.as_slice().str());
}

auto parse_stake_recover_transaction(td::Ref<vm::CellSlice>&& msg_in, td::Ref<vm::CellSlice>&& msg_out)
    -> tonlib_api_ptr<tonlib_api::liteServer_transactionAdditionalInfoStakeRecover> {
  auto& msg_in_body = msg_in.write();
  auto& msg_out_body = msg_out.write();

  unsigned long long query_id{};
  if (!msg_in_body.advance(32) || !msg_in_body.fetch_ulong_bool(64, query_id)) {
    return nullptr;
  }

  td::uint32 msg_out_id{};
  unsigned long long response_query_id{};
  if (!msg_out_body.fetch_uint_to(32, msg_out_id) || !msg_out_body.fetch_ulong_bool(64, response_query_id) ||
      query_id != response_query_id) {
    return nullptr;
  }
  const auto success = msg_out_id == SpecialMessageId::StakeRecoverResponseSuccess;

  return tonlib_api::make_object<tonlib_api::liteServer_transactionAdditionalInfoStakeRecover>(success);
}

auto parse_transaction(int workchain, const td::Bits256& account, td::Ref<vm::Cell>&& list)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_transaction>> {
  block::gen::Transaction::Record trans;
  if (!tlb::unpack_cell_inexact(list, trans)) {
    return td::Status::Error("failed to unpack transaction");
  }

  tonlib_api_ptr<tonlib_api::liteServer_message> in_msg = nullptr;
  if (auto in_msg_ref = trans.r1.in_msg->prefetch_ref(); in_msg_ref.not_null()) {
    TRY_RESULT_ASSIGN(in_msg, parse_message(std::move(in_msg_ref)))
  }

  std::vector<tonlib_api_ptr<tonlib_api::liteServer_message>> out_msgs;
  out_msgs.reserve(trans.outmsg_cnt);
  vm::Dictionary dict{trans.r1.out_msgs, 15};
  for (td::int32 i = 0; i < trans.outmsg_cnt; ++i) {
    auto out_msg = dict.lookup_ref(td::BitArray<15>{i});
    TRY_RESULT(msg, parse_message(std::move(out_msg)))
    out_msgs.emplace_back(std::move(msg));
  }

  block::CurrencyCollection total_fees_collection;
  if (!total_fees_collection.validate_unpack(trans.total_fees)) {
    return td::Status::Error("failed to unpack transaction fees");
  }
  TRY_RESULT(total_fees, to_tonlib_api(total_fees_collection.grams))

  block::gen::HASH_UPDATE::Record hash_update;
  if (!tlb::type_unpack_cell(std::move(trans.state_update), block::gen::t_HASH_UPDATE_Account, hash_update)) {
    return td::Status::Error("failed to unpack state update");
  }

  tonlib_api_ptr<tonlib_api::liteServer_TransactionDescr> transaction_descr = nullptr;

  auto td_cs = vm::load_cell_slice(trans.description);
  int tag = block::gen::t_TransactionDescr.get_tag(td_cs);
  switch (tag) {
    case block::gen::TransactionDescr::trans_ord: {
      block::gen::TransactionDescr::Record_trans_ord record;
      if (!tlb::unpack(td_cs, record)) {
        return td::Status::Error("failed to unpack ordinary transaction");
      }
      auto additional_info = check_special_transaction(in_msg, out_msgs);

      transaction_descr = tonlib_api::make_object<tonlib_api::liteServer_transactionDescrOrdinary>(
          record.credit_first, record.aborted, record.destroyed, std::move(additional_info));
      break;
    }
    case block::gen::TransactionDescr::trans_tick_tock: {
      block::gen::TransactionDescr::Record_trans_tick_tock record;
      if (!tlb::unpack(td_cs, record)) {
        return td::Status::Error("failed to unpack ticktock transaction");
      }
      transaction_descr = tonlib_api::make_object<tonlib_api::liteServer_transactionDescrTickTock>(
          record.is_tock, record.aborted, record.destroyed);
      break;
    }
    case block::gen::TransactionDescr::trans_split_prepare: {
      block::gen::TransactionDescr::Record_trans_split_prepare record;
      if (!tlb::unpack(td_cs, record)) {
        return td::Status::Error("failed to unpack split prepare transaction");
      }
      transaction_descr = tonlib_api::make_object<tonlib_api::liteServer_transactionDescrSplitPrepare>(
          record.aborted, record.destroyed);
      break;
    }
    case block::gen::TransactionDescr::trans_split_install: {
      block::gen::TransactionDescr::Record_trans_split_install record;
      if (!tlb::unpack(td_cs, record)) {
        return td::Status::Error("failed to unpack split install transaction");
      }
      transaction_descr =
          tonlib_api::make_object<tonlib_api::liteServer_transactionDescrSplitInstall>(record.installed);
      break;
    }
    case block::gen::TransactionDescr::trans_merge_prepare: {
      block::gen::TransactionDescr::Record_trans_merge_prepare record;
      if (!tlb::unpack(td_cs, record)) {
        return td::Status::Error("failed to unpack merge prepare transaction");
      }
      transaction_descr = tonlib_api::make_object<tonlib_api::liteServer_transactionDescrMergePrepare>(record.aborted);
      break;
    }
    case block::gen::TransactionDescr::trans_merge_install: {
      block::gen::TransactionDescr::Record_trans_merge_install record;
      if (!tlb::unpack(td_cs, record)) {
        return td::Status::Error("failed to unpack merge install transaction");
      }
      transaction_descr = tonlib_api::make_object<tonlib_api::liteServer_transactionDescrMergeInstall>(
          record.aborted, record.destroyed);
      break;
    }
    default:
      return td::Status::Error("failed to unpack transaction description");
  }

  return tonlib_api::make_object<tonlib_api::liteServer_transaction>(
      workchain, account.as_slice().str(), list->get_hash().as_slice().str(), static_cast<std::int64_t>(trans.lt),
      trans.prev_trans_hash.as_slice().str(), static_cast<std::int64_t>(trans.prev_trans_lt),
      static_cast<std::int32_t>(trans.now), trans.outmsg_cnt, static_cast<std::int32_t>(trans.orig_status),
      static_cast<std::int32_t>(trans.end_status), std::move(in_msg), std::move(out_msgs), total_fees,
      tonlib_api::make_object<tonlib_api::liteServer_transactionHashUpdate>(hash_update.old_hash.as_slice().str(),
                                                                            hash_update.new_hash.as_slice().str()),
      std::move(transaction_descr));
}

auto to_tonlib_api(const block::ValidatorDescr& validator) -> tonlib_api_ptr<tonlib_api::liteServer_validator> {
  return tonlib_api::make_object<tonlib_api::liteServer_validator>(
      validator.pubkey.as_slice().str(), validator.adnl_addr.as_slice().str(), validator.weight, validator.cum_weight);
}

auto to_tonlib_api(const block::ValidatorSet& vset) -> tonlib_api_ptr<tonlib_api::liteServer_validatorSet> {
  std::vector<tonlib_api_ptr<tonlib_api::liteServer_validator>> list;
  list.reserve(vset.list.size());
  for (const auto& item : vset.list) {
    list.emplace_back(to_tonlib_api(item));
  }
  return tonlib_api::make_object<tonlib_api::liteServer_validatorSet>(vset.utime_since, vset.utime_until, vset.total,
                                                                      vset.main, vset.total_weight, std::move(list));
}

auto parse_config_addr(td::Ref<vm::Cell>&& cell) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_accountId>> {
  if (cell.is_null() || vm::load_cell_slice(cell).size_ext() != 0x100) {
    return td::Status::Error("failed to parse address from config");
  }

  ton::StdSmcAddress addr;
  CHECK(vm::load_cell_slice(cell).prefetch_bits_to(addr));
  return tonlib_api::make_object<tonlib_api::liteServer_accountId>(ton::masterchainId, addr.as_slice().str());
}

auto parse_config_vset(td::Ref<vm::Cell>&& cell) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_validatorSet>> {
  TRY_RESULT(vset, block::ConfigInfo::unpack_validator_set(cell))
  return to_tonlib_api(*vset);
}

using ConfigParam = block::gen::ConfigParam;

auto parse_mint_price(td::Ref<vm::Cell>&& cell) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configMintPrice>> {
  ConfigParam::Record_cons6 mint_price;
  if (cell.is_null() || !tlb::type_unpack_cell(cell, ConfigParam{6}, mint_price)) {
    return td::Status::Error("failed to unpack mint price");
  }
  TRY_RESULT(mint_new_price, parse_grams(mint_price.mint_new_price))
  TRY_RESULT(mint_add_price, parse_grams(mint_price.mint_add_price))
  return tonlib_api::make_object<tonlib_api::liteServer_configMintPrice>(mint_new_price, mint_add_price);
}

auto parse_to_mint(td::Ref<vm::Cell>&& cell) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configToMint>> {
  block::gen::ExtraCurrencyCollection::Record cc;
  ConfigParam::Record_cons7 to_mint_value;
  if (cell.is_null() || !tlb::type_unpack_cell(cell, ConfigParam{7}, to_mint_value) ||
      !tlb::csr_unpack(to_mint_value.to_mint, cc)) {
    return td::Status::Error("failed to unpack to_mint");
  }

  std::vector<tonlib_api_ptr<tonlib_api::liteServer_currencyCollectionItem>> items;
  vm::Dictionary currencies{cc.dict, 32};
  block::gen::VarUInteger::Record value;
  for (const auto& item : currencies) {
    if (!tlb::csr_type_unpack(item.second, block::gen::t_VarUInteger_32, value)) {
      return td::Status::Error("failed to unpack currency value");
    }
    TRY_RESULT(currency_value, to_tonlib_api(value.value))
    items.emplace_back(
        tonlib_api::make_object<tonlib_api::liteServer_currencyCollectionItem>(item.first.get_int(32), currency_value));
  }

  return tonlib_api::make_object<tonlib_api::liteServer_configToMint>(std::move(items));
}

auto parse_global_version(td::Ref<vm::Cell>&& cell)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configGlobalVersion>> {
  block::gen::GlobalVersion::Record global_version;
  ConfigParam::Record_cons8 global_version_value;
  if (cell.is_null() || !tlb::type_unpack_cell(cell, ConfigParam{8}, global_version_value) ||
      !tlb::csr_unpack(global_version_value.x, global_version)) {
    return td::Status::Error("failed to unpack global version");
  }
  return tonlib_api::make_object<tonlib_api::liteServer_configGlobalVersion>(  //
      global_version.version, global_version.capabilities);
}

auto parse_integer_array(td::Ref<vm::Cell>&& cell) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configParams>> {
  if (cell.is_null()) {
    return td::Status::Error("failed to unpack config params");
  }

  std::vector<td::int32> result;
  vm::Dictionary mandatory_params{cell, 32};
  for (const auto& item : mandatory_params) {
    result.emplace_back(item.first.get_int(32));
  }
  return tonlib_api::make_object<tonlib_api::liteServer_configParams>(std::move(result));
}

auto parse_config_proposal_setup(td::Ref<vm::Cell>&& cell)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configProposalSetup>> {
  block::gen::ConfigProposalSetup::Record proposal_setup;
  if (cell.is_null() || !tlb::unpack_cell(std::move(cell), proposal_setup)) {
    return td::Status::Error("failed to unpack config proposal setup");
  }
  return tonlib_api::make_object<tonlib_api::liteServer_configProposalSetup>(
      proposal_setup.min_tot_rounds, proposal_setup.max_tot_rounds, proposal_setup.min_wins, proposal_setup.max_losses,
      proposal_setup.min_store_sec, proposal_setup.max_store_sec, proposal_setup.bit_price, proposal_setup.cell_price);
}

auto parse_config_voting_setup(td::Ref<vm::Cell>&& cell)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configVotingSetup>> {
  block::gen::ConfigVotingSetup::Record config_voting_setup;
  ConfigParam::Record_cons11 config_voting_setup_value;
  if (cell.is_null() || !tlb::type_unpack_cell(cell, ConfigParam{11}, config_voting_setup_value) ||
      !tlb::csr_unpack(config_voting_setup_value.x, config_voting_setup)) {
    return td::Status::Error("failed to unpack voting setup");
  }
  TRY_RESULT(normal_params, parse_config_proposal_setup(std::move(config_voting_setup.normal_params)))
  TRY_RESULT(critical_params, parse_config_proposal_setup(std::move(config_voting_setup.critical_params)))
  return tonlib_api::make_object<tonlib_api::liteServer_configVotingSetup>(  //
      std::move(normal_params), std::move(critical_params));
}

auto parse_workchain_descr(td::Ref<vm::CellSlice>&& cs)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configWorkchainInfo>> {
  block::gen::WorkchainDescr::Record info;
  if (cs.is_null() || !tlb::csr_unpack(cs, info)) {
    return td::Status::Error("failed to unpack workchain description");
  }

  block::gen::WorkchainFormat::Record_wfmt_basic workchain_format;
  if (!tlb::csr_type_unpack(info.format, block::gen::WorkchainFormat{block::gen::WorkchainFormat::wfmt_basic},
                            workchain_format)) {
    return td::Status::Error("failed to unpack workchain format");
  }

  auto format = tonlib_api::make_object<tonlib_api::liteServer_configWorkchainFormat>(  //
      workchain_format.vm_version, workchain_format.vm_mode);

  return tonlib_api::make_object<tonlib_api::liteServer_configWorkchainInfo>(
      info.enabled_since, info.actual_min_split, info.min_split, info.max_split, info.basic, info.active,
      info.accept_msgs, info.flags, info.zerostate_root_hash.as_slice().str(),
      info.zerostate_file_hash.as_slice().str(), info.version, std::move(format));
}

auto parse_config_workchains(td::Ref<vm::Cell>&& cell)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configWorkchains>> {
  ConfigParam::Record_cons12 workchains_value;
  if (cell.is_null() || !tlb::type_unpack_cell(cell, ConfigParam{12}, workchains_value)) {
    return td::Status::Error("failed to unpack config workchains");
  }

  std::vector<tonlib_api_ptr<tonlib_api::liteServer_configWorkchainInfo>> result{};
  vm::Dictionary workchains{workchains_value.workchains, 32};
  for (const auto& item : workchains) {
    auto value = item.second;
    TRY_RESULT(workchain_info, parse_workchain_descr(std::move(value)))
    result.emplace_back(std::move(workchain_info));
  }
  return tonlib_api::make_object<tonlib_api::liteServer_configWorkchains>(std::move(result));
}

template <typename T>
auto parse_config_param(block::Config& config, int param, td::Result<tonlib_api_ptr<T>> (*f)(td::Ref<vm::Cell>&&))
    -> td::Result<tonlib_api_ptr<T>> {
  tonlib_api_ptr<T> result{};
  if (auto param_ref = config.get_config_param(param); param_ref.not_null()) {
    TRY_RESULT_ASSIGN(result, (*f)(std::move(param_ref)))
  }
  return result;
}

auto parse_config(const ton::BlockIdExt& blkid, td::Slice state_proof, td::Slice config_proof)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configInfo>> {
  enum {
    CONFIG_ADDR = 0,
    ELECTOR_ADDR = 1,
    MINTER_ADDR = 2,
    FEE_COLLECTOR_ADDR = 3,
    DNS_ROOT_ADDR = 4,

    MINT_PRICE = 6,
    TO_MINT = 7,
    GLOBAL_VERSION = 8,
    MANDATORY_PARAMS = 9,
    CRITICAL_PARAMS = 10,
    CONFIG_VOTING_SETUP = 11,
    WORKCHAINS = 12,
    COMPLAINT_PRICING = 13,
    BLOCK_CREATE_FEES = 14,
    VALIDATORS_TIMINGS = 15,
    VALIDATORS_QUANTITY_LIMITS = 16,
    VALIDATORS_STAKE_LIMITS = 17,
    STORAGE_PRICES = 18,

    MASTERCHAIN_GAS_PRICES = 20,
    GAS_PRICES = 21,
    MASTERCHAIN_BLOCK_LIMITS = 22,
    BLOCK_LIMITS = 23,
    MASTERCHAIN_MSG_FORWARD_PRICES = 24,
    MSG_FORWARD_PRICES = 25,

    CATCHAIN_CONFIG = 28,
    CONSENSUS_CONFIG = 29,

    FUNDAMENTAL_SMC_ADDR = 31,

    PREV_VSET = 32,
    PREV_TEMP_VSET = 33,
    CURR_VSET = 34,
    CURR_TEMP_VSET = 35,
    NEXT_VSET = 36,
    NEXT_TEMP_VSET = 37,

    VALIDATOR_SIGNED_TEMP_KEY = 39,
  };

  TRY_RESULT(state_proof_ref, vm::std_boc_deserialize(state_proof))
  TRY_RESULT(config_proof_ref, vm::std_boc_deserialize(config_proof))
  TRY_RESULT(state, block::check_extract_state_proof(blkid, state_proof, config_proof))

  TRY_RESULT(config, block::ConfigInfo::extract_from_state(state, block::ConfigInfo::needShardHashes))

  // Accounts
  TRY_RESULT(config_addr, parse_config_param(*config, CONFIG_ADDR, parse_config_addr))
  TRY_RESULT(elector_addr, parse_config_param(*config, ELECTOR_ADDR, parse_config_addr))
  TRY_RESULT(minter_addr, parse_config_param(*config, MINTER_ADDR, parse_config_addr))
  TRY_RESULT(fee_collector_addr, parse_config_param(*config, FEE_COLLECTOR_ADDR, parse_config_addr))
  TRY_RESULT(dns_root_addr, parse_config_param(*config, DNS_ROOT_ADDR, parse_config_addr))

  // General
  TRY_RESULT(mint_price, parse_config_param(*config, MINT_PRICE, parse_mint_price))
  TRY_RESULT(to_mint, parse_config_param(*config, TO_MINT, parse_to_mint))
  TRY_RESULT(global_version, parse_config_param(*config, GLOBAL_VERSION, parse_global_version))
  TRY_RESULT(mandatory_params, parse_config_param(*config, MANDATORY_PARAMS, parse_integer_array))
  TRY_RESULT(critical_params, parse_config_param(*config, CRITICAL_PARAMS, parse_integer_array))
  TRY_RESULT(config_voting_setup, parse_config_param(*config, CONFIG_VOTING_SETUP, parse_config_voting_setup))
  TRY_RESULT(workchains, parse_config_param(*config, WORKCHAINS, parse_config_workchains))

  // Validators
  TRY_RESULT(prev_vset, parse_config_param(*config, PREV_VSET, parse_config_vset))
  TRY_RESULT(prev_temp_vset, parse_config_param(*config, PREV_TEMP_VSET, parse_config_vset))
  TRY_RESULT(curr_vset, parse_config_param(*config, CURR_VSET, parse_config_vset))
  TRY_RESULT(curr_temp_vset, parse_config_param(*config, CURR_TEMP_VSET, parse_config_vset))
  TRY_RESULT(next_vset, parse_config_param(*config, NEXT_VSET, parse_config_vset))
  TRY_RESULT(next_temp_vset, parse_config_param(*config, NEXT_TEMP_VSET, parse_config_vset))

  return tonlib_api::make_object<tonlib_api::liteServer_configInfo>(
      to_tonlib_api(blkid), std::move(config_addr), std::move(elector_addr), std::move(minter_addr),
      std::move(fee_collector_addr), std::move(dns_root_addr), std::move(mint_price), std::move(to_mint),
      std::move(global_version), std::move(mandatory_params), std::move(critical_params),
      std::move(config_voting_setup), std::move(workchains), std::move(prev_vset), std::move(prev_temp_vset),
      std::move(curr_vset), std::move(curr_temp_vset), std::move(next_vset), std::move(next_temp_vset));
}

}  // namespace tonlib
