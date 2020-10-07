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

auto parse_message(td::Ref<vm::Cell>&& msg) -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_message>> {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg, block::gen::t_Message_Any, message)) {
    return td::Status::Error("failed to unpack message");
  }

  TRY_RESULT(info, parse_message_info(message.info))

  bool has_init = message.init->prefetch_ulong(1);
  bool has_body = message.body->prefetch_ulong(1);

  return tonlib_api::make_object<tonlib_api::liteServer_message>(msg->get_hash().as_slice().str(), std::move(info),
                                                                 has_init, has_body);
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
      transaction_descr = tonlib_api::make_object<tonlib_api::liteServer_transactionDescrOrdinary>(
          record.credit_first, record.aborted, record.destroyed);
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

auto parse_config(const ton::BlockIdExt& blkid, td::Slice state_proof, td::Slice config_proof)
    -> td::Result<tonlib_api_ptr<tonlib_api::liteServer_configInfo>> {
  TRY_RESULT(state_proof_ref, vm::std_boc_deserialize(state_proof))
  TRY_RESULT(config_proof_ref, vm::std_boc_deserialize(config_proof))
  TRY_RESULT(state, block::check_extract_state_proof(blkid, state_proof, config_proof))

  TRY_RESULT(config, block::ConfigInfo::extract_from_state(state, block::ConfigInfo::needShardHashes))

  enum { PREV_VSET = 32, CURR_VSET = 34, NEXT_VSET = 36 };

  tonlib_api_ptr<tonlib_api::liteServer_validatorSet> prev_vset{};
  tonlib_api_ptr<tonlib_api::liteServer_validatorSet> curr_vset{};
  tonlib_api_ptr<tonlib_api::liteServer_validatorSet> next_vset{};

  if (auto param = config->get_config_param(PREV_VSET); param.not_null()) {
    TRY_RESULT(vset, block::ConfigInfo::unpack_validator_set(param))
    prev_vset = to_tonlib_api(*vset);
  }

  if (auto param = config->get_config_param(CURR_VSET); param.not_null()) {
    TRY_RESULT(vset, block::ConfigInfo::unpack_validator_set(param))
    curr_vset = to_tonlib_api(*vset);
  }

  if (auto param = config->get_config_param(NEXT_VSET); param.not_null()) {
    TRY_RESULT(vset, block::ConfigInfo::unpack_validator_set(param))
    next_vset = to_tonlib_api(*vset);
  }

  return tonlib_api::make_object<tonlib_api::liteServer_configInfo>(to_tonlib_api(blkid), std::move(prev_vset),
                                                                    std::move(curr_vset), std::move(next_vset));
}

}  // namespace tonlib
