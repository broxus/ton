#include "GetBlock.h"

#include "tonlib/LastBlock.h"
#include "tonlib/LastConfig.h"
#include "tonlib/LiteServerUtils.h"

#include "ton/lite-tl.hpp"

#include "block/block.h"
#include "block/block-parse.h"
#include "block/block-auto.h"
#include "vm/boc.h"
#include "vm/cellops.h"
#include "vm/cells/MerkleProof.h"

namespace tonlib {

GetBlock::GetBlock(ExtClientRef ext_client_ref, ton::BlockIdExt block_id, td::actor::ActorShared<> parent,
                   td::Promise<tonlib_api_ptr<tonlib_api::liteServer_block>>&& promise)
    : block_id_(std::move(block_id)), mode_{0x1000u}, parent_(std::move(parent)), promise_(std::move(promise)) {
  client_.set_client(ext_client_ref);
}

GetBlock::GetBlock(ExtClientRef ext_client_ref, ton::BlockId block_id, int mode, td::int64 lt, td::int32 utime,
                   td::actor::ActorShared<> parent, td::Promise<ResultType>&& promise)
    : mode_{mode}
    , block_id_simple_{std::move(block_id)}
    , lt_{lt}
    , utime_{utime}
    , parent_{std::move(parent)}
    , promise_{std::move(promise)} {
  client_.set_client(ext_client_ref);
}

auto GetBlock::parse_result() -> td::Result<ResultType> {
  if (!block_id_.has_value()) {
    return td::Status::Error("block not found");
  }
  const auto& block_id = *block_id_;

  TRY_RESULT(block_root, vm::std_boc_deserialize(block_data_))

  std::vector<ton::BlockIdExt> prev{};
  ton::BlockIdExt masterchain_blk_id{};
  bool after_split = false;
  if (auto res = block::unpack_block_prev_blk_ext(block_root, block_id, prev, masterchain_blk_id, after_split);
      res.is_error()) {
    LOG(ERROR) << "failed to unpack block header " << block_id.to_str() << ": " << res;
    return td::Status::Error("failed to unpack block header");
  }

  std::vector<tonlib_api_ptr<tonlib_api::ton_blockIdExt>> previous_blocks;
  std::vector<tonlib_api_ptr<tonlib_api::ton_blockId>> next_blocks;
  std::vector<tonlib_api_ptr<tonlib_api::liteServer_transaction>> transactions;
  tonlib_api_ptr<tonlib_api::liteServer_blockInfo> block_info;

  previous_blocks.reserve(prev.size());
  for (const auto& id : prev) {
    previous_blocks.emplace_back(to_tonlib_api(id));
  }

  try {
    block::gen::Block::Record blk;
    block::gen::BlockExtra::Record extra;
    if (!(tlb::unpack_cell(block_root, blk) && tlb::unpack_cell(blk.extra, extra))) {
      return td::Status::Error(PSLICE() << "cannot find account transaction data in block " << block_id.to_str());
    }

    std::vector<tonlib_api_ptr<tonlib_api::liteServer_inMsgDescrItem>> in_msg_descr;    // TODO
    std::vector<tonlib_api_ptr<tonlib_api::liteServer_outMsgDescrItem>> out_msg_descr;  // TODO
    std::vector<tonlib_api_ptr<tonlib_api::liteServer_blockExtraAccount>> extra_accounts;

    vm::AugmentedDictionary acc_dict{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                     block::tlb::aug_ShardAccountBlocks};

    auto allow_same = true;
    td::Bits256 dict_key{};
    while (true) {
      td::Ref<vm::CellSlice> value;
      try {
        value = acc_dict.extract_value(
            acc_dict.vm::DictionaryFixed::lookup_nearest_key(dict_key.bits(), 256, true, allow_same));
      } catch (const vm::VmError& err) {
        return td::Status::Error(PSLICE() << "error while traversing account block dictionary: " << err.get_msg());
      }
      if (value.is_null()) {
        break;
      }

      allow_same = false;

      block::gen::AccountBlock::Record acc_blk;
      if (!(tlb::csr_unpack(std::move(value), acc_blk) && acc_blk.account_addr == dict_key)) {
        return td::Status::Error(PSLICE() << "invalid AccountBlock for account " << dict_key.to_hex());
      }

      vm::AugmentedDictionary trans_dict{vm::DictNonEmpty(), std::move(acc_blk.transactions), 64,
                                         block::tlb::aug_AccountTransactions};
      auto transaction_count = 0;

      td::BitArray<64> cur_trans{};
      while (true) {
        td::Ref<vm::Cell> tvalue;
        try {
          tvalue = trans_dict.extract_value_ref(
              trans_dict.vm::DictionaryFixed::lookup_nearest_key(cur_trans.bits(), 64, true));
        } catch (const vm::VmError& err) {
          return td::Status::Error(PSLICE() << "error while traversing transaction dictionary of an AccountBlock: "
                                            << err.get_msg());
        }
        if (tvalue.is_null()) {
          break;
        }

        TRY_RESULT(transaction, parse_transaction(block_id.id.workchain, dict_key, std::move(tvalue)))
        transactions.emplace_back(std::move(transaction));
        ++transaction_count;
      }

      block::gen::HASH_UPDATE::Record state_update_value;
      if (!tlb::type_unpack_cell(acc_blk.state_update, block::gen::t_HASH_UPDATE_Account, state_update_value)) {
        return td::Status::Error("failed to unpack account state update");
      }
      auto state_update = tonlib_api::make_object<tonlib_api::liteServer_hashUpdate>(  //
          state_update_value.old_hash.as_slice().str(), state_update_value.new_hash.as_slice().str());

      extra_accounts.emplace_back(tonlib_api::make_object<tonlib_api::liteServer_blockExtraAccount>(
          dict_key.as_slice().str(), transaction_count, std::move(state_update)));
    }

    block::gen::BlockInfo::Record info;
    if (!tlb::unpack_cell(blk.info, info)) {
      return td::Status::Error("failed to unpack block info");
    }

    next_blocks.reserve(info.before_split ? 2 : 1);
    if (info.before_split) {
      next_blocks.emplace_back(to_tonlib_api(
          ton::BlockId{block_id.id.workchain, ton::shard_child(block_id.id.shard, true), block_id.id.seqno + 1}));
      next_blocks.emplace_back(to_tonlib_api(
          ton::BlockId{block_id.id.workchain, ton::shard_child(block_id.id.shard, false), block_id.id.seqno + 1}));
    } else {
      next_blocks.emplace_back(
          to_tonlib_api(ton::BlockId{block_id.id.workchain, block_id.id.shard, block_id.id.seqno + 1}));
    }

    tonlib_api_ptr<tonlib_api::liteServer_globalVersion> gen_software;
    if (info.flags & 0x1u) {
      TRY_RESULT_ASSIGN(gen_software,
                        parse_global_version(vm::CellBuilder{}.append_cellslice(info.gen_software).finalize()))
    }

    tonlib_api_ptr<tonlib_api::liteServer_extBlockRef> master_ref;
    if (info.not_master && info.master_ref.not_null()) {
      TRY_RESULT_ASSIGN(master_ref, parse_ext_block_ref(info.master_ref))
    }

    block_info = tonlib_api::make_object<tonlib_api::liteServer_blockInfo>(
        info.version, info.not_master, info.after_merge, info.before_split, info.after_split, info.want_split,
        info.want_merge, info.key_block, info.vert_seqno_incr, info.flags, info.seq_no, info.vert_seq_no,
        info.gen_utime, info.start_lt, info.end_lt, info.gen_validator_list_hash_short, info.gen_catchain_seqno,
        info.min_ref_mc_seqno, info.prev_key_block_seqno, std::move(gen_software), std::move(master_ref));

    tonlib_api_ptr<tonlib_api::liteServer_mcBlockExtra> mc_block_extra;
    td::Ref<vm::Cell> mc_block_extra_cell;
    if (extra.custom->prefetch_maybe_ref(mc_block_extra_cell) && mc_block_extra_cell.not_null()) {
      TRY_RESULT_ASSIGN(mc_block_extra, parse_mc_block_extra(mc_block_extra_cell))
    }

    TRY_RESULT(value_flow, parse_value_flow(blk.value_flow))

    auto block_extra = tonlib_api::make_object<tonlib_api::liteServer_blockExtra>(
        std::move(in_msg_descr), std::move(out_msg_descr), std::move(extra_accounts), extra.rand_seed.as_slice().str(),
        extra.created_by.as_slice().str(), std::move(mc_block_extra));

    return tonlib_api::make_object<tonlib_api::liteServer_block>(
        to_tonlib_api(block_id), to_tonlib_api(masterchain_blk_id), blk.global_id, std::move(block_info),
        std::move(value_flow), std::move(block_extra), std::move(previous_blocks), std::move(next_blocks),
        std::move(transactions));
  } catch (const vm::VmError& err) {
    return td::Status::Error(PSLICE() << "error while parsing AccountBlocks of block " << block_id.to_str() << " : "
                                      << err.get_msg());
  }
}

void GetBlock::finish_query() {
  promise_.set_result(parse_result());
  stop();
}

void GetBlock::start_up() {
  if (block_id_.has_value()) {
    start_up_with_block_id(*block_id_);
  } else {
    start_up_with_lookup();
  }
}

void GetBlock::start_up_with_block_id(const ton::BlockIdExt& block_id) {
  pending_queries_ = 0;
  proceed_with_block_id(block_id);
}

void GetBlock::start_up_with_lookup() {
  auto block_header_handler = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockHeader>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &GetBlock::got_block_header, R.move_as_ok());
        }
      });
  client_.send_query(lite_api::liteServer_lookupBlock(
                         mode_ & 0b0111u, ton::create_tl_lite_block_id_simple(block_id_simple_), lt_, utime_),
                     std::move(block_header_handler));
  pending_queries_ = 1;
}

void GetBlock::proceed_with_block_id(const ton::BlockIdExt& block_id) {
  auto block_data_handler =
      td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockData>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &GetBlock::got_block_data, R.move_as_ok());
        }
      });
  client_.send_query(lite_api::liteServer_getBlock(ton::create_tl_lite_block_id(block_id)),
                     std::move(block_data_handler));
  pending_queries_++;
}

void GetBlock::got_block_header(lite_api_ptr<lite_api::liteServer_blockHeader>&& result) {
  const auto block_id = from_lite_api(*result->id_);
  block_id_ = block_id;
  proceed_with_block_id(block_id);
  check_finished();
}

void GetBlock::got_block_data(lite_api_ptr<lite_api::liteServer_blockData>&& result) {
  block_data_ = std::move(result->data_);
  check_finished();
}

}  // namespace tonlib
