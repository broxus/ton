#include "GetBlock.h"

#include "tonlib/LastBlock.h"
#include "tonlib/LastConfig.h"

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
    : block_id_(std::move(block_id)), parent_(std::move(parent)), promise_(std::move(promise)) {
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

  TRY_RESULT(block_header_root, vm::std_boc_deserialize(data_))
  auto virt_root = vm::MerkleProof::virtualize(block_header_root, 1);
  if (virt_root.is_null()) {
    return td::Status::Error("invalid merkle proof");
  }

  ton::RootHash vhash{virt_root->get_hash().bits()};
  std::vector<ton::BlockIdExt> prev{};
  ton::BlockIdExt masterchain_blk_id{};
  bool after_split = false;
  if (auto res = block::unpack_block_prev_blk_ext(virt_root, block_id, prev, masterchain_blk_id, after_split);
      res.is_error()) {
    LOG(ERROR) << "failed to unpack block header " << block_id.to_str() << ": " << res;
    return td::Status::Error("failed to unpack block header");
  }

  block::gen::Block::Record blk;
  if (!tlb::unpack_cell(virt_root, blk)) {
    return td::Status::Error("failed to unpack block record");
  }

  block::gen::BlockInfo::Record info;
  if (!tlb::unpack_cell(blk.info, info)) {
    return td::Status::Error("failed to unpack block info");
  }

  std::vector<tonlib_api_ptr<tonlib_api::ton_blockIdExt>> previous_blocks;
  previous_blocks.reserve(prev.size());
  for (const auto& id : prev) {
    previous_blocks.emplace_back(to_tonlib_api(id));
  }

  std::vector<tonlib_api_ptr<tonlib_api::ton_blockId>> next_blocks;
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

  auto block_info = tonlib_api::make_object<tonlib_api::liteServer_blockInfo>(
      info.version, info.not_master, info.after_merge, info.before_split, info.after_split, info.want_split,
      info.want_merge, info.key_block, info.vert_seqno_incr, info.flags, info.seq_no, info.vert_seq_no, info.gen_utime,
      info.start_lt, info.end_lt, info.gen_validator_list_hash_short, info.gen_catchain_seqno, info.min_ref_mc_seqno,
      info.prev_key_block_seqno);

  tonlib_api_ptr<tonlib_api::liteServer_allShardsInfo> all_shards_info = nullptr;
  if (!shard_data_.empty()) {
    TRY_RESULT(shard_data, vm::std_boc_deserialize(shard_data_))

    block::ShardConfig shard_config;
    if (!shard_config.unpack(vm::load_cell_slice_ref(shard_data))) {
      return td::Status::Error("failed to unpack shard config");
    }
    auto ids = shard_config.get_shard_hash_ids(true);

    auto min_shard_gen_utime = ids.empty() ? 0u : std::numeric_limits<ton::UnixTime>::max();
    auto max_shard_gen_utime = ids.empty() ? 0u : std::numeric_limits<ton::UnixTime>::min();
    std::vector<tonlib_api_ptr<tonlib_api::liteServer_shardHash>> shards;
    shards.reserve(ids.size());

    for (auto id : ids) {
      auto ref = shard_config.get_shard_hash(ton::ShardIdFull(id));
      if (ref.is_null()) {
        continue;
      }

      min_shard_gen_utime = std::min(min_shard_gen_utime, ref->gen_utime_);
      max_shard_gen_utime = std::max(max_shard_gen_utime, ref->gen_utime_);

      TRY_RESULT(fees_collected, to_tonlib_api(ref->fees_collected_.grams))
      TRY_RESULT(funds_collected, to_tonlib_api(ref->funds_created_.grams))

      shards.emplace_back(tonlib_api::make_object<tonlib_api::liteServer_shardHash>(
          ref->blk_.id.workchain, ref->blk_.id.shard, to_tonlib_api(ref->blk_), ref->start_lt_, ref->end_lt_,
          ref->before_split_, ref->before_merge_, ref->want_split_, ref->want_merge_, ref->next_catchain_seqno_,
          ref->next_validator_shard_, ref->min_ref_mc_seqno_, ref->gen_utime_, fees_collected, funds_collected));
    }

    all_shards_info = tonlib_api::make_object<tonlib_api::liteServer_allShardsInfo>(
        min_shard_gen_utime, max_shard_gen_utime, std::move(shards));
  }

  return tonlib_api::make_object<tonlib_api::liteServer_block>(
      to_tonlib_api(block_id), to_tonlib_api(masterchain_blk_id), std::move(block_info), std::move(previous_blocks),
      std::move(next_blocks), std::move(all_shards_info), std::move(transactions_));
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
  auto block_header_handler = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockHeader>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &GetBlock::got_block_header, R.move_as_ok(), QueryMode::Get);
        }
      });
  client_.send_query(lite_api::liteServer_getBlockHeader(ton::create_tl_lite_block_id(block_id), 0),
                     std::move(block_header_handler));
  pending_queries_ = 1;

  proceed_with_block_id(block_id);
}

void GetBlock::start_up_with_lookup() {
  auto block_header_handler = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockHeader>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &GetBlock::got_block_header, R.move_as_ok(), QueryMode::Lookup);
        }
      });
  client_.send_query(
      lite_api::liteServer_lookupBlock(mode_, ton::create_tl_lite_block_id_simple(block_id_simple_), lt_, utime_),
      std::move(block_header_handler));
  pending_queries_ = 1;
}

void GetBlock::proceed_with_block_id(const ton::BlockIdExt& block_id) {
  if (block_id.is_masterchain()) {
    auto all_shards_info_handler = td::PromiseCreator::lambda(
        [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_allShardsInfo>> R) {
          if (R.is_error()) {
            td::actor::send_closure(SelfId, &GetBlock::failed_to_get_shard_info, R.move_as_error());
          } else {
            td::actor::send_closure(SelfId, &GetBlock::got_shard_info, R.move_as_ok());
          }
        });
    client_.send_query(lite_api::liteServer_getAllShardsInfo(ton::create_tl_lite_block_id(block_id)),
                       std::move(all_shards_info_handler));
    pending_queries_++;
  }

  auto block_transactions_handler = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockTransactions>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &GetBlock::got_transactions, R.move_as_ok());
        }
      });
  client_.send_query(lite_api::liteServer_listBlockTransactions(ton::create_tl_lite_block_id(block_id), 7, 1024,
                                                                nullptr, false, false),
                     std::move(block_transactions_handler));
  pending_queries_++;
}

void GetBlock::got_block_header(lite_api_ptr<lite_api::liteServer_blockHeader>&& result, QueryMode query_mode) {
  if (query_mode == QueryMode::Lookup) {
    const auto block_id = from_lite_api(*result->id_);
    block_id_ = block_id;
    proceed_with_block_id(block_id);
  }

  data_ = std::move(result->header_proof_);
  check_finished();
}

void GetBlock::got_shard_info(lite_api_ptr<lite_api::liteServer_allShardsInfo>&& result) {
  shard_data_ = std::move(result->data_);
  check_finished();
}

void GetBlock::got_transactions(lite_api_ptr<lite_api::liteServer_blockTransactions>&& result) {
  if (!block_id_.has_value()) {
    check(td::Status::Error("block not found"));
    return;
  }
  const auto& block_id = *block_id_;

  trans_req_count_ = result->req_count_;

  for (auto&& transaction_id : result->ids_) {
    transactions_.emplace_back(to_tonlib_api(*transaction_id));
  }

  if (result->incomplete_ && transactions_.size() > 0) {
    const auto& last = transactions_.back();
    auto last_account = to_bits256(last->account_, "last.account");

    if (last_account.is_ok()) {
      auto block_transactions_handler = td::PromiseCreator::lambda(
          [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockTransactions>> R) {
            if (R.is_error()) {
              td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
            } else {
              td::actor::send_closure(SelfId, &GetBlock::got_transactions, R.move_as_ok());
            }
          });
      client_.send_query(
          lite_api::liteServer_listBlockTransactions(
              ton::create_tl_lite_block_id(block_id), 7 + 128, 1024,
              lite_api::make_object<ton::lite_api::liteServer_transactionId3>(last_account.move_as_ok(), last->lt_),
              false, false),
          std::move(block_transactions_handler));
    } else {
      check(last_account.move_as_error());
    }
  } else {
    check_finished();
  }
}

void GetBlock::failed_to_get_shard_info(td::Status error) {
  LOG(WARNING) << error;
  if (!--pending_queries_) {
    finish_query();
  }
}

}  // namespace tonlib
