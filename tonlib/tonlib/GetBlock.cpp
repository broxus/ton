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

auto GetBlock::parse_result() -> td::Result<ResultType> {
  TRY_RESULT(block_header_root, vm::std_boc_deserialize(data_))
  auto virt_root = vm::MerkleProof::virtualize(block_header_root, 1);
  if (virt_root.is_null()) {
    return td::Status::Error("invalid merkle proof");
  }

  ton::RootHash vhash{virt_root->get_hash().bits()};
  std::vector<ton::BlockIdExt> prev{};
  ton::BlockIdExt masterchain_blk_id{};
  bool after_split = false;
  if (auto res = block::unpack_block_prev_blk_ext(virt_root, block_id_, prev, masterchain_blk_id, after_split);
      res.is_error()) {
    LOG(ERROR) << "failed to unpack block header " << block_id_.to_str() << ": " << res;
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
        ton::BlockId{block_id_.id.workchain, ton::shard_child(block_id_.id.shard, true), block_id_.id.seqno}));
    next_blocks.emplace_back(to_tonlib_api(
        ton::BlockId{block_id_.id.workchain, ton::shard_child(block_id_.id.shard, false), block_id_.id.seqno}));
  } else {
    next_blocks.emplace_back(
        to_tonlib_api(ton::BlockId{block_id_.id.workchain, block_id_.id.shard, block_id_.id.seqno}));
  }

  auto block_info = tonlib_api::make_object<tonlib_api::liteServer_blockInfo>(
      info.version, info.not_master, info.after_merge, info.before_split, info.after_split, info.want_split,
      info.want_merge, info.key_block, info.vert_seqno_incr, info.flags, info.seq_no, info.vert_seq_no, info.gen_utime,
      info.start_lt, info.end_lt, info.gen_validator_list_hash_short, info.gen_catchain_seqno, info.min_ref_mc_seqno,
      info.prev_key_block_seqno);
  return tonlib_api::make_object<tonlib_api::liteServer_block>(to_tonlib_api(block_id_),
                                                               to_tonlib_api(masterchain_blk_id), std::move(block_info),
                                                               std::move(previous_blocks), std::move(next_blocks));
}

void GetBlock::finish_query() {
  promise_.set_result(parse_result());
  stop();
}

void GetBlock::start_up() {
  auto block_header_handler = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_blockHeader>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &GetBlock::got_block_header, R.move_as_ok());
        }
      });
  client_.send_query(lite_api::liteServer_getBlockHeader(ton::create_tl_lite_block_id(block_id_), 0),
                     std::move(block_header_handler));
  pending_queries_ = 1;

  if (block_id_.is_masterchain()) {
    auto all_shards_info_handler = td::PromiseCreator::lambda(
        [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_allShardsInfo>> R) {
          if (R.is_error()) {
            td::actor::send_closure(SelfId, &GetBlock::check, R.move_as_error());
          } else {
            td::actor::send_closure(SelfId, &GetBlock::got_shard_info, R.move_as_ok());
          }
        });
    client_.send_query(lite_api::liteServer_getAllShardsInfo(ton::create_tl_lite_block_id(block_id_)),
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
  client_.send_query(lite_api::liteServer_listBlockTransactions(ton::create_tl_lite_block_id(block_id_), 7, 1024,
                                                                nullptr, false, false),
                     std::move(block_transactions_handler));
  pending_queries_++;
}

void GetBlock::got_block_header(lite_api_ptr<lite_api::liteServer_blockHeader>&& result) {
  data_ = std::move(result->header_proof_);
  if (!--pending_queries_) {
    finish_query();
  }
}

void GetBlock::got_shard_info(lite_api_ptr<lite_api::liteServer_allShardsInfo>&& result) {
  shard_data_ = std::move(result->data_);
  if (!--pending_queries_) {
    finish_query();
  }
}

void GetBlock::got_transactions(lite_api_ptr<lite_api::liteServer_blockTransactions>&& result) {
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
              ton::create_tl_lite_block_id(block_id_), 7 + 128, 1024,
              lite_api::make_object<ton::lite_api::liteServer_transactionId3>(last_account.move_as_ok(), last->lt_),
              false, false),
          std::move(block_transactions_handler));
    } else {
      check(last_account.move_as_error());
    }
  } else if (!--pending_queries_) {
    finish_query();
  }
}

}  // namespace tonlib
