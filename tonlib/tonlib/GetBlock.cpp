#include "GetBlock.h"

#include "tonlib/LastBlock.h"
#include "tonlib/LastConfig.h"

#include "ton/lite-tl.hpp"

namespace tonlib {

GetBlock::GetBlock(ExtClientRef ext_client_ref, ton::BlockIdExt block_id, td::actor::ActorShared<> parent,
                   td::Promise<tonlib_api_ptr<tonlib_api::liteServer_block>>&& promise)
    : block_id_(std::move(block_id)), parent_(std::move(parent)), promise_(std::move(promise)) {
  client_.set_client(ext_client_ref);
}

void GetBlock::finish_query() {
  LOG(WARNING) << "Got block data: " << data_.has_value();
  LOG(WARNING) << "Got shard data: " << shard_data_.has_value();
  promise_.set_value(nullptr);
  stop();
}

void GetBlock::start_up_query() {
  client_.send_query(lite_api::liteServer_getBlockHeader(ton::create_tl_lite_block_id(block_id_), 0),
                     [this](lite_api_ptr<lite_api::liteServer_blockHeader>&& block_header) {
                       got_block_header(std::move(block_header));
                     });
  pending_queries_ = 1;

  if (block_id_.is_masterchain()) {
    client_.send_query(lite_api::liteServer_getAllShardsInfo(ton::create_tl_lite_block_id(block_id_)),
                       [this](lite_api_ptr<lite_api::liteServer_allShardsInfo>&& all_shards_info) {
                         got_shard_info(std::move(all_shards_info));
                       });
    pending_queries_++;
  }

  client_.send_query(lite_api::liteServer_listBlockTransactions(ton::create_tl_lite_block_id(block_id_), 7, 1024,
                                                                nullptr, false, false),
                     [this](lite_api_ptr<lite_api::liteServer_blockTransactions>&& block_transactions) {
                       got_transactions(std::move(block_transactions));
                     });
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
      client_.send_query(
          lite_api::liteServer_listBlockTransactions(
              ton::create_tl_lite_block_id(block_id_), 7 + 128, 1024,
              lite_api::make_object<ton::lite_api::liteServer_transactionId3>(last_account.move_as_ok(), last->lt_),
              false, false),
          [this](lite_api_ptr<lite_api::liteServer_blockTransactions>&& result) {
            got_transactions(std::move(result));
          });
      return;
    } else {
      block_transactions_receive_error_ = last_account.move_as_error();
    }
  }

  if (!--pending_queries_) {
    finish_query();
  }
}

}  // namespace tonlib
