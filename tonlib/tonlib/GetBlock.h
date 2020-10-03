#pragma once

#include "tonlib/Config.h"
#include "tonlib/Stuff.h"
#include "tonlib/ExtClient.h"
#include "tonlib/ExtClientOutbound.h"
#include "tonlib/TonlibCallback.h"

#include "td/actor/actor.h"

namespace tonlib {

class GetBlock : public td::actor::Actor {
 public:
  using ResultType = tonlib_api_ptr<tonlib_api::liteServer_block>;

  GetBlock(ExtClientRef ext_client_ref, ton::BlockIdExt block_id, td::actor::ActorShared<> parent,
           td::Promise<ResultType>&& promise);

  void finish_query();

  void start_up_query();
  void got_block_header(lite_api_ptr<lite_api::liteServer_blockHeader>&& result);
  void got_shard_info(lite_api_ptr<lite_api::liteServer_allShardsInfo>&& result);
  void got_transactions(lite_api_ptr<lite_api::liteServer_blockTransactions>&& result);

 private:
  ton::BlockIdExt block_id_;

  td::int32 pending_queries_ = 0;

  std::optional<td::BufferSlice> data_;
  std::optional<td::BufferSlice> shard_data_;

  std::optional<td::Status> data_receive_error_;
  std::optional<td::Status> shard_data_receive_error_;
  std::optional<td::Status> block_transactions_receive_error_;

  std::vector<tonlib_api_ptr<tonlib_api::liteServer_transactionId>> transactions_;
  td::uint32 trans_req_count_;

  td::actor::ActorShared<> parent_;
  td::Promise<ResultType> promise_;
  ExtClient client_;
};

}  // namespace tonlib
