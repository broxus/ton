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

  auto parse_result() -> td::Result<ResultType>;
  void finish_query();

  void start_up() override;
  void got_block_header(lite_api_ptr<lite_api::liteServer_blockHeader>&& result);
  void got_shard_info(lite_api_ptr<lite_api::liteServer_allShardsInfo>&& result);
  void got_transactions(lite_api_ptr<lite_api::liteServer_blockTransactions>&& result);

  void hangup() override {
    check(TonlibError::Cancelled());
  }

 private:
  void check(td::Status status) {
    if (status.is_error()) {
      promise_.set_error(std::move(status));
      stop();
    }
  }

  ton::BlockIdExt block_id_;

  td::int32 pending_queries_ = 0;

  td::BufferSlice data_;
  td::BufferSlice shard_data_;

  std::vector<tonlib_api_ptr<tonlib_api::liteServer_transactionId>> transactions_;
  td::uint32 trans_req_count_;

  td::actor::ActorShared<> parent_;
  td::Promise<ResultType> promise_;
  ExtClient client_;
};

}  // namespace tonlib
