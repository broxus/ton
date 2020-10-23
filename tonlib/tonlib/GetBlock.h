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
  GetBlock(ExtClientRef ext_client_ref, ton::BlockId block_id, int mode, td::int64 lt, td::int32 utime,
           td::actor::ActorShared<> parent, td::Promise<ResultType>&& promise);

 private:
  auto parse_result() -> td::Result<ResultType>;
  void finish_query();

  void start_up() override;
  void start_up_with_block_id(const ton::BlockIdExt& block_id);
  void start_up_with_lookup();
  void proceed_with_block_id(const ton::BlockIdExt& block_id);

  void got_block_header(lite_api_ptr<lite_api::liteServer_blockHeader>&& result);
  void got_block_data(lite_api_ptr<lite_api::liteServer_blockData>&& result);

  void hangup() override {
    check(TonlibError::Cancelled());
  }

  void check_finished() {
    if (!--pending_queries_) {
      finish_query();
    }
  }

  void check(td::Status status) {
    if (status.is_error()) {
      LOG(ERROR) << status.error().message();
      promise_.set_error(std::move(status));
      stop();
    }
  }

  std::optional<ton::BlockIdExt> block_id_{};
  int mode_{};
  ton::BlockId block_id_simple_{};
  td::int64 lt_{};
  td::int32 utime_{};

  td::int32 pending_queries_ = 0;

  td::BufferSlice block_data_;

  td::actor::ActorShared<> parent_;
  td::Promise<ResultType> promise_;
  ExtClient client_;
};

}  // namespace tonlib
