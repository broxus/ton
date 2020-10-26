#pragma once

#include "tonlib/Stuff.h"
#include "tonlib/ExtClient.h"
#include "tonlib/ExtClientOutbound.h"
#include "tonlib/TonlibCallback.h"

#include "td/actor/actor.h"

namespace tonlib {

class ElectorSmc : public td::actor::Actor {
 public:
  using PastElectionsHandler = td::Promise<tonlib_api_ptr<tonlib_api::liteServer_pastElections>>;

  ElectorSmc(ExtClientRef ext_client_ref, td::actor::ActorShared<> parent, const ton::BlockIdExt& block_id,
             const ton::StdSmcAddress& elector_addr,
             td::Promise<tonlib_api_ptr<tonlib_api::liteServer_pastElections>>&& promise);

 private:
  void start_up_with_block_id(const ton::BlockIdExt& block_id);
  void got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state);
  auto execute_method(lite_api_ptr<lite_api::liteServer_accountState>&& account_state) -> td::Status;

  void start_up() final;
  void hangup() final;
  void check(td::Status status);

  ton::BlockIdExt block_id_;
  ton::StdSmcAddress elector_addr_;
  PastElectionsHandler past_elections_handler_;

  td::actor::ActorShared<> parent_;
  ExtClient client_;
};

}  // namespace tonlib
