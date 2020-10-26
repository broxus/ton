#include "ElectorSmc.h"

#include "tonlib/LastBlock.h"
#include "tonlib/LastConfig.h"

#include "ton/lite-tl.hpp"
#include "vm/cp0.h"
#include "lite-client/lite-client-common.h"

namespace tonlib {

namespace {
auto convert_int64(td::Slice word, td::int64& val) -> bool {
  val = (~0ULL << 63);
  if (word.empty()) {
    return false;
  }
  const char* ptr = word.data();
  char* end = nullptr;
  val = std::strtoll(ptr, &end, 10);
  if (end == ptr + word.size()) {
    return true;
  } else {
    val = (~0ULL << 63);
    return false;
  }
}

auto compute_method_id(const std::string& method) -> td::int64 {
  td::int64 method_id;
  if (!convert_int64(method, method_id)) {
    method_id = (td::crc16(td::Slice{method}) & 0xffff) | 0x10000;
  }
  return method_id;
}
}  // namespace

static const auto past_elections_method_id = compute_method_id("past_elections");

ElectorSmc::ElectorSmc(ExtClientRef ext_client_ref, td::actor::ActorShared<> parent, const ton::BlockIdExt& block_id,
                       const ton::StdSmcAddress& elector_addr,
                       td::Promise<tonlib_api_ptr<tonlib_api::liteServer_pastElections>>&& promise)
    : block_id_{block_id}
    , elector_addr_{elector_addr}
    , past_elections_handler_{std::move(promise)}
    , parent_{std::move(parent)} {
  client_.set_client(std::move(ext_client_ref));
}

void ElectorSmc::start_up_with_block_id(const ton::BlockIdExt& block_id) {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<lite_api_ptr<lite_api::liteServer_accountState>> R) {
        if (R.is_error()) {
          td::actor::send_closure(SelfId, &ElectorSmc::check, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &ElectorSmc::got_account_state, R.move_as_ok());
        }
      });
  auto elector_addr = lite_api::make_object<lite_api::liteServer_accountId>(ton::masterchainId, elector_addr_);
  client_.send_query(
      lite_api::liteServer_getAccountState(ton::create_tl_lite_block_id(block_id), std::move(elector_addr)),
      std::move(P));
}

void ElectorSmc::got_account_state(lite_api_ptr<lite_api::liteServer_accountState>&& account_state) {
  check(execute_method(std::move(account_state)));
  stop();
}

auto ElectorSmc::execute_method(lite_api_ptr<lite_api::liteServer_accountState>&& account_state) -> td::Status {
  block::AccountState state;
  state.blk = ton::create_block_id(account_state->id_);
  state.shard_blk = ton::create_block_id(account_state->shardblk_);
  state.shard_proof = std::move(account_state->shard_proof_);
  state.proof = std::move(account_state->proof_);
  state.state = std::move(account_state->state_);
  TRY_RESULT(account_info, state.validate(block_id_, block::StdAddress(ton::masterchainId, elector_addr_)))
  if (account_info.root.is_null()) {
    return td::Status::Error("account is empty");
  }

  block::gen::AccountStorage::Record store;
  block::gen::Account::Record_account account;
  block::CurrencyCollection balance;
  if (!tlb::unpack_cell(account_info.root, account) || !tlb::csr_unpack(account.storage, store) ||
      !balance.validate_unpack(store.balance)) {
    return td::Status::Error("failed to unpack account record");
  }

  switch (block::gen::t_AccountState.get_tag(*store.state)) {
    case block::gen::AccountState::account_uninit:
      return td::Status::Error("account uninit");
    case block::gen::AccountState::account_frozen:
      return td::Status::Error("account frozen");
    default:
      break;
  }

  CHECK(store.state.write().fetch_ulong(1) == 1)  // account_init$1 _:StateInit = AccountState;
  block::gen::StateInit::Record state_init;
  CHECK(tlb::csr_unpack(store.state, state_init));

  // fill stack
  auto stack = td::make_ref<vm::Stack>();
  stack.write().push_smallint(past_elections_method_id);  // method id

  // create vm
  vm::init_op_cp0();

  vm::VmState vm{state_init.code->prefetch_ref(),
                 std::move(stack),
                 vm::GasLimits{1'000'000'000},
                 /* flags */ 1,
                 state_init.data->prefetch_ref(),
                 vm::VmLog{}};

  // initialize registers with SmartContractInfo
  vm.set_c7(liteclient::prepare_vm_c7(account_info.gen_utime, account_info.gen_lt, account.addr, balance));

  // execute
  int exit_code;
  try {
    exit_code = ~vm.run();
  } catch (vm::VmVirtError& err) {
    LOG(ERROR) << "virtualization error while running VM to locally compute runSmcMethod result: " << err.get_msg();
    return td::Status::Error(
        PSLICE() << "virtualization error while running VM to locally compute runSmcMethod result: " << err.get_msg());
  } catch (vm::VmError& err) {
    LOG(ERROR) << "error while running VM to locally compute runSmcMethod result: " << err.get_msg();
    return td::Status::Error(PSLICE() << "error while running VM to locally compute runSmcMethod result: "
                                      << err.get_msg());
  } catch (vm::VmFatal& err) {
    LOG(ERROR) << "error while running VM";
    return td::Status::Error("Fatal VM error");
  }

  LOG(DEBUG) << "VM terminated with exit code " << exit_code;

  if (exit_code != 0) {
    return td::Status::Error(PSLICE() << "VM terminated with non-zero exit code " << exit_code);
  }

  const auto results = vm.get_stack_ref()->extract_contents();
  if (results.size() != 1 || (!results[0].is_null() && !results[0].is_tuple())) {
    return td::Status::Error("invalid result");
  }

  std::vector<tonlib_api_ptr<tonlib_api::liteServer_pastElectionsItem>> result;

  using WrapperType = decltype(std::declval<vm::StackEntry>().as_tuple());

  WrapperType wrapper{};
  if (const auto& root = results[0]; root.is_tuple()) {
    wrapper = root.as_tuple();
  }

  while (wrapper.not_null()) {
    if (wrapper->size() != 2 || !wrapper->at(0).is_tuple()) {
      return td::Status::Error("invalid result wrapper item");
    }
    const auto& tuple = wrapper->at(0).as_tuple();
    if (tuple->size() != 8) {
      return td::Status::Error("invalid result tuple");
    }
    auto tuple_it = tuple->begin();

    td::int32 election_id, unfreeze_at, stake_held_for;
    td::RefInt256 vset_hash_value, total_stake_value, total_bonuses_value;

    if (!tuple_it->is_int() || !(election_id = static_cast<td::int32>((tuple_it++)->as_int()->to_long()), true) ||
        !tuple_it->is_int() || !(unfreeze_at = static_cast<td::int32>((tuple_it++)->as_int()->to_long()), true) ||
        !tuple_it->is_int() || !(stake_held_for = static_cast<td::int32>((tuple_it++)->as_int()->to_long()), true) ||
        !tuple_it->is_int() || !(vset_hash_value = (tuple_it++)->as_int(), true) ||    //
        !tuple_it->is_cell() || (tuple_it++, false) ||                                 //
        !tuple_it->is_int() || !(total_stake_value = (tuple_it++)->as_int(), true) ||  //
        !tuple_it->is_int() || !(total_bonuses_value = (tuple_it++)->as_int(), true)) {
      return td::Status::Error("failed to parse result tuple");
    }

    TRY_RESULT(vset_hash, to_tonlib_api(vset_hash_value))
    TRY_RESULT(total_stake, to_tonlib_api(total_stake_value))
    TRY_RESULT(total_bonuses, to_tonlib_api(total_bonuses_value))

    result.emplace_back(tonlib_api::make_object<tonlib_api::liteServer_pastElectionsItem>(
        election_id, unfreeze_at, stake_held_for, vset_hash, total_stake, total_bonuses));

    auto next = wrapper->at(1);
    wrapper = next.is_tuple() ? next.as_tuple() : WrapperType{};
  }

  past_elections_handler_.set_value(tonlib_api::make_object<tonlib_api::liteServer_pastElections>(std::move(result)));
  return td::Status::OK();
}

void ElectorSmc::start_up() {
  start_up_with_block_id(block_id_);
}

void ElectorSmc::hangup() {
  check(TonlibError::Cancelled());
}

void ElectorSmc::check(td::Status status) {
  if (status.is_error()) {
    LOG(ERROR) << status.error().message();
    past_elections_handler_.set_error(std::move(status));
    stop();
  }
}

}  // namespace tonlib
