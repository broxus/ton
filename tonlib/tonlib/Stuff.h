#pragma once

#include "tonlib/utils.h"
#include "tonlib/KeyStorage.h"

#include "smc-envelope/WalletV3.h"
#include "smc-envelope/PaymentChannel.h"
#include "smc-envelope/ManualDns.h"

#include "block/check-proof.h"

#include "td/actor/actor.h"

#include "auto/tl/tonlib_api.hpp"
#include "auto/tl/lite_api.hpp"

namespace tonlib {

template <class Type>
using lite_api_ptr = ton::lite_api::object_ptr<Type>;
template <class Type>
using tonlib_api_ptr = ton::tonlib_api::object_ptr<Type>;

namespace tonlib_api = ton::tonlib_api;
namespace lite_api = ton::lite_api;

template <class R, class O, class F>
R downcast_call2(O&& o, F&& f, R res = {}) {
  downcast_call(o, [&](auto& x) { res = f(x); });
  return res;
}

auto status_to_tonlib_api(const td::Status& status) -> tonlib_api_ptr<tonlib_api::error>;

auto to_bits256(td::Slice data, td::Slice name) -> td::Result<td::Bits256>;

auto to_bytes(const td::Ref<vm::Cell>& cell) -> std::string;
auto from_bytes(const std::string& bytes) -> td::Result<td::Ref<vm::Cell>>;

auto empty_transaction_id() -> tonlib_api_ptr<tonlib_api::internal_transactionId>;
auto to_transaction_id(const block::AccountState::Info& info) -> tonlib_api_ptr<tonlib_api::internal_transactionId>;

auto get_public_key(td::Slice public_key) -> td::Result<block::PublicKey>;
auto get_adnl_address(td::Slice adnl_address) -> td::Result<td::Bits256>;

auto get_wallet_type(tonlib_api::InitialAccountState& state) -> td::optional<ton::SmartContractCode::Type>;

auto get_account_address(td::Slice account_address) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::raw_initialAccountState& raw_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::wallet_v3_initialAccountState& test_wallet_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::wallet_highload_v1_initialAccountState& test_wallet_state,
                         td::int32 revision, ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::wallet_highload_v2_initialAccountState& test_wallet_state,
                         td::int32 revision, ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::dns_initialAccountState& dns_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::pchan_initialAccountState& pchan_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;
auto get_account_address(const tonlib_api::rwallet_initialAccountState& rwallet_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress>;

auto public_key_from_bytes(td::Slice bytes) -> td::Result<block::PublicKey>;

auto create_account_state(ton::tl_object_ptr<ton::lite_api::liteServer_accountState> from) -> block::AccountState;
auto create_account_state(ton::tl_object_ptr<ton::lite_api::liteServer_runMethodResult>& from) -> block::AccountState;

auto is_list(vm::StackEntry entry) -> bool;

auto to_init_data(const tonlib_api::rwallet_initialAccountState& rwallet_state)
    -> td::Result<ton::RestrictedWallet::InitData>;
auto to_pchan_config(const tonlib_api::pchan_initialAccountState& pchan_state) -> td::Result<ton::pchan::Config>;
auto to_dns_entry_data(tonlib_api::dns_EntryData& entry_data) -> td::Result<ton::ManualDns::EntryData>;

auto to_balance(td::Ref<vm::CellSlice> balance_ref) -> td::Result<td::int64>;
auto to_balance_or_throw(td::Ref<vm::CellSlice> balance_ref) -> td::Result<td::int64>;

auto to_std_address(td::Ref<vm::CellSlice> cs) -> td::Result<std::string>;
auto to_std_address_or_throw(td::Ref<vm::CellSlice> cs) -> td::Result<std::string>;

auto to_tonlib_api(const ton::BlockIdExt& blk) -> tonlib_api_ptr<tonlib_api::ton_blockIdExt>;
auto to_tonlib_api(const lite_api::tonNode_blockIdExt& blk) -> tonlib_api_ptr<tonlib_api::ton_blockIdExt>;
auto to_tonlib_api(const lite_api::liteServer_signatureSet& set) -> tonlib_api_ptr<tonlib_api::liteServer_signatureSet>;
auto to_tonlib_api(lite_api::liteServer_BlockLink& link) -> tonlib_api_ptr<tonlib_api::liteServer_BlockLink>;
auto to_tonlib_api(const lite_api::liteServer_transactionId& id)
    -> tonlib_api_ptr<tonlib_api::liteServer_transactionId>;
auto to_tonlib_api(const lite_api::tonNode_zeroStateIdExt& zeroStateId)
    -> tonlib_api_ptr<tonlib_api::ton_zeroStateIdExt>;
auto to_tonlib_api(const td::RefInt256& value) -> td::Result<std::string>;
auto to_tonlib_api(const vm::StackEntry& entry) -> tonlib_api_ptr<tonlib_api::tvm_StackEntry>;
auto to_tonlib_api(const ton::ManualDns::EntryData& entry_data)
    -> td::Result<tonlib_api_ptr<tonlib_api::dns_EntryData>>;

auto from_tonlib_api(tonlib_api::InputKey& input_key) -> td::Result<KeyStorage::InputKey>;
auto from_tonlib_api(tonlib_api::inputKeyRegular& input_key) -> td::Result<KeyStorage::InputKey>;
auto from_tonlib_api(tonlib_api::tvm_StackEntry& entry) -> td::Result<vm::StackEntry>;

auto to_lite_api(const tonlib_api::ton_blockId& blk) -> lite_api_ptr<lite_api::tonNode_blockId>;
auto to_lite_api(const tonlib_api::ton_blockIdExt& blk) -> td::Result<lite_api_ptr<lite_api::tonNode_blockIdExt>>;
auto to_lite_api(const tonlib_api::liteServer_accountId& account)
    -> td::Result<lite_api_ptr<lite_api::liteServer_accountId>>;
auto to_lite_api(const tonlib_api::liteServer_transactionId3& transaction)
    -> td::Result<lite_api_ptr<lite_api::liteServer_transactionId3>>;

}  // namespace tonlib
