#pragma once

#include "tonlib/Stuff.h"

namespace tonlib {

struct RawAccountState {
  td::int64 balance = -1;

  ton::UnixTime storage_last_paid{0};
  vm::CellStorageStat storage_stat;

  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
  td::Ref<vm::Cell> state;
  std::string frozen_hash;
  block::AccountState::Info info;
  ton::BlockIdExt block_id;
};

class AccountState {
 public:
  AccountState(block::StdAddress address, RawAccountState&& raw, td::uint32 wallet_id);

  auto to_uninited_accountState() const -> tonlib_api_ptr<tonlib_api::uninited_accountState>;

  auto to_raw_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::raw_accountState>>;
  auto to_raw_fullAccountState() const -> td::Result<tonlib_api_ptr<tonlib_api::raw_fullAccountState>>;

  auto to_wallet_v3_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::wallet_v3_accountState>>;
  auto to_wallet_highload_v1_accountState() const
      -> td::Result<tonlib_api_ptr<tonlib_api::wallet_highload_v1_accountState>>;
  auto to_wallet_highload_v2_accountState() const
      -> td::Result<tonlib_api_ptr<tonlib_api::wallet_highload_v2_accountState>>;
  auto to_rwallet_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::rwallet_accountState>>;
  auto to_payment_channel_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::pchan_accountState>>;

  auto to_dns_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::dns_accountState>>;

  auto to_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::AccountState>>;

  auto to_fullAccountState() const -> td::Result<tonlib_api_ptr<tonlib_api::fullAccountState>>;

  //NB: Order is important! Used during guessAccountRevision
  enum WalletType {
    Empty,
    Unknown,
    WalletV3,
    HighloadWalletV1,
    HighloadWalletV2,
    ManualDns,
    PaymentChannel,
    RestrictedWallet
  };

  WalletType get_wallet_type() const {
    return wallet_type_;
  }

  td::int32 get_wallet_revision() const {
    return wallet_revision_;
  }

  bool is_wallet() const {
    switch (get_wallet_type()) {
      case AccountState::Empty:
      case AccountState::Unknown:
      case AccountState::ManualDns:
      case AccountState::PaymentChannel:
        return false;
      case AccountState::WalletV3:
      case AccountState::HighloadWalletV1:
      case AccountState::HighloadWalletV2:
      case AccountState::RestrictedWallet:
        return true;
    }
    UNREACHABLE();
    return false;
  }

  auto get_wallet() const -> td::unique_ptr<ton::WalletInterface>;

  bool is_frozen() const {
    return !raw_.frozen_hash.empty();
  }

  const block::StdAddress& get_address() const {
    return address_;
  }

  void make_non_bounceable() {
    address_.bounceable = false;
  }

  td::uint32 get_sync_time() const {
    return raw_.info.gen_utime;
  }

  ton::BlockIdExt get_block_id() const {
    return raw_.block_id;
  }

  td::int64 get_balance() const {
    return raw_.balance;
  }

  const RawAccountState& raw() const {
    return raw_;
  }

  auto guess_type_by_init_state(tonlib_api::InitialAccountState& initial_account_state) -> WalletType;
  auto guess_type_by_public_key(td::Ed25519::PublicKey& key) -> WalletType;
  auto guess_type_default(td::Ed25519::PublicKey& key) -> WalletType;

  ton::SmartContract::State get_smc_state() const {
    return {raw_.code, raw_.data};
  }

  td::Ref<vm::Cell> get_raw_state() {
    return raw_.state;
  }

  void set_new_state(ton::SmartContract::State state) {
    raw_.code = std::move(state.code);
    raw_.data = std::move(state.data);
    raw_.state = ton::GenericAccount::get_init_state(raw_.code, raw_.data);
    has_new_state_ = true;
  }

  td::Ref<vm::Cell> get_new_state() const {
    if (!has_new_state_) {
      return {};
    }
    return raw_.state;
  }

 private:
  block::StdAddress address_;
  RawAccountState raw_;
  vm::CellHash code_hash_{};
  WalletType wallet_type_{Unknown};
  td::int32 wallet_revision_{0};
  td::uint32 wallet_id_{0};
  bool has_new_state_{false};

  auto guess_type() -> WalletType;
};

}  // namespace tonlib
