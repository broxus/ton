#include "AccountState.h"

#include "tonlib/TonlibError.h"

#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/ManualDns.h"
#include "smc-envelope/WalletV3.h"
#include "smc-envelope/HighloadWallet.h"
#include "smc-envelope/HighloadWalletV2.h"
#include "smc-envelope/PaymentChannel.h"
#include "smc-envelope/SmartContractCode.h"

#include "td/utils/overloaded.h"
#include "td/utils/base64.h"

#include "block/check-proof.h"

namespace tonlib {

AccountState::AccountState(block::StdAddress address, RawAccountState&& raw, td::uint32 wallet_id)
    : address_(std::move(address)), raw_(std::move(raw)), wallet_id_(wallet_id) {
  guess_type();
}

auto AccountState::to_uninited_accountState() const -> tonlib_api_ptr<tonlib_api::uninited_accountState> {
  return tonlib_api::make_object<tonlib_api::uninited_accountState>(raw().frozen_hash);
}

auto AccountState::to_raw_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::raw_accountState>> {
  auto state = get_smc_state();
  std::string code;
  if (state.code.not_null()) {
    code = to_bytes(state.code);
  }
  std::string data;
  if (state.data.not_null()) {
    data = to_bytes(state.data);
  }
  return tonlib_api::make_object<tonlib_api::raw_accountState>(std::move(code), std::move(data), raw().frozen_hash);
}

auto AccountState::to_raw_fullAccountState() const -> td::Result<tonlib_api_ptr<tonlib_api::raw_fullAccountState>> {
  auto state = get_smc_state();
  std::string code;
  if (state.code.not_null()) {
    code = to_bytes(state.code);
  }
  std::string data;
  if (state.data.not_null()) {
    data = to_bytes(state.data);
  }
  return tonlib_api::make_object<tonlib_api::raw_fullAccountState>(
      get_balance(), std::move(code), std::move(data), to_transaction_id(raw().info), to_tonlib_api(raw().block_id),
      raw().frozen_hash, get_sync_time());
}

auto AccountState::to_wallet_v3_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::wallet_v3_accountState>> {
  if (wallet_type_ != WalletV3) {
    return TonlibError::AccountTypeUnexpected("WalletV3");
  }
  auto wallet = ton::WalletV3(get_smc_state());
  TRY_RESULT(seqno, wallet.get_seqno());
  TRY_RESULT(wallet_id, wallet.get_wallet_id());
  return tonlib_api::make_object<tonlib_api::wallet_v3_accountState>(static_cast<td::uint32>(wallet_id),
                                                                     static_cast<td::uint32>(seqno));
}

auto AccountState::to_wallet_highload_v1_accountState() const
    -> td::Result<tonlib_api_ptr<tonlib_api::wallet_highload_v1_accountState>> {
  if (wallet_type_ != HighloadWalletV1) {
    return TonlibError::AccountTypeUnexpected("HighloadWalletV1");
  }
  auto wallet = ton::HighloadWallet(get_smc_state());
  TRY_RESULT(seqno, wallet.get_seqno());
  TRY_RESULT(wallet_id, wallet.get_wallet_id());
  return tonlib_api::make_object<tonlib_api::wallet_highload_v1_accountState>(static_cast<td::uint32>(wallet_id),
                                                                              static_cast<td::uint32>(seqno));
}

auto AccountState::to_wallet_highload_v2_accountState() const
    -> td::Result<tonlib_api_ptr<tonlib_api::wallet_highload_v2_accountState>> {
  if (wallet_type_ != HighloadWalletV2) {
    return TonlibError::AccountTypeUnexpected("HighloadWalletV2");
  }
  auto wallet = ton::HighloadWalletV2(get_smc_state());
  TRY_RESULT(wallet_id, wallet.get_wallet_id());
  return tonlib_api::make_object<tonlib_api::wallet_highload_v2_accountState>(static_cast<td::uint32>(wallet_id));
}

auto AccountState::to_rwallet_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::rwallet_accountState>> {
  if (wallet_type_ != RestrictedWallet) {
    return TonlibError::AccountTypeUnexpected("RestrictedWallet");
  }
  auto wallet = ton::RestrictedWallet::create(get_smc_state());
  TRY_RESULT(seqno, wallet->get_seqno());
  TRY_RESULT(wallet_id, wallet->get_wallet_id());
  TRY_RESULT(balance, wallet->get_balance(raw_.balance, raw_.info.gen_utime));
  TRY_RESULT(config, wallet->get_config());

  auto api_config = tonlib_api::make_object<tonlib_api::rwallet_config>();
  api_config->start_at_ = config.start_at;
  for (auto& limit : config.limits) {
    api_config->limits_.push_back(tonlib_api::make_object<tonlib_api::rwallet_limit>(limit.first, limit.second));
  }

  return tonlib_api::make_object<tonlib_api::rwallet_accountState>(wallet_id, seqno, balance, std::move(api_config));
}

auto AccountState::to_payment_channel_accountState() const
    -> td::Result<tonlib_api_ptr<tonlib_api::pchan_accountState>> {
  if (wallet_type_ != PaymentChannel) {
    return TonlibError::AccountTypeUnexpected("PaymentChannel");
  }
  auto pchan = ton::PaymentChannel::create(get_smc_state());
  TRY_RESULT(info, pchan->get_info());
  TRY_RESULT(a_key, public_key_from_bytes(info.config.a_key));
  TRY_RESULT(b_key, public_key_from_bytes(info.config.b_key));

  tonlib_api_ptr<tonlib_api::pchan_State> tl_state;
  info.state.visit(td::overloaded(
      [&](const ton::pchan::StateInit& state) {
        tl_state = tonlib_api::make_object<tonlib_api::pchan_stateInit>(state.signed_A, state.signed_B, state.min_A,
                                                                        state.min_B, state.A, state.B, state.expire_at);
      },
      [&](const ton::pchan::StateClose& state) {
        tl_state = tonlib_api::make_object<tonlib_api::pchan_stateClose>(
            state.signed_A, state.signed_B, state.promise_A, state.promise_B, state.A, state.B, state.expire_at);
      },
      [&](const ton::pchan::StatePayout& state) {
        tl_state = tonlib_api::make_object<tonlib_api::pchan_statePayout>(state.A, state.B);
      }));

  using tonlib_api::make_object;
  return tonlib_api::make_object<tonlib_api::pchan_accountState>(
      tonlib_api::make_object<tonlib_api::pchan_config>(
          a_key.serialize(true), make_object<tonlib_api::accountAddress>(info.config.a_addr.rserialize(true)),
          b_key.serialize(true), make_object<tonlib_api::accountAddress>(info.config.b_addr.rserialize(true)),
          info.config.init_timeout, info.config.close_timeout, info.config.channel_id),
      std::move(tl_state), info.description);
}

auto AccountState::to_dns_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::dns_accountState>> {
  if (wallet_type_ != ManualDns) {
    return TonlibError::AccountTypeUnexpected("ManualDns");
  }
  TRY_RESULT(wallet_id, ton::ManualDns(get_smc_state()).get_wallet_id());
  return tonlib_api::make_object<tonlib_api::dns_accountState>(static_cast<td::uint32>(wallet_id));
}

auto AccountState::to_accountState() const -> td::Result<tonlib_api_ptr<tonlib_api::AccountState>> {
  auto f = [](auto&& r_x) -> td::Result<tonlib_api_ptr<tonlib_api::AccountState>> {
    TRY_RESULT(x, std::move(r_x));
    return std::move(x);
  };

  switch (wallet_type_) {
    case Empty:
      return to_uninited_accountState();
    case Unknown:
      return f(to_raw_accountState());
    case WalletV3:
      return f(to_wallet_v3_accountState());
    case HighloadWalletV1:
      return f(to_wallet_highload_v1_accountState());
    case HighloadWalletV2:
      return f(to_wallet_highload_v2_accountState());
    case RestrictedWallet:
      return f(to_rwallet_accountState());
    case ManualDns:
      return f(to_dns_accountState());
    case PaymentChannel:
      return f(to_payment_channel_accountState());
  }
  UNREACHABLE();
}

auto AccountState::to_fullAccountState() const -> td::Result<tonlib_api_ptr<tonlib_api::fullAccountState>> {
  TRY_RESULT(account_state, to_accountState());
  return tonlib_api::make_object<tonlib_api::fullAccountState>(
      tonlib_api::make_object<tonlib_api::accountAddress>(get_address().rserialize(true)), get_balance(),
      to_transaction_id(raw().info), to_tonlib_api(raw().block_id), get_sync_time(), std::move(account_state),
      get_wallet_revision());
}

auto AccountState::get_wallet() const -> td::unique_ptr<ton::WalletInterface> {
  switch (get_wallet_type()) {
    case AccountState::Empty:
    case AccountState::Unknown:
    case AccountState::ManualDns:
    case AccountState::PaymentChannel:
      return {};
    case AccountState::WalletV3:
      return td::make_unique<ton::WalletV3>(get_smc_state());
    case AccountState::HighloadWalletV1:
      return td::make_unique<ton::HighloadWallet>(get_smc_state());
    case AccountState::HighloadWalletV2:
      return td::make_unique<ton::HighloadWalletV2>(get_smc_state());
    case AccountState::RestrictedWallet:
      return td::make_unique<ton::RestrictedWallet>(get_smc_state());
  }
  UNREACHABLE();
  return {};
}

auto AccountState::guess_type_by_init_state(tonlib_api::InitialAccountState& initial_account_state) -> WalletType {
  if (wallet_type_ != WalletType::Empty) {
    return wallet_type_;
  }
  downcast_call(
      initial_account_state,
      td::overloaded(
          [](auto& x) {},
          [&](tonlib_api::wallet_v3_initialAccountState& wallet_v3) {
            wallet_id_ = static_cast<uint32_t>(wallet_v3.wallet_id_);
          },
          [&](tonlib_api::wallet_highload_v1_initialAccountState& wallet_highload_v1) {
            wallet_id_ = static_cast<uint32_t>(wallet_highload_v1.wallet_id_);
          },
          [&](tonlib_api::wallet_highload_v2_initialAccountState& wallet_highload_v2) {
            wallet_id_ = static_cast<uint32_t>(wallet_highload_v2.wallet_id_);
          },
          [&](tonlib_api::dns_initialAccountState& dns) { wallet_id_ = static_cast<uint32_t>(dns.wallet_id_); },
          [&](tonlib_api::rwallet_initialAccountState& rwallet) {
            for (auto revision : ton::SmartContractCode::get_revisions(ton::SmartContractCode::RestrictedWallet)) {
              auto r_init_data = to_init_data(rwallet);
              if (r_init_data.is_error()) {
                continue;
              }
              auto wallet = ton::RestrictedWallet::create(r_init_data.move_as_ok(), revision);
              if (!(wallet->get_address(ton::masterchainId) == address_ ||
                    wallet->get_address(ton::basechainId) == address_)) {
                continue;
              }

              wallet_type_ = WalletType::RestrictedWallet;
              wallet_revision_ = revision;
              wallet_id_ = static_cast<uint32_t>(rwallet.wallet_id_);

              set_new_state(wallet->get_state());
              break;
            }
          },
          [&](tonlib_api::pchan_initialAccountState& pchan) {
            for (auto revision : ton::SmartContractCode::get_revisions(ton::SmartContractCode::PaymentChannel)) {
              auto r_conf = to_pchan_config(pchan);
              if (r_conf.is_error()) {
                continue;
              }
              auto conf = r_conf.move_as_ok();
              auto wallet = ton::PaymentChannel::create(conf, revision);
              if (!(wallet->get_address(ton::masterchainId) == address_ ||
                    wallet->get_address(ton::basechainId) == address_)) {
                continue;
              }
              wallet_type_ = WalletType::PaymentChannel;
              wallet_revision_ = revision;
              set_new_state(wallet->get_state());
              break;
            }
          }));
  return wallet_type_;
}

auto AccountState::guess_type_by_public_key(td::Ed25519::PublicKey& key) -> WalletType {
  if (wallet_type_ != WalletType::Empty) {
    return wallet_type_;
  }

  ton::WalletV3::InitData init_data{key.as_octet_string(), wallet_id_};
  auto o_revision = ton::WalletV3::guess_revision(address_, init_data);
  if (o_revision) {
    wallet_type_ = WalletType::WalletV3;
    wallet_revision_ = o_revision.value();
    set_new_state(ton::WalletV3::get_init_state(wallet_revision_, init_data));
    return wallet_type_;
  }
  o_revision = ton::HighloadWalletV2::guess_revision(address_, init_data);
  if (o_revision) {
    wallet_type_ = WalletType::HighloadWalletV2;
    wallet_revision_ = o_revision.value();
    set_new_state(ton::HighloadWalletV2::get_init_state(wallet_revision_, init_data));
    return wallet_type_;
  }
  o_revision = ton::HighloadWallet::guess_revision(address_, init_data);
  if (o_revision) {
    wallet_type_ = WalletType::HighloadWalletV1;
    wallet_revision_ = o_revision.value();
    set_new_state(ton::HighloadWallet::get_init_state(wallet_revision_, init_data));
    return wallet_type_;
  }
  o_revision = ton::ManualDns::guess_revision(address_, key, wallet_id_);
  if (o_revision) {
    wallet_type_ = WalletType::ManualDns;
    wallet_revision_ = o_revision.value();
    auto dns = ton::ManualDns::create(key, wallet_id_, wallet_revision_);
    set_new_state(dns->get_state());
    return wallet_type_;
  }
  return wallet_type_;
}

auto AccountState::guess_type_default(td::Ed25519::PublicKey& key) -> WalletType {
  if (wallet_type_ != WalletType::Empty) {
    return wallet_type_;
  }
  ton::WalletV3::InitData init_data(key.as_octet_string(), wallet_id_ + address_.workchain);
  set_new_state(ton::WalletV3::get_init_state(0, init_data));
  wallet_type_ = WalletType::WalletV3;
  return wallet_type_;
}

auto AccountState::guess_type() -> WalletType {
  if (raw_.code.is_null()) {
    wallet_type_ = WalletType::Empty;
    return wallet_type_;
  }
  auto code_hash = raw_.code->get_hash();
  auto o_revision = ton::WalletV3::guess_revision(code_hash);
  if (o_revision) {
    wallet_type_ = WalletType::WalletV3;
    wallet_revision_ = o_revision.value();
    return wallet_type_;
  }
  o_revision = ton::HighloadWalletV2::guess_revision(code_hash);
  if (o_revision) {
    wallet_type_ = WalletType::HighloadWalletV2;
    wallet_revision_ = o_revision.value();
    return wallet_type_;
  }
  o_revision = ton::HighloadWallet::guess_revision(code_hash);
  if (o_revision) {
    wallet_type_ = WalletType::HighloadWalletV1;
    wallet_revision_ = o_revision.value();
    return wallet_type_;
  }
  o_revision = ton::ManualDns::guess_revision(code_hash);
  if (o_revision) {
    wallet_type_ = WalletType::ManualDns;
    wallet_revision_ = o_revision.value();
    return wallet_type_;
  }
  o_revision = ton::PaymentChannel::guess_revision(code_hash);
  if (o_revision) {
    wallet_type_ = WalletType::PaymentChannel;
    wallet_revision_ = o_revision.value();
    return wallet_type_;
  }
  o_revision = ton::RestrictedWallet::guess_revision(code_hash);
  if (o_revision) {
    wallet_type_ = WalletType::RestrictedWallet;
    wallet_revision_ = o_revision.value();
    return wallet_type_;
  }

  LOG(WARNING) << "Unknown code hash: " << td::base64_encode(code_hash.as_slice());
  wallet_type_ = WalletType::Unknown;
  return wallet_type_;
}

}  // namespace tonlib
