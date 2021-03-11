#include "Stuff.h"

#include "tonlib/TonlibError.h"

#include "ton/lite-tl.hpp"
#include "ton/ton-shard.h"

#include "td/utils/overloaded.h"

#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/HighloadWallet.h"
#include "smc-envelope/HighloadWalletV2.h"
#include "smc-envelope/SmartContractCode.h"

#include "common/util.h"

#include <list>

namespace tonlib {

auto status_to_tonlib_api(const td::Status& status) -> tonlib_api_ptr<tonlib_api::error> {
  return tonlib_api::make_object<tonlib_api::error>(status.code(), status.message().str());
}

auto to_bits256(td::Slice data, td::Slice name) -> td::Result<td::Bits256> {
  if (data.size() != 32) {
    return TonlibError::InvalidField(name, "wrong length (not 32 bytes)");
  }
  return td::Bits256(data.ubegin());
}

auto to_bytes(const td::Ref<vm::Cell>& cell) -> std::string {
  if (cell.is_null()) {
    return "";
  }
  return vm::std_boc_serialize(cell, vm::BagOfCells::Mode::WithCRC32C).move_as_ok().as_slice().str();
}

auto from_bytes(const std::string& bytes) -> td::Result<td::Ref<vm::Cell>> {
  if (bytes.empty()) {
    return td::Ref<vm::Cell>{};
  }
  return vm::std_boc_deserialize(td::Slice{bytes.data(), bytes.size()});
}

auto empty_transaction_id() -> tonlib_api_ptr<tonlib_api::internal_transactionId> {
  return tonlib_api::make_object<tonlib_api::internal_transactionId>(0, std::string(32, 0));
}

auto to_transaction_id(const block::AccountState::Info& info) -> tonlib_api_ptr<tonlib_api::internal_transactionId> {
  return tonlib_api::make_object<tonlib_api::internal_transactionId>(info.last_trans_lt,
                                                                     info.last_trans_hash.as_slice().str());
}

auto get_public_key(td::Slice public_key) -> td::Result<block::PublicKey> {
  TRY_RESULT_PREFIX(address, block::PublicKey::parse(public_key), TonlibError::InvalidPublicKey());
  return address;
}

auto get_adnl_address(td::Slice adnl_address) -> td::Result<td::Bits256> {
  TRY_RESULT_PREFIX(address, td::adnl_id_decode(adnl_address),
                    TonlibError::InvalidField("adnl_address", "can't decode"));
  return address;
}

auto get_wallet_type(tonlib_api::InitialAccountState& state) -> td::optional<ton::SmartContractCode::Type> {
  return downcast_call2<td::optional<ton::SmartContractCode::Type>>(
      state,
      td::overloaded(
          [](const tonlib_api::raw_initialAccountState&) { return td::optional<ton::SmartContractCode::Type>(); },
          [](const tonlib_api::wallet_v3_initialAccountState&) { return ton::SmartContractCode::WalletV3; },
          [](const tonlib_api::wallet_highload_v1_initialAccountState&) {
            return ton::SmartContractCode::HighloadWalletV1;
          },
          [](const tonlib_api::wallet_highload_v2_initialAccountState&) {
            return ton::SmartContractCode::HighloadWalletV2;
          },
          [](const tonlib_api::rwallet_initialAccountState&) { return ton::SmartContractCode::RestrictedWallet; },
          [](const tonlib_api::pchan_initialAccountState&) { return ton::SmartContractCode::PaymentChannel; },
          [](const tonlib_api::dns_initialAccountState&) { return ton::SmartContractCode::ManualDns; }));
}

auto get_account_address(td::Slice account_address) -> td::Result<block::StdAddress> {
  TRY_RESULT_PREFIX(address, block::StdAddress::parse(account_address), TonlibError::InvalidAccountAddress());
  return address;
}

auto get_account_address(const tonlib_api::raw_initialAccountState& raw_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT_PREFIX(code, vm::std_boc_deserialize(raw_state.code_), TonlibError::InvalidBagOfCells("raw_state.code"));
  TRY_RESULT_PREFIX(data, vm::std_boc_deserialize(raw_state.data_), TonlibError::InvalidBagOfCells("raw_state.data"));
  return ton::GenericAccount::get_address(workchain_id,
                                          ton::GenericAccount::get_init_state(std::move(code), std::move(data)));
}

auto get_account_address(const tonlib_api::wallet_v3_initialAccountState& test_wallet_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT(key_bytes, get_public_key(test_wallet_state.public_key_));
  return ton::WalletV3::create({key_bytes.key, static_cast<td::uint32>(test_wallet_state.wallet_id_)}, revision)
      ->get_address(workchain_id);
}

auto get_account_address(const tonlib_api::wallet_highload_v1_initialAccountState& test_wallet_state,
                         td::int32 revision, ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT(key_bytes, get_public_key(test_wallet_state.public_key_));
  return ton::HighloadWallet::create({key_bytes.key, static_cast<td::uint32>(test_wallet_state.wallet_id_)}, revision)
      ->get_address(workchain_id);
}

auto get_account_address(const tonlib_api::wallet_highload_v2_initialAccountState& test_wallet_state,
                         td::int32 revision, ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT(key_bytes, get_public_key(test_wallet_state.public_key_));
  return ton::HighloadWalletV2::create({key_bytes.key, static_cast<td::uint32>(test_wallet_state.wallet_id_)}, revision)
      ->get_address(workchain_id);
}

auto get_account_address(const tonlib_api::dns_initialAccountState& dns_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT(key_bytes, get_public_key(dns_state.public_key_));
  auto key = td::Ed25519::PublicKey(td::SecureString(key_bytes.key));
  return ton::ManualDns::create(key, static_cast<td::uint32>(dns_state.wallet_id_), revision)
      ->get_address(workchain_id);
}

auto get_account_address(const tonlib_api::pchan_initialAccountState& pchan_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT(config, to_pchan_config(pchan_state));
  return ton::PaymentChannel::create(config, revision)->get_address(workchain_id);
}

auto get_account_address(const tonlib_api::rwallet_initialAccountState& rwallet_state, td::int32 revision,
                         ton::WorkchainId workchain_id) -> td::Result<block::StdAddress> {
  TRY_RESULT(init_data, to_init_data(rwallet_state));
  return ton::RestrictedWallet::create(init_data, revision)->get_address(workchain_id);
}

auto compute_last_blocks(std::vector<tonlib_api_ptr<tonlib_api::ton_blockId>>&& blocks)
    -> std::vector<tonlib_api_ptr<tonlib_api::ton_blockId>> {
  using BlockId = tonlib_api_ptr<tonlib_api::ton_blockId>;

  if (blocks.empty()) {
    return {};
  }

  // Sort by workchain, seqno and level
  std::sort(blocks.begin(), blocks.end(), [](const BlockId& left, const BlockId& right) {
    return left->workchain_ > right->workchain_ || left->seqno_ > right->seqno_ ||
           td::lower_bit64(left->shard_) < td::lower_bit64(right->shard_);
  });

  std::vector<tonlib_api_ptr<tonlib_api::ton_blockId>> top_blocks{};

  // Graph node in helper trees
  struct Item {
    const BlockId::element_type* block{};
    td::int32 child_count{};
  };

  // Helper trees
  std::list<std::list<Item>> leaves;

  // Process each block
  auto current_workchain = blocks.front()->workchain_;
  for (auto& block : blocks) {
    // Reset leaves for each new workchain
    if (block->workchain_ != current_workchain) {
      leaves.clear();
    }

    bool is_leaf = true;

    // Try to find child in helper trees
    for (auto& leaf : leaves) {
      for (auto it = leaf.begin(); it != leaf.end(); ++it) {
        if (!ton::shard_is_parent(block->shard_, it->block->shard_)) {
          continue;
        }
        // If child found
        const auto child_it = it;
        // Insert current block right after it
        leaf.insert(++it, Item{block.get(), 0});
        // Remove child from tree if all it's parents are found
        if (++child_it->child_count == 2) {
          leaf.erase(child_it);
        }
        // Mark as parent and proceed to next block
        is_leaf = false;
        break;
      }
      if (!is_leaf) {
        break;
      }
    }

    // If no children are found
    if (is_leaf) {
      auto* block_ptr = block.get();

      // Add workers task
      top_blocks.emplace_back(std::move(block));
      // Create leaf tree
      leaves.emplace_back(std::list{Item{block_ptr, 0}});
    }
  }

  return top_blocks;
}

auto public_key_from_bytes(td::Slice bytes) -> td::Result<block::PublicKey> {
  TRY_RESULT_PREFIX(key_bytes, block::PublicKey::from_bytes(bytes), TonlibError::Internal());
  return key_bytes;
}

auto create_account_state(ton::tl_object_ptr<ton::lite_api::liteServer_accountState> from) -> block::AccountState {
  block::AccountState res;
  res.blk = ton::create_block_id(from->id_);
  res.shard_blk = ton::create_block_id(from->shardblk_);
  res.shard_proof = std::move(from->shard_proof_);
  res.proof = std::move(from->proof_);
  res.state = std::move(from->state_);
  return res;
}

auto create_account_state(ton::tl_object_ptr<ton::lite_api::liteServer_runMethodResult>& from) -> block::AccountState {
  block::AccountState res;
  res.blk = ton::create_block_id(from->id_);
  res.shard_blk = ton::create_block_id(from->shardblk_);
  res.shard_proof = std::move(from->shard_proof_);
  res.proof = std::move(from->proof_);
  res.state = std::move(from->state_proof_);
  res.is_virtualized = from->mode_ > 0;
  return res;
}

auto is_list(vm::StackEntry entry) -> bool {
  while (true) {
    if (entry.type() == vm::StackEntry::Type::t_null) {
      return true;
    }
    if (entry.type() != vm::StackEntry::Type::t_tuple) {
      return false;
    }
    if (entry.as_tuple()->size() != 2) {
      return false;
    }
    entry = entry.as_tuple()->at(1);
  }
}

auto to_init_data(const tonlib_api::rwallet_initialAccountState& rwallet_state)
    -> td::Result<ton::RestrictedWallet::InitData> {
  TRY_RESULT(init_key_bytes, get_public_key(rwallet_state.init_public_key_));
  TRY_RESULT(key_bytes, get_public_key(rwallet_state.public_key_));
  ton::RestrictedWallet::InitData init_data;
  init_data.init_key = td::SecureString(init_key_bytes.key);
  init_data.main_key = td::SecureString(key_bytes.key);
  init_data.wallet_id = static_cast<td::uint32>(rwallet_state.wallet_id_);
  return std::move(init_data);
}

auto to_pchan_config(const tonlib_api::pchan_initialAccountState& pchan_state) -> td::Result<ton::pchan::Config> {
  ton::pchan::Config config;
  if (!pchan_state.config_) {
    return TonlibError::EmptyField("config");
  }
  TRY_RESULT_PREFIX(a_key, get_public_key(pchan_state.config_->alice_public_key_),
                    TonlibError::InvalidField("alice_public_key", ""));
  config.a_key = td::SecureString(a_key.key);
  TRY_RESULT_PREFIX(b_key, get_public_key(pchan_state.config_->bob_public_key_),
                    TonlibError::InvalidField("bob_public_key", ""));
  config.b_key = td::SecureString(b_key.key);

  if (!pchan_state.config_->alice_address_) {
    return TonlibError::EmptyField("config.alice_address");
  }
  TRY_RESULT_PREFIX(a_addr, get_account_address(pchan_state.config_->alice_address_->account_address_),
                    TonlibError::InvalidField("alice_address", ""));
  config.a_addr = std::move(a_addr);

  if (!pchan_state.config_->bob_address_) {
    return TonlibError::EmptyField("config.bob_address");
  }
  TRY_RESULT_PREFIX(b_addr, get_account_address(pchan_state.config_->bob_address_->account_address_),
                    TonlibError::InvalidField("bob_address", ""));
  config.b_addr = std::move(b_addr);

  config.channel_id = pchan_state.config_->channel_id_;
  config.init_timeout = pchan_state.config_->init_timeout_;
  config.close_timeout = pchan_state.config_->close_timeout_;
  return std::move(config);
}

auto to_dns_entry_data(tonlib_api::dns_EntryData& entry_data) -> td::Result<ton::ManualDns::EntryData> {
  using R = td::Result<ton::ManualDns::EntryData>;
  return downcast_call2<R>(
      entry_data,
      td::overloaded(
          [&](tonlib_api::dns_entryDataUnknown& unknown) -> R { return ton::ManualDns::EntryData(); },
          [&](tonlib_api::dns_entryDataNextResolver& next_resolver) -> R {
            if (!next_resolver.resolver_) {
              return TonlibError::EmptyField("resolver");
            }
            TRY_RESULT(resolver, get_account_address(next_resolver.resolver_->account_address_));
            return ton::ManualDns::EntryData::next_resolver(std::move(resolver));
          },
          [&](tonlib_api::dns_entryDataSmcAddress& smc_address) -> R {
            if (!smc_address.smc_address_) {
              return TonlibError::EmptyField("smc_address");
            }
            TRY_RESULT(address, get_account_address(smc_address.smc_address_->account_address_));
            return ton::ManualDns::EntryData::smc_address(std::move(address));
          },
          [&](tonlib_api::dns_entryDataAdnlAddress& adnl_address) -> R {
            if (!adnl_address.adnl_address_) {
              return TonlibError::EmptyField("adnl_address");
            }
            TRY_RESULT(address, get_adnl_address(adnl_address.adnl_address_->adnl_address_));
            return ton::ManualDns::EntryData::adnl_address(std::move(address));
          },
          [&](tonlib_api::dns_entryDataText& text) -> R { return ton::ManualDns::EntryData::text(text.text_); }));
}

auto to_balance(td::Ref<vm::CellSlice> balance_ref) -> td::Result<td::int64> {
  return TRY_VM(to_balance_or_throw(std::move(balance_ref)));
}

auto to_balance_or_throw(td::Ref<vm::CellSlice> balance_ref) -> td::Result<td::int64> {
  vm::CellSlice balance_slice = *balance_ref;
  auto balance = block::tlb::t_Grams.as_integer_skip(balance_slice);
  if (balance.is_null()) {
    return td::Status::Error("Failed to unpack balance");
  }
  auto res = balance->to_long();
  if (res == td::int64(~0ULL << 63)) {
    return td::Status::Error("Failed to unpack balance (2)");
  }
  return res;
}

auto to_std_address(td::Ref<vm::CellSlice> cs) -> td::Result<std::string> {
  return TRY_VM(to_std_address_or_throw(std::move(cs)));
}

auto to_std_address_or_throw(td::Ref<vm::CellSlice> cs) -> td::Result<std::string> {
  auto tag = block::gen::MsgAddressInt().get_tag(*cs);
  if (tag < 0) {
    return td::Status::Error("Failed to read MsgAddressInt tag");
  }
  if (tag != block::gen::MsgAddressInt::addr_std) {
    return "";
  }
  block::gen::MsgAddressInt::Record_addr_std addr;
  if (!tlb::csr_unpack(cs, addr)) {
    return td::Status::Error("Failed to unpack MsgAddressInt");
  }
  return block::StdAddress(addr.workchain_id, addr.address).rserialize(true);
}

auto to_tonlib_api(const ton::BlockId& blk) -> tonlib_api_ptr<tonlib_api::ton_blockId> {
  return tonlib_api::make_object<tonlib_api::ton_blockId>(blk.workchain, blk.shard, blk.seqno);
}

auto to_tonlib_api(const ton::BlockIdExt& blk) -> tonlib_api_ptr<tonlib_api::ton_blockIdExt> {
  return tonlib_api::make_object<tonlib_api::ton_blockIdExt>(
      blk.id.workchain, blk.id.shard, blk.id.seqno, blk.root_hash.as_slice().str(), blk.file_hash.as_slice().str());
}

auto to_tonlib_api(const lite_api::tonNode_blockIdExt& blk) -> tonlib_api_ptr<tonlib_api::ton_blockIdExt> {
  return tonlib_api::make_object<tonlib_api::ton_blockIdExt>(
      blk.workchain_, blk.shard_, blk.seqno_, blk.root_hash_.as_slice().str(), blk.file_hash_.as_slice().str());
}

auto to_tonlib_api(const lite_api::liteServer_signatureSet& set)
    -> tonlib_api_ptr<tonlib_api::liteServer_signatureSet> {
  std::vector<tonlib_api_ptr<tonlib_api::liteServer_signature>> signatures;
  signatures.resize(set.signatures_.size());
  for (const auto& item : set.signatures_) {
    signatures.emplace_back(tonlib_api::make_object<tonlib_api::liteServer_signature>(
        item->node_id_short_.as_slice().str(), item->signature_.as_slice().str()));
  }
  return lite_api::make_object<tonlib_api::liteServer_signatureSet>(set.validator_set_hash_, set.catchain_seqno_,
                                                                    std::move(signatures));
}

auto to_tonlib_api(lite_api::liteServer_BlockLink& link) -> tonlib_api_ptr<tonlib_api::liteServer_BlockLink> {
  using ReturnType = tonlib_api_ptr<tonlib_api::liteServer_BlockLink>;
  return downcast_call2<ReturnType>(  //
      link,                           //
      td::overloaded(                 //
          [](const lite_api::liteServer_blockLinkBack& param) -> ReturnType {
            return tonlib_api::make_object<tonlib_api::liteServer_blockLinkBack>(
                param.to_key_block_, to_tonlib_api(*param.from_), to_tonlib_api(*param.to_),
                param.dest_proof_.as_slice().str(), param.proof_.as_slice().str(), param.state_proof_.as_slice().str());
          },
          [](const lite_api::liteServer_blockLinkForward& param) -> ReturnType {
            return tonlib_api::make_object<tonlib_api::liteServer_blockLinkForward>(
                param.to_key_block_, to_tonlib_api(*param.from_), to_tonlib_api(*param.to_),
                param.dest_proof_.as_slice().str(), param.config_proof_.as_slice().str(),
                to_tonlib_api(*param.signatures_));
          }));
}

auto to_tonlib_api(const lite_api::liteServer_transactionId& id)
    -> tonlib_api_ptr<tonlib_api::liteServer_transactionId> {
  std::string account{};
  if (id.mode_ & lite_api::liteServer_transactionId::ACCOUNT_MASK) {
    account = id.account_.as_slice().str();
  }
  std::string hash{};
  if (id.mode_ & lite_api::liteServer_transactionId::HASH_MASK) {
    hash = id.hash_.as_slice().str();
  }
  return tonlib_api::make_object<tonlib_api::liteServer_transactionId>(id.mode_, account, id.lt_, hash);
}

auto to_tonlib_api(const lite_api::tonNode_zeroStateIdExt& zeroStateId)
    -> tonlib_api_ptr<tonlib_api::ton_zeroStateIdExt> {
  return tonlib_api::make_object<tonlib_api::ton_zeroStateIdExt>(
      zeroStateId.workchain_, zeroStateId.root_hash_.as_slice().str(), zeroStateId.file_hash_.as_slice().str());
}

auto to_tonlib_api(const td::RefInt256& value) -> td::Result<std::string> {
  td::BufferSlice bytes(32);
  if (!value->export_bytes(reinterpret_cast<unsigned char*>(bytes.data()), 32, false)) {
    return td::Status::Error("failed to unpack integer");
  }
  return bytes.as_slice().str();
}

auto to_tonlib_api(const vm::StackEntry& entry) -> tonlib_api_ptr<tonlib_api::tvm_StackEntry> {
  switch (entry.type()) {
    case vm::StackEntry::Type::t_int:
      return tonlib_api::make_object<tonlib_api::tvm_stackEntryNumber>(
          tonlib_api::make_object<tonlib_api::tvm_numberDecimal>(dec_string(entry.as_int())));
    case vm::StackEntry::Type::t_slice:
      return tonlib_api::make_object<tonlib_api::tvm_stackEntryCell>(tonlib_api::make_object<tonlib_api::tvm_cell>(
          to_bytes(vm::CellBuilder().append_cellslice(entry.as_slice()).finalize())));
    case vm::StackEntry::Type::t_cell:
      return tonlib_api::make_object<tonlib_api::tvm_stackEntryCell>(
          tonlib_api::make_object<tonlib_api::tvm_cell>(to_bytes(entry.as_cell())));
    case vm::StackEntry::Type::t_null:
    case vm::StackEntry::Type::t_tuple: {
      std::vector<tonlib_api_ptr<tonlib_api::tvm_StackEntry>> elements;
      if (is_list(entry)) {
        auto node = entry;
        while (node.type() == vm::StackEntry::Type::t_tuple) {
          elements.push_back(to_tonlib_api(node.as_tuple()->at(0)));
          node = node.as_tuple()->at(1);
        }
        return tonlib_api::make_object<tonlib_api::tvm_stackEntryList>(
            tonlib_api::make_object<tonlib_api::tvm_list>(std::move(elements)));

      } else {
        for (auto& element : *entry.as_tuple()) {
          elements.push_back(to_tonlib_api(element));
        }
        return tonlib_api::make_object<tonlib_api::tvm_stackEntryTuple>(
            tonlib_api::make_object<tonlib_api::tvm_tuple>(std::move(elements)));
      }
    }

    default:
      return tonlib_api::make_object<tonlib_api::tvm_stackEntryUnsupported>();
  }
}

auto to_tonlib_api(const ton::ManualDns::EntryData& entry_data)
    -> td::Result<tonlib_api_ptr<tonlib_api::dns_EntryData>> {
  td::Result<tonlib_api_ptr<tonlib_api::dns_EntryData>> res;
  if (entry_data.data.empty()) {
    return TonlibError::Internal("Unexpected empty EntryData");
  }
  entry_data.data.visit(td::overloaded(
      [&](const ton::ManualDns::EntryDataText& text) {
        res = tonlib_api::make_object<tonlib_api::dns_entryDataText>(text.text);
      },
      [&](const ton::ManualDns::EntryDataNextResolver& resolver) {
        res = tonlib_api::make_object<tonlib_api::dns_entryDataNextResolver>(
            tonlib_api::make_object<tonlib_api::accountAddress>(resolver.resolver.rserialize(true)));
      },
      [&](const ton::ManualDns::EntryDataAdnlAddress& adnl_address) {
        res = tonlib_api::make_object<tonlib_api::dns_entryDataAdnlAddress>(
            tonlib_api::make_object<tonlib_api::adnlAddress>(
                td::adnl_id_encode(adnl_address.adnl_address.as_slice()).move_as_ok()));
      },
      [&](const ton::ManualDns::EntryDataSmcAddress& smc_address) {
        res = tonlib_api::make_object<tonlib_api::dns_entryDataSmcAddress>(
            tonlib_api::make_object<tonlib_api::accountAddress>(smc_address.smc_address.rserialize(true)));
      }));
  return res;
}

auto from_tonlib_api(tonlib_api::InputKey& input_key)
    -> td::Result<std::pair<KeyStorage::InputKeyType, KeyStorage::InputKey>> {
  return downcast_call2<td::Result<std::pair<KeyStorage::InputKeyType, KeyStorage::InputKey>>>(
      input_key, td::overloaded([&](tonlib_api::inputKeyRegular& input_key) { return from_tonlib_api(input_key); },
                                [&](tonlib_api::inputKeyFtabi& input_key) { return from_tonlib_api(input_key); },
                                [&](tonlib_api::inputKeyFake&) {
                                  return std::make_pair(KeyStorage::InputKeyType::Fake, KeyStorage::fake_input_key());
                                }));
}

auto from_tonlib_api(tonlib_api::inputKeyRegular& input_key)
    -> td::Result<std::pair<KeyStorage::InputKeyType, KeyStorage::InputKey>> {
  if (!input_key.key_) {
    return TonlibError::EmptyField("key");
  }

  TRY_RESULT(key_bytes, get_public_key(input_key.key_->public_key_));
  return std::make_pair(KeyStorage::InputKeyType::Original,
                        KeyStorage::InputKey{{td::SecureString(key_bytes.key), std::move(input_key.key_->secret_)},
                                             std::move(input_key.local_password_)});
}

auto from_tonlib_api(tonlib_api::inputKeyFtabi& input_key)
    -> td::Result<std::pair<KeyStorage::InputKeyType, KeyStorage::InputKey>> {
  if (!input_key.key_) {
    return TonlibError::EmptyField("key");
  }

  TRY_RESULT(key_bytes, get_public_key(input_key.key_->public_key_));
  return std::make_pair(KeyStorage::InputKeyType::Ftabi,
                        KeyStorage::InputKey{{td::SecureString(key_bytes.key), std::move(input_key.key_->secret_)},
                                             std::move(input_key.local_password_)});
}

auto from_tonlib_api(tonlib_api::tvm_StackEntry& entry) -> td::Result<vm::StackEntry> {
  // TODO: error codes
  // downcast_call
  return downcast_call2<td::Result<vm::StackEntry>>(
      entry,
      td::overloaded(
          [&](tonlib_api::tvm_stackEntryUnsupported& cell) { return td::Status::Error("Unsuppored stack entry"); },
          [&](tonlib_api::tvm_stackEntrySlice& cell) -> td::Result<vm::StackEntry> {
            TRY_RESULT(res, vm::std_boc_deserialize(cell.slice_->bytes_));
            return vm::StackEntry{std::move(res)};
          },
          [&](tonlib_api::tvm_stackEntryCell& cell) -> td::Result<vm::StackEntry> {
            TRY_RESULT(res, vm::std_boc_deserialize(cell.cell_->bytes_));
            return vm::StackEntry{std::move(res)};
          },
          [&](tonlib_api::tvm_stackEntryTuple& tuple) -> td::Result<vm::StackEntry> {
            std::vector<vm::StackEntry> elements;
            for (auto& element : tuple.tuple_->elements_) {
              TRY_RESULT(new_element, from_tonlib_api(*element));
              elements.push_back(std::move(new_element));
            }
            return td::Ref<vm::Tuple>(true, std::move(elements));
          },
          [&](tonlib_api::tvm_stackEntryList& tuple) -> td::Result<vm::StackEntry> {
            vm::StackEntry tail;
            for (auto& element : td::reversed(tuple.list_->elements_)) {
              TRY_RESULT(new_element, from_tonlib_api(*element));
              tail = vm::make_tuple_ref(std::move(new_element), std::move(tail));
            }
            return tail;
          },
          [&](tonlib_api::tvm_stackEntryNumber& number) -> td::Result<vm::StackEntry> {
            auto& dec = *number.number_;
            auto num = td::dec_string_to_int256(dec.number_);
            if (num.is_null()) {
              return td::Status::Error("Failed to parse dec string to int256");
            }
            return num;
          }));
}

auto to_lite_api(const block::StdAddress& addr) -> lite_api_ptr<lite_api::liteServer_accountId> {
  return tonlib_api::make_object<lite_api::liteServer_accountId>(  //
      addr.workchain, addr.addr);
}

auto to_lite_api(const tonlib_api::ton_blockId& blk) -> lite_api_ptr<lite_api::tonNode_blockId> {
  return lite_api::make_object<lite_api::tonNode_blockId>(blk.workchain_, blk.shard_, blk.seqno_);
}

auto to_lite_api(const tonlib_api::ton_blockIdExt& blk) -> td::Result<lite_api_ptr<lite_api::tonNode_blockIdExt>> {
  TRY_RESULT(root_hash, to_bits256(blk.root_hash_, "blk.root_hash"))
  TRY_RESULT(file_hash, to_bits256(blk.file_hash_, "blk.file_hash"))
  return lite_api::make_object<lite_api::tonNode_blockIdExt>(blk.workchain_, blk.shard_, blk.seqno_, root_hash,
                                                             file_hash);
}

auto to_lite_api(const tonlib_api::liteServer_accountId& account)
    -> td::Result<lite_api_ptr<lite_api::liteServer_accountId>> {
  TRY_RESULT(id, to_bits256(account.id_, "account.id"))
  return lite_api::make_object<lite_api::liteServer_accountId>(account.workchain_, id);
}

auto to_lite_api(const tonlib_api::liteServer_transactionId3& transaction)
    -> td::Result<lite_api_ptr<lite_api::liteServer_transactionId3>> {
  TRY_RESULT(account, to_bits256(transaction.account_, "transaction.account"))
  return lite_api::make_object<lite_api::liteServer_transactionId3>(account, transaction.lt_);
}

auto from_lite_api(lite_api::tonNode_blockIdExt& block_id) -> ton::BlockIdExt {
  return ton::BlockIdExt(block_id.workchain_, block_id.shard_, block_id.seqno_, block_id.root_hash_,
                         block_id.file_hash_);
}

}  // namespace tonlib
