#pragma once

#include <tdutils/td/utils/port/FileFd.h>
#include "validator/interfaces/scorer.h"

namespace ton {

namespace validator {

class ScorerImpl : public Scorer<ton::UnixTime> {
  template <typename T = ton::UnixTime>
  struct BlockTimings {
    T created_at;
    std::map<ton::Bits256, T> validator_signatures = {};

    explicit BlockTimings(T created_at) : created_at(created_at) {
    }
  };

 public:
  td::Status init() override;
  td::Status flush() override;
  void push_block(BlockIdExt block_id, Time time, td::Promise<td::Unit> promise) override;
  void mention_validator(BlockIdExt block_id, ton::Ed25519_PublicKey key, Time time,
                         td::Promise<td::Unit> promise) override;
  void accept_block(BlockIdExt block_id, Time time, td::Promise<td::Unit> promise) override;
  void reject_block(BlockIdExt block_id, Time time, td::Promise<td::Unit> promise) override;

  ScorerImpl(std::string db_root) : db_root_{db_root} {
  }

 private:
  void write(td::Slice slice);

  std::map<BlockIdExt, BlockTimings<Time>> timings_;
  std::string db_root_;
  td::FileFd file_;
  td::uint64 sync_counter_;
};

}  // namespace validator

}  // namespace ton
