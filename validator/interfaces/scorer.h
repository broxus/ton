#pragma once

#include <map>

#include "td/actor/actor.h"

#include "ton/ton-types.h"

namespace ton {

namespace validator {

template <typename T>
class Scorer : public td::actor::Actor {
 public:
  using Time = T;

  virtual ~Scorer() = default;
  virtual td::Status init() = 0;
  virtual td::Status flush() = 0;
  virtual void push_block(BlockIdExt block_id, T time, td::Promise<td::Unit> promise) = 0;
  virtual void mention_validator(BlockIdExt block_id, ton::Ed25519_PublicKey key, T time,
                                 td::Promise<td::Unit> promise) = 0;
  virtual void accept_block(BlockIdExt block_id, T time, td::Promise<td::Unit> promise) = 0;
  virtual void reject_block(BlockIdExt block_id, T time, td::Promise<td::Unit> promise) = 0;
};

}  // namespace validator

}  // namespace ton
