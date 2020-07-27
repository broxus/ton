#pragma once

#include "validator/validator.h"
#include "adnl/adnl.h"

namespace ton {

namespace validator {

class ScorerFactory {
 public:
  static td::actor::ActorOwn<Scorer<ton::UnixTime>> create(std::string db_root);
};

}  // namespace validator

}  // namespace ton
