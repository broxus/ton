#include <tdutils/td/utils/port/path.h>
#include "scorer.hpp"
#include "scorer.h"

namespace ton {

namespace validator {

td::Status ScorerImpl::init() {
  auto path = db_root_ + "/scorer";
  td::mkdir(path).ensure();
  auto R = td::FileFd::open(path + "/scores.csv",
                            td::FileFd::Flags::Write | td::FileFd::Flags::Append | td::FileFd::Flags::Create);
  if (R.is_ok()) {
    file_ = R.move_as_ok();
    return td::Status::OK();
  } else {
    return R.move_as_error();
  }
}

td::Status ScorerImpl::flush() {
  return file_.sync();
}

void ScorerImpl::push_block(BlockIdExt block_id, ton::UnixTime time, td::Promise<td::Unit> promise) {
  auto it = timings_.find(block_id);
  if (it == timings_.end()) {
    return;
  }

  timings_.emplace(block_id, BlockTimings<>{time});
  LOG(INFO) << "Inserted new block id[" << time << "] " << block_id.to_str();
  promise.set_result(td::Unit{});
}

void ScorerImpl::mention_validator(BlockIdExt block_id, ton::Ed25519_PublicKey key, unsigned int time,
                                   td::Promise<td::Unit> promise) {
  auto it = timings_.find(block_id);
  if (it == timings_.end()) {
    return;
  }

  it->second.validator_signatures.emplace(key.as_bits256(), time);
  LOG(INFO) << "Rejected block[" << time << "] " << block_id.to_str() << " " << key.as_bits256().to_hex();
  promise.set_result(td::Unit{});
}

void ScorerImpl::accept_block(BlockIdExt block_id, ton::UnixTime time, td::Promise<td::Unit> promise) {
  auto it = timings_.find(block_id);
  if (it == timings_.end()) {
    return;
  }

  td::StringBuilder out;
  out << block_id.to_str() << "," << it->second.created_at << ",";

  for (const auto& [key, timing] : it->second.validator_signatures) {
    out << key.to_hex() << "," << timing;
  }

  out << "\n";
  write(out.as_cslice());

  // TODO: aggregate values for validators

  timings_.erase(block_id);
  LOG(INFO) << "Accepted block[" << time << "] " << block_id.to_str();
  promise.set_result(td::Unit{});
}

void ScorerImpl::reject_block(BlockIdExt block_id, ton::UnixTime time, td::Promise<td::Unit> promise) {
  auto it = timings_.find(block_id);
  if (it == timings_.end()) {
    return;
  }

  td::StringBuilder out;
  out << block_id.to_str() << "," << it->second.created_at << ",";

  for (const auto& [key, timing] : it->second.validator_signatures) {
    out << key.to_hex() << "," << timing;
  }

  out << "\n";
  write(out.as_cslice());

  timings_.erase(block_id);
  LOG(INFO) << "Rejected block[" << time << "] " << block_id.to_str();
  promise.set_result(td::Unit{});
}

void ScorerImpl::write(td::Slice slice) {
  file_.write(slice);
  if (++sync_counter_ > 1000) {
    sync_counter_ = 0;
    flush().ensure();
  }
}

td::actor::ActorOwn<Scorer<ton::UnixTime>> validator::ScorerFactory::create(std::string db_root) {
  return td::actor::create_actor<ScorerImpl>("scorer", db_root);
}

}  // namespace validator

}  // namespace ton
