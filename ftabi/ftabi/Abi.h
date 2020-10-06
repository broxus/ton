#pragma once

#include "ftabi/utils.h"

#include <td/utils/JsonBuilder.h>

namespace ftabi {

auto param_from_string(const std::string &name, const std::string &string) -> td::Result<ParamRef>;

auto header_params_from_json(td::JsonValue& object) -> td::Result<HeaderParams>;
auto param_from_json(td::JsonValue& object) -> td::Result<ParamRef>;
auto params_from_json(td::JsonValue& object) -> td::Result<std::vector<ParamRef>>;
auto function_from_json(td::JsonValue& object) -> td::Result<td::Ref<Function>>;
auto functions_from_json(td::JsonValue& object) -> td::Result<std::vector<td::Ref<Function>>>;

class Abi {
 public:
  auto from_json(std::string&& encoded) -> td::Result<Abi>;

 private:
  explicit Abi();

  bool set_time_{true};
  HeaderParams header_params_{};
  std::vector<Function> functions_{};
};

}  // namespace ftabi
