#include "Abi.h"

namespace ftabi {
namespace {
auto to_string(td::JsonValue::Type type) -> const char* {
  switch (type) {
    case td::JsonValue::Type::Array:
      return "Array";
    case td::JsonValue::Type::String:
      return "String";
    case td::JsonValue::Type::Object:
      return "Object";
    case td::JsonValue::Type::Boolean:
      return "Boolean";
    case td::JsonValue::Type::Number:
      return "Number";
    case td::JsonValue::Type::Null:
      return "Null";
    default:
      return "Unknown";
  }
}

auto check_value_type(const td::JsonValue& object, td::JsonValue::Type requested) -> td::Status {
  if (requested == object.type()) {
    return td::Status::OK();
  }
  return td::Status::Error(400, PSLICE() << "Expected " << to_string(requested));
}

auto check_value_type(const td::JsonValue& object, td::JsonValue::Type requested, const std::string& name)
    -> td::Status {
  if (requested == object.type()) {
    return td::Status::OK();
  }
  return td::Status::Error(400, PSLICE() << "Field \"" << name << "\" must be a " << to_string(requested));
}

template <typename T>
auto check_missing_field(const std::string& name, const std::optional<T>& value) -> td::Status {
  if (!value.has_value()) {
    return td::Status::Error(400, PSLICE() << "Missing field \"" << name << "\"");
  }
  return td::Status::OK();
}

auto string_from_json(const std::string& name, td::JsonValue& object) -> td::Result<std::string> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String, name))
  return object.get_string();
}

template <typename T>
auto number_from_json(const std::string& name, td::JsonValue& object) -> td::Result<T> {
  if (object.type() == td::JsonValue::Type::String) {
    return td::to_integer_safe<T>(object.get_string());
  }
  if (object.type() == td::JsonValue::Type::Number) {
    return td::to_integer_safe<T>(object.get_number());
  }

  return td::Status::Error(400, PSLICE() << "Field \"" << name << "\" must be a Number");
}
}  // namespace

auto header_params_from_json(td::JsonValue& object) -> td::Result<HeaderParams> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  HeaderParams result{};
  std::unordered_set<std::string> headers;

  for (auto& item : array) {
    if (item.type() == td::JsonValue::Type::String) {
      auto item_value = item.get_string().str();
      if (headers.find(item_value) != headers.end()) {
        return td::Status::Error(400, "duplicated header found");
      }
      headers.emplace(item_value);

      if (item_value == "time") {
        result.emplace_back(ParamTime{item_value});
      } else if (item_value == "expire") {
        result.emplace_back(ParamExpire{item_value});
      } else if (item_value == "pubkey") {
        result.emplace_back(ParamPublicKey{item_value});
      }
    } else if (item.type() == td::JsonValue::Type::Object) {
      TRY_RESULT(param, param_from_json(item))
      result.emplace_back(std::move(param));
    } else {
      return td::Status::Error(400, "Expected String or Object");
    }
  }

  return result;
}

auto param_from_json(td::JsonValue& object) -> td::Result<ParamRef> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Object))
  auto& root = object.get_object();

  std::optional<std::string> param_name{};
  std::optional<std::string> param_type{};
  std::optional<std::vector<ParamRef>> components{};
  for (auto& item : root) {
    auto key = item.first.str();
    auto& value = item.second;

    if (key == "name") {
      TRY_RESULT_ASSIGN(param_name, string_from_json(key, value))
    } else if (key == "type") {
      TRY_RESULT_ASSIGN(param_name, string_from_json(key, value))
    } else if (key == "components") {
      // TODO: parse components
    }
  }


}

auto params_from_json(td::JsonValue& object) -> td::Result<std::vector<ParamRef>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  std::vector<ParamRef> result{};
  std::unordered_set<std::string> params{};
  for (auto& item : array) {
    TRY_RESULT(param, param_from_json(item))
    if (params.find(param->name()) != params.end()) {
      return td::Status::Error(400, "duplicate param found");
    }
    params.emplace(param->name());

    result.emplace_back(std::move(param));
  }

  return result;
}

auto function_from_json(td::JsonValue& object) -> td::Result<td::Ref<Function>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Object))
  auto& root = object.get_object();

  std::optional<std::string> function_name{};
  std::optional<InputParams> input_params{};
  std::optional<OutputParams> output_params{};
  std::optional<td::uint32> function_id{};

  for (auto& item : root) {
    auto key = item.first.str();
    auto& value = item.second;

    if (key == "name") {
      TRY_RESULT_ASSIGN(function_name, string_from_json(key, value))
    } else if (key == "inputs") {
      TRY_RESULT_ASSIGN(input_params, params_from_json(value))
    } else if (key == "outputs") {
      TRY_RESULT_ASSIGN(output_params, params_from_json(value))
    } else if (key == "id") {
      TRY_RESULT_ASSIGN(function_id, number_from_json<td::uint32>(key, value))
    }
  }

  TRY_STATUS(check_missing_field("name", function_name))
  TRY_STATUS(check_missing_field("inputs", input_params))
  TRY_STATUS(check_missing_field("outputs", output_params))
  if (function_id.has_value()) {
    return td::Ref{Function{std::move(function_name.value()),
                            {},
                            std::move(input_params.value()),
                            std::move(output_params.value()),
                            function_id.value()}};
  } else {
    return td::Ref{Function{
        std::move(function_name.value()), {}, std::move(input_params.value()), std::move(output_params.value())}};
  }
}

auto functions_from_json(td::JsonValue& object) -> td::Result<std::vector<td::Ref<Function>>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  std::vector<td::Ref<Function>> result{};
  std::unordered_set<std::string> functions{};

  for (auto& item : array) {
    TRY_RESULT(function, function_from_json(item));
    if (functions.find(function->name()) != functions.end()) {
      return td::Status::Error(400, "duplicate function found");
    }
    functions.emplace(function->name());
    result.emplace_back(std::move(function));
  }

  return result;
}

Abi::Abi() {
}

auto Abi::from_json(std::string&& encoded) -> td::Result<Abi> {
  TRY_RESULT(json, td::json_decode(td::MutableSlice(encoded)))

  Abi abi{};

  auto& root = json.get_object();
  for (auto& item : root) {
    auto key = item.first.str();
    auto& value = item.second;

    if (key == "ABI version") {
      TRY_RESULT(abi_version, number_from_json<td::int32>(key, value))
      if (abi_version != 2) {
        return td::Status::Error("only ABI version 2 is supported");
      }
    } else if (key == "header") {
      if (!abi.header_params_.empty()) {
        return td::Status::Error("duplicate header field");
      }

      TRY_RESULT(header_params, header_params_from_json(value))
      abi.header_params_ = std::move(header_params);
    } else if (key == "functions") {
    }
  }

  return td::Result<Abi>();
}

}  // namespace ftabi
