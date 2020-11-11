#include "Abi.hpp"

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
  return object.get_string().str();
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

auto ContractAbi::create_function(std::string name) -> td::Result<Function> {
  auto it = functions.find(name);
  if (it == functions.end()) {
    return td::Status::Error(400, "function not found in contract abi");
  }
  auto& function = it->second;

  auto function_header = header;
  auto function_inputs = function.inputs;
  auto function_outputs = function.outputs;

  if (function.id.has_value()) {
    return Function{std::move(name), std::move(function_header), std::move(function_inputs),
                    std::move(function_outputs), function.id.value()};
  } else {
    return Function{std::move(name), std::move(function_header), std::move(function_inputs),
                    std::move(function_outputs)};
  }
}

auto param_from_string(const std::string& /*name*/, const std::string& type,
                       std::optional<std::vector<ParamRef>>&& components) -> td::Result<ParamRef> {
  constexpr td::Slice unknown_param_type = "unknown param type";
  constexpr td::Slice invalid_integer_size = "invalid integer size";
  constexpr td::Slice invalid_fixedbytes_size = "invalid fixedbytes size";
  constexpr td::Slice tuple_components_not_found = "tuple components not found";

  bool is_array = false;
  std::string_view main_type{type.data(), type.size()};
  if (const auto size = type.size(); size > 2) {
    if (type.compare(size - 2, 2, "[]")) {
      is_array = true;
      main_type = std::string_view{type.data(), size - 2};
    }
  } else {
    return td::Status::Error(400, unknown_param_type);
  }

  ParamRef result;

  //    time
  if (main_type == "time") {
    result = ParamRef{ParamTime{}};
  }  // expire
  else if (main_type == "expire") {
    result = ParamRef{ParamExpire{}};
  }  // pubkey
  else if (main_type == "pubkey") {
    result = ParamRef{ParamPublicKey{}};
  }  // int<M>
  else if (main_type.compare(0, 3, "int") == 0) {
    const td::Slice bits_str{main_type.data() + 3, main_type.size() - 3};
    TRY_RESULT(bits, td::to_integer_safe<uint32_t>(bits_str))
    if (bits < 1 || bits > 256) {
      return td::Status::Error(400, invalid_integer_size);
    }
    result = ParamRef{ParamInt{bits}};
  }  // uint<M>
  else if (main_type.compare(0, 4, "uint") == 0) {
    const td::Slice bits_str{main_type.data() + 4, main_type.size() - 4};
    TRY_RESULT(bits, td::to_integer_safe<uint32_t>(bits_str))
    if (bits < 1 || bits > 256) {
      return td::Status::Error(400, invalid_integer_size);
    }
    result = ParamRef{ParamUint{bits}};
  }  // bool
  else if (main_type == "bool") {
    result = ParamRef{ParamBool{}};
  }  // tuple
  else if (main_type == "tuple") {
    if (components->empty() || components.value().empty()) {
      return td::Status::Error(400, tuple_components_not_found);
    }
    result = ParamRef{ParamTuple{std::move(components.value())}};
  }  // bytes
  else if (main_type == "bytes") {
    result = ParamRef{ParamBytes{}};
  }  // fixedbytes<M>
  else if (main_type.compare(0, 10, "fixedbytes") == 0) {
    const td::Slice bytes_str{main_type.data() + 10, main_type.size() - 10};
    TRY_RESULT(bytes, td::to_integer_safe<uint32_t>(bytes_str))
    if (bytes < 1) {
      return td::Status::Error(400, invalid_fixedbytes_size);
    }
    result = ParamRef{ParamFixedBytes{bytes}};
  }  // address
  else if (main_type == "address") {
    result = ParamRef{ParamAddress{}};
  }  // map
  else if (main_type == "map") {
    // TODO: add support for map types
    return td::Status::Error(400, "map param type is not supported yet");
  }  // cell
  else if (main_type == "cell") {
    result = ParamRef{ParamCell{}};
  }  // ...other...
  else {
    return td::Status::Error(400, unknown_param_type);
  }

  if (is_array) {
    return ParamRef{ParamArray{std::move(result)}};
  } else {
    return result;
  }
}

auto abi_named_param_from_json(td::JsonValue& object) -> td::Result<std::pair<std::string, ParamRef>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Object))
  auto& root = object.get_object();

  std::optional<std::string> param_name{};
  std::optional<std::string> param_type{};
  std::optional<std::vector<ParamRef>> components{};
  for (auto& item : root) {
    auto key = item.first.str();
    auto& value = item.second;

    if (key == "name") {
      if (param_name.has_value()) {
        return td::Status::Error(400, "duplicate param name found");
      }

      TRY_RESULT_ASSIGN(param_name, string_from_json(key, value))
    } else if (key == "type") {
      if (param_type.has_value()) {
        return td::Status::Error(400, "duplicate param type found");
      }

      TRY_RESULT_ASSIGN(param_name, string_from_json(key, value))
    } else if (key == "components") {
      if (components.has_value()) {
        return td::Status::Error(400, "duplicate param components found");
      }

      TRY_STATUS(check_value_type(value, td::JsonValue::Type::Array))
      auto& components_array = value.get_array();

      components->reserve(components_array.size());
      for (auto& components_item : components_array) {
        TRY_RESULT(component, abi_param_from_json(components_item))
        components->emplace_back(std::move(component));
      }
    }
  }

  TRY_STATUS(check_missing_field("name", param_name))
  TRY_STATUS(check_missing_field("type", param_type))

  TRY_RESULT(param, param_from_string(param_name.value(), param_type.value(), std::move(components)))

  return std::make_pair(param_name.value(), std::move(param));
}

auto abi_param_from_json(td::JsonValue& object) -> td::Result<ParamRef> {
  TRY_RESULT(named_param, abi_named_param_from_json(object))
  return named_param.second;
}

auto abi_params_from_json(td::JsonValue& object) -> td::Result<std::vector<ParamRef>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  std::vector<ParamRef> params{};
  for (auto& item : array) {
    TRY_RESULT(param, abi_param_from_json(item))
    params.emplace_back(std::move(param));
  }

  return params;
}

auto abi_header_from_json(td::JsonValue& object) -> td::Result<HeaderParams> {
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
        result.emplace_back(std::piecewise_construct, std::forward_as_tuple(item_value),
                            std::forward_as_tuple(ParamTime{}));
      } else if (item_value == "expire") {
        result.emplace_back(std::piecewise_construct, std::forward_as_tuple(item_value),
                            std::forward_as_tuple(ParamExpire{}));
      } else if (item_value == "pubkey") {
        result.emplace_back(std::piecewise_construct, std::forward_as_tuple(item_value),
                            std::forward_as_tuple(ParamPublicKey{}));
      }
    } else if (item.type() == td::JsonValue::Type::Object) {
      TRY_RESULT(named_param, abi_named_param_from_json(item))
      result.emplace_back(std::piecewise_construct, std::forward_as_tuple(std::move(named_param.first)),
                          std::forward_as_tuple(std::move(named_param.second)));
    } else {
      return td::Status::Error(400, "Expected String or Object");
    }
  }

  return result;
}

auto abi_function_from_json(td::JsonValue& object) -> td::Result<FunctionAbi> {
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
      TRY_RESULT_ASSIGN(input_params, abi_params_from_json(value))
    } else if (key == "outputs") {
      TRY_RESULT_ASSIGN(output_params, abi_params_from_json(value))
    } else if (key == "id") {
      TRY_RESULT_ASSIGN(function_id, number_from_json<td::uint32>(key, value))
    }
  }

  TRY_STATUS(check_missing_field("name", function_name))
  TRY_STATUS(check_missing_field("inputs", input_params))
  TRY_STATUS(check_missing_field("outputs", output_params))

  return FunctionAbi{std::move(function_name.value()), std::move(input_params.value()),
                     std::move(output_params.value()), std::move(function_id)};
}

auto abi_functions_from_json(td::JsonValue& object) -> td::Result<std::unordered_map<std::string, FunctionAbi>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  std::unordered_map<std::string, FunctionAbi> functions{};
  functions.reserve(array.size());

  for (auto& item : array) {
    TRY_RESULT(function, abi_function_from_json(item));
    if (functions.find(function.name) != functions.end()) {
      return td::Status::Error(400, "duplicate function found");
    }
    functions.emplace(std::piecewise_construct, std::forward_as_tuple(function.name),
                      std::forward_as_tuple(std::move(function)));
  }

  return functions;
}

auto contract_abi_from_json(td::JsonValue& object) -> td::Result<ContractAbi> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Object))
  auto& root = object.get_object();

  ContractAbi abi{};

  for (auto& item : root) {
    auto key = item.first.str();
    auto& value = item.second;

    if (key == "ABI version") {
      TRY_RESULT(abi_version, number_from_json<td::int32>(key, value))
      if (abi_version != 2) {
        return td::Status::Error("only ABI version 2 is supported");
      }
    } else if (key == "header") {
      if (!abi.header.empty()) {
        return td::Status::Error("duplicate header field");
      }

      TRY_RESULT(header_params, abi_header_from_json(value))
      abi.header = std::move(header_params);
    } else if (key == "functions") {
      if (!abi.functions.empty()) {
        return td::Status::Error("duplicate functions field");
      }

      TRY_RESULT(functions, abi_functions_from_json(value))
      abi.functions = std::move(functions);
    }
  }

  return abi;
}

}  // namespace ftabi
