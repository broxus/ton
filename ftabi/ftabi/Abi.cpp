#include "Abi.hpp"

#include <td/utils/base64.h>

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

auto field_string_from_json(const std::string& name, td::JsonValue& object) -> td::Result<std::string> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String, name))
  return object.get_string().str();
}

template <typename T>
auto field_number_from_json(const std::string& name, td::JsonValue& object) -> td::Result<T> {
  if (object.type() == td::JsonValue::Type::String) {
    return td::to_integer_safe<T>(object.get_string());
  }
  if (object.type() == td::JsonValue::Type::Number) {
    return td::to_integer_safe<T>(object.get_number());
  }
  return td::Status::Error(400, PSLICE() << "Field \"" << name << "\" must be a Number");
}

template <typename T>
auto number_from_json(td::JsonValue& object) -> td::Result<T> {
  if (object.type() == td::JsonValue::Type::String) {
    return td::to_integer_safe<T>(object.get_string());
  }
  if (object.type() == td::JsonValue::Type::Number) {
    return td::to_integer_safe<T>(object.get_number());
  }
  return td::Status::Error(400, "Expected string or Number");
}

auto big_int_from_json(td::JsonValue& object) -> td::Result<td::BigInt256> {
  if (object.type() == td::JsonValue::Type::Number) {
    TRY_RESULT(number, td::to_integer_safe<int64_t>(object.get_number()))
    return td::make_bigint(number);
  }
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String))
  auto value = object.get_string();
  if (value.empty()) {
    return td::Status::Error(400, "empty invalid bigint value");
  }

  const auto is_negative = value[0] == '-';
  const auto is_hex = value.size() > (is_negative + 2u) &&  //
                      value[is_negative] == '0' && (value[is_negative + 1u] | 0x20u) == 'x';
  const auto prefix_length = is_negative + is_hex * 2u;

  const auto* str = value.data() + prefix_length;
  const auto str_length = static_cast<int>(value.size() - prefix_length);

  td::BigInt256 number;
  if (is_hex && number.parse_hex(str, str_length) < 0) {
    return td::Status::Error(400, "invalid hex value");
  } else if (!is_hex && number.parse_dec(str, str_length) < 0) {
    return td::Status::Error(400, "invalid decimal value");
  }
  if (is_negative) {
    number.negate();
  }
  return number;
}

auto bytes_str_from_json(td::JsonValue& object) -> td::Result<std::string> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String))
  return base64_decode(object.get_string());
}

auto bytes_from_json(td::JsonValue& object) -> td::Result<std::vector<uint8_t>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String))
  TRY_RESULT(decoded, base64_decode(object.get_string()));
  std::vector<uint8_t> result;
  result.resize(decoded.size());
  std::memcpy(result.data(), decoded.data(), decoded.size());
  return result;
}

auto secure_bytes_from_json(td::JsonValue& object) -> td::Result<td::SecureString> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String))
  return base64_decode_secure(object.get_string());
}

auto boc_from_json(td::JsonValue& object) -> td::Result<td::Ref<vm::Cell>> {
  TRY_RESULT(bytes, bytes_str_from_json(object))
  return vm::std_boc_deserialize(bytes, true);
}

auto address_from_json(td::JsonValue& object) -> td::Result<block::StdAddress> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::String))

  block::StdAddress result;
  if (!result.parse_addr(object.get_string())) {
    return td::Status::Error(400, "invalid address");
  }
  return result;
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

auto extract_array_from_type(const std::string& type)
    -> td::Result<std::pair<std::string_view, std::optional<uint32_t>>> {
  const auto* begin = type.data();
  const auto size = type.size();
  if (size < 3 || type[size - 1] != ']') {
    return std::make_pair(std::string_view{begin, size}, std::nullopt);
  }
  if (type[size - 2] == '[') {
    return std::make_pair(std::string_view{begin, size - 2}, 0u);
  }

  const auto* size_str_end = begin + size - 1;    // last ']' position
  const auto* size_str_begin = size_str_end - 1;  // previous char

  while (size_str_begin != begin && *size_str_begin != '[') {
    --size_str_begin;
  }
  if (*size_str_begin != '[') {
    return td::Status::Error(400, "invalid param type. array expected");
  }
  TRY_RESULT(fixed_size, td::to_integer_safe<uint32_t>(td::Slice{size_str_begin, size_str_end}))

  const auto basic_type_size = static_cast<size_t>(size_str_begin - begin);
  return std::make_pair(std::string_view{begin, basic_type_size}, fixed_size);
}

auto param_from_string(const std::string& /*name*/, const std::string& type,
                       std::optional<std::vector<ParamRef>>&& components) -> td::Result<ParamRef> {
  constexpr td::Slice unknown_param_type = "unknown param type";
  constexpr td::Slice invalid_integer_size = "invalid integer size";
  constexpr td::Slice invalid_fixedbytes_size = "invalid fixedbytes size";
  constexpr td::Slice tuple_components_not_found = "tuple components not found";

  TRY_RESULT(parsed_type, extract_array_from_type(type))
  const auto& basic_type = parsed_type.first;
  const auto& array_size = parsed_type.second;

  ParamRef result;

  //    time
  if (basic_type == "time") {
    result = ParamRef{ParamTime{}};
  }  // expire
  else if (basic_type == "expire") {
    result = ParamRef{ParamExpire{}};
  }  // pubkey
  else if (basic_type == "pubkey") {
    result = ParamRef{ParamPublicKey{}};
  }  // int<M>
  else if (basic_type.compare(0, 3, "int") == 0) {
    const td::Slice bits_str{basic_type.data() + 3, basic_type.size() - 3};
    TRY_RESULT(bits, td::to_integer_safe<uint32_t>(bits_str))
    if (bits < 1 || bits > 256) {
      return td::Status::Error(400, invalid_integer_size);
    }
    result = ParamRef{ParamInt{bits}};
  }  // uint<M>
  else if (basic_type.compare(0, 4, "uint") == 0) {
    const td::Slice bits_str{basic_type.data() + 4, basic_type.size() - 4};
    TRY_RESULT(bits, td::to_integer_safe<uint32_t>(bits_str))
    if (bits < 1 || bits > 256) {
      return td::Status::Error(400, invalid_integer_size);
    }
    result = ParamRef{ParamUint{bits}};
  }  // bool
  else if (basic_type == "bool") {
    result = ParamRef{ParamBool{}};
  }  // tuple
  else if (basic_type == "tuple") {
    if (!components.has_value() || components.value().empty()) {
      return td::Status::Error(400, tuple_components_not_found);
    }
    result = ParamRef{ParamTuple{std::move(components.value())}};
  }  // bytes
  else if (basic_type == "bytes") {
    result = ParamRef{ParamBytes{}};
  }  // fixedbytes<M>
  else if (basic_type.compare(0, 10, "fixedbytes") == 0) {
    const td::Slice bytes_str{basic_type.data() + 10, basic_type.size() - 10};
    TRY_RESULT(bytes, td::to_integer_safe<uint32_t>(bytes_str))
    if (bytes < 1) {
      return td::Status::Error(400, invalid_fixedbytes_size);
    }
    result = ParamRef{ParamFixedBytes{bytes}};
  }  // gram
  else if (basic_type == "gram") {
    result = ParamRef{ParamGram{}};
  }  // address
  else if (basic_type == "address") {
    result = ParamRef{ParamAddress{}};
  }  // map
  else if (basic_type == "map") {
    // TODO: add support for map types
    return td::Status::Error(400, "map param type is not supported yet");
  }  // cell
  else if (basic_type == "cell") {
    result = ParamRef{ParamCell{}};
  }  // ...other...
  else {
    return td::Status::Error(400, unknown_param_type);
  }

  if (array_size.has_value() && array_size.value() > 0) {
    return ParamRef{ParamFixedArray{std::move(result), array_size.value()}};
  } else if (array_size.has_value()) {
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

      TRY_RESULT_ASSIGN(param_name, field_string_from_json(key, value))
    } else if (key == "type") {
      if (param_type.has_value()) {
        return td::Status::Error(400, "duplicate param type found");
      }

      TRY_RESULT_ASSIGN(param_type, field_string_from_json(key, value))
    } else if (key == "components") {
      if (components.has_value()) {
        return td::Status::Error(400, "duplicate param components found");
      }

      TRY_STATUS(check_value_type(value, td::JsonValue::Type::Array))
      auto& components_array = value.get_array();

      components.emplace();
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
  params.reserve(array.size());
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
      TRY_RESULT_ASSIGN(function_name, field_string_from_json(key, value))
    } else if (key == "inputs") {
      TRY_RESULT_ASSIGN(input_params, abi_params_from_json(value))
    } else if (key == "outputs") {
      TRY_RESULT_ASSIGN(output_params, abi_params_from_json(value))
    } else if (key == "id") {
      TRY_RESULT_ASSIGN(function_id, field_number_from_json<td::uint32>(key, value))
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
      TRY_RESULT(abi_version, field_number_from_json<td::int32>(key, value))
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

auto value_tuple_from_json(const ParamRef& param, td::JsonValue& object) -> td::Result<ValueRef> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  const auto& param_tuple = param->as<ParamTuple>();
  if (param_tuple.items.size() != array.size()) {
    return td::Status::Error(400, "invalid tuple values");
  }

  std::vector<ValueRef> values;
  values.reserve(param_tuple.items.size());
  for (size_t i = 0; i < array.size(); ++i) {
    TRY_RESULT(value, value_from_json(param_tuple.items[i], array[i]))
    values.emplace_back(std::move(value));
  }

  return ValueRef{ValueTuple{param, std::move(values)}};
}

auto value_array_from_json(const ParamRef& param, td::JsonValue& object) -> td::Result<ValueRef> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  const auto& item_param = param->as<ParamArray>().param;

  std::vector<ValueRef> values;
  values.reserve(array.size());
  for (auto& item : array) {
    TRY_RESULT(value, value_from_json(item_param, item))
    values.emplace_back(std::move(value));
  }

  return ValueRef{ValueArray{param, std::move(values)}};
}

auto value_fixed_array_from_json(const ParamRef& param, td::JsonValue& object) -> td::Result<ValueRef> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  const auto& param_fixed = param->as<ParamFixedArray>();

  if (array.size() != param_fixed.size) {
    return td::Status::Error("invalid length of fixed array value");
  }

  std::vector<ValueRef> values;
  values.reserve(array.size());
  for (auto& item : array) {
    TRY_RESULT(value, value_from_json(param_fixed.param, item))
    values.emplace_back(std::move(value));
  }

  return ValueRef{ValueFixedArray{param, std::move(values)}};
}

auto value_pubkey_from_json(const ParamRef& param, td::JsonValue& object) -> td::Result<ValueRef> {
  td::optional<td::SecureString> key{};
  if (object.type() != td::JsonValue::Type::Null) {
    TRY_RESULT(raw, secure_bytes_from_json(object))
    key.emplace(std::move(raw));
  }
  return ValueRef{ValuePublicKey{param, std::move(key)}};
}

auto value_from_json(ParamRef param, td::JsonValue& object) -> td::Result<ValueRef> {
  switch (param->type()) {
    case ParamType::Uint:
    case ParamType::Int: {
      TRY_RESULT(number, big_int_from_json(object))
      return ValueRef{ValueInt{param, number}};
    }
    case ParamType::Bool: {
      TRY_STATUS(check_value_type(object, td::JsonValue::Type::Boolean))
      return ValueRef{ValueBool{param, object.get_boolean()}};
    }
    case ParamType::Tuple:
      return value_tuple_from_json(param, object);
    case ParamType::Array:
      return value_array_from_json(param, object);
    case ParamType::FixedArray:
      return value_fixed_array_from_json(param, object);
    case ParamType::Cell: {
      TRY_RESULT(cell, boc_from_json(object))
      return ValueRef{ValueCell{param, cell}};
    }
    case ParamType::Map:
      // TODO: add support for map types
      return td::Status::Error(400, "map param type is not supported yet");
    case ParamType::Address: {
      TRY_RESULT(address, address_from_json(object))
      return ValueRef{ValueAddress{param, address}};
    }
    case ParamType::Bytes:
    case ParamType::FixedBytes: {
      TRY_RESULT(bytes, bytes_from_json(object))
      return ValueRef{ValueBytes{param, bytes}};
    }
    case ParamType::Gram: {
      TRY_RESULT(number, big_int_from_json(object))
      return ValueRef{ValueGram{param, number}};
    }
    case ParamType::Time: {
      TRY_RESULT(time, number_from_json<uint64_t>(object))
      return ValueRef{ValueTime{param, time}};
    }
    case ParamType::Expire: {
      TRY_RESULT(expire, number_from_json<uint32_t>(object))
      return ValueRef{ValueExpire{param, expire}};
    }
    case ParamType::PublicKey:
      return value_pubkey_from_json(param, object);
    default:
      UNREACHABLE();
  }
}

auto function_call_header_from_json(const HeaderParams& params, td::JsonValue& object) -> td::Result<HeaderValues> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Object))
  auto& root = object.get_object();

  std::unordered_map<std::string, td::JsonValue> root_map;
  root_map.reserve(root.size());
  for (auto&& item : root) {
    root_map.emplace(std::piecewise_construct, std::forward_as_tuple(item.first.str()),
                     std::forward_as_tuple(std::move(item.second)));
  }

  std::unordered_map<std::string, ValueRef> result;
  for (const auto& [name, param] : params) {
    auto it = root_map.find(name);
    if (it != root_map.end()) {
      TRY_RESULT(value, value_from_json(param, it->second))
    }
  }
  return result;
}

auto function_call_inputs_from_json(const std::vector<ParamRef>& params, td::JsonValue& object)
    -> td::Result<std::vector<ValueRef>> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Array))
  auto& array = object.get_array();

  if (array.size() != params.size()) {
    return td::Status::Error(400, "invalid function call arguments passed");
  }

  std::vector<ValueRef> values;
  values.reserve(array.size());
  for (size_t i = 0; i < array.size(); ++i) {
    TRY_RESULT(value, value_from_json(params[i], array[i]));
    values.emplace_back(std::move(value));
  }

  return values;
}

auto function_call_from_json(Function& function, td::JsonValue& object) -> td::Result<FunctionCall> {
  TRY_STATUS(check_value_type(object, td::JsonValue::Type::Object))
  auto& root = object.get_object();

  HeaderValues header{};
  InputValues inputs{};
  auto internal = false;
  td::optional<td::Ed25519::PrivateKey> private_key{};

  for (auto& item : root) {
    auto key = item.first.str();
    auto& value = item.second;

    if (key == "header") {
      TRY_RESULT(parsed_header, function_call_header_from_json(function.header(), value))
      header = std::move(parsed_header);
    } else if (key == "inputs") {
      TRY_RESULT(parsed_inputs, function_call_inputs_from_json(function.inputs(), value))
      inputs = std::move(parsed_inputs);
    } else if (key == "internal") {
      TRY_STATUS(check_value_type(value, td::JsonValue::Type::Boolean))
      internal = value.get_boolean();
    } else if (key == "key" && value.type() != td::JsonValue::Type::Null) {
      TRY_RESULT(raw, secure_bytes_from_json(value))
      private_key.emplace(std::move(raw));
    }
  }

  return FunctionCall{std::move(header), std::move(inputs), internal, std::move(private_key)};
}

}  // namespace ftabi
