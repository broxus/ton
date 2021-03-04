#include "AbiDto.h"

#include "tonlib/TonlibError.h"

#include "td/utils/overloaded.h"

namespace tonlib {

auto parse_param(tonlib_api::ftabi_Param& param) -> td::Result<ftabi::ParamRef> {
  using ReturnType = td::Result<ftabi::ParamRef>;
  return downcast_call2<ReturnType>(
      param,
      td::overloaded(  //
          [](const tonlib_api::ftabi_paramUint& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamUint{static_cast<uint32_t>(param.size_)}};
          },
          [](const tonlib_api::ftabi_paramInt& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamInt{static_cast<uint32_t>(param.size_)}};
          },
          [](const tonlib_api::ftabi_paramBool& param) -> ReturnType { return ftabi::ParamRef{ftabi::ParamBool{}}; },
          [](const tonlib_api::ftabi_paramTuple& param) -> ReturnType {
            std::vector<ftabi::ParamRef> itemTypes{};
            itemTypes.reserve(param.itemTypes_.size());
            for (const auto& item : param.itemTypes_) {
              TRY_RESULT(itemType, parse_param(*item))
              itemTypes.emplace_back(std::move(itemType));
            }
            return ftabi::ParamRef{ftabi::ParamTuple{std::move(itemTypes)}};
          },
          [](const tonlib_api::ftabi_paramArray& param) -> ReturnType {
            TRY_RESULT(itemType, parse_param(*param.itemType_))
            return ftabi::ParamRef{ftabi::ParamArray{std::move(itemType)}};
          },
          [](const tonlib_api::ftabi_paramFixedArray& param) -> ReturnType {
            TRY_RESULT(itemType, parse_param(*param.itemType_))
            return ftabi::ParamRef{ftabi::ParamFixedArray{std::move(itemType), static_cast<uint32_t>(param.size_)}};
          },
          [](const tonlib_api::ftabi_paramCell& param) -> ReturnType { return ftabi::ParamRef{ftabi::ParamCell{}}; },
          [](const tonlib_api::ftabi_paramMap& param) -> ReturnType {
            TRY_RESULT(keyType, parse_param(*param.keyType_))
            TRY_RESULT(valueType, parse_param(*param.valueType_))
            return ftabi::ParamRef{ftabi::ParamMap{std::move(keyType), std::move(valueType)}};
          },
          [](const tonlib_api::ftabi_paramAddress& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamAddress{}};
          },
          [](const tonlib_api::ftabi_paramBytes& param) -> ReturnType { return ftabi::ParamRef{ftabi::ParamBytes{}}; },
          [](const tonlib_api::ftabi_paramFixedBytes& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamFixedBytes{static_cast<size_t>(param.size_)}};
          },
          [](const tonlib_api::ftabi_paramGram& param) -> ReturnType { return ftabi::ParamRef{ftabi::ParamGram{}}; },
          [](const tonlib_api::ftabi_paramTime& param) -> ReturnType { return ftabi::ParamRef{ftabi::ParamTime{}}; },
          [](const tonlib_api::ftabi_paramExpire& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamExpire{}};
          },
          [](const tonlib_api::ftabi_paramPublicKey& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamPublicKey{}};
          }));
}

auto parse_params(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Param>>& params)
    -> td::Result<std::vector<ftabi::ParamRef>> {
  std::vector<ftabi::ParamRef> result{};
  result.reserve(params.size());
  for (auto& item : params) {
    if (item == nullptr) {
      return TonlibError::EmptyField("params[i]");
    }
    TRY_RESULT(param, parse_param(*item))
    result.emplace_back(std::move(param));
  }
  return std::move(result);
}

auto parse_named_param(tonlib_api::ftabi_namedParam& named_param) -> td::Result<NamedParam> {
  TRY_RESULT(value, parse_param(*named_param.param_))
  return std::make_pair(named_param.name_, std::move(value));
}

auto parse_named_params(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedParam>>& params)
    -> td::Result<std::vector<NamedParam>> {
  std::vector<NamedParam> result{};
  result.reserve(params.size());
  for (auto& item : params) {
    if (item == nullptr) {
      return TonlibError::EmptyField("params[i]");
    }
    TRY_RESULT(param, parse_named_param(*item))
    result.emplace_back(std::move(param));
  }
  return std::move(result);
}

td::Result<ftabi::ValueRef> parse_value(tonlib_api::ftabi_Value& value) {
  using ReturnType = td::Result<ftabi::ValueRef>;
  return downcast_call2<ReturnType>(
      value,
      td::overloaded(  //
          [](const tonlib_api::ftabi_valueInt& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            return ftabi::ValueRef{ftabi::ValueInt(std::move(param), td::make_bigint(value.value_))};
          },
          [](const tonlib_api::ftabi_valueBigInt& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            td::BigInt256 data{};
            data.import_bytes(reinterpret_cast<const uint8_t*>(value.value_.data()), value.value_.size(),
                              param->type() == ftabi::ParamType::Int);
            return ftabi::ValueRef{ftabi::ValueInt(std::move(param), data)};
          },
          [](const tonlib_api::ftabi_valueBool& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            return ftabi::ValueRef{ftabi::ValueBool(std::move(param), value.value_)};
          },
          [](const tonlib_api::ftabi_valueTuple& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            std::vector<ftabi::ValueRef> values{};
            values.reserve(value.values_.size());
            for (auto& item : value.values_) {
              TRY_RESULT(itemValue, parse_value(*item))
              values.emplace_back(std::move(itemValue));
            }
            return ftabi::ValueRef{ftabi::ValueTuple(std::move(param), std::move(values))};
          },
          [](const tonlib_api::ftabi_valueArray& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            std::vector<ftabi::ValueRef> values{};
            values.reserve(value.values_.size());
            for (auto& item : value.values_) {
              TRY_RESULT(itemValue, parse_value(*item))
              values.emplace_back(std::move(itemValue));
            }
            return ftabi::ValueRef{ftabi::ValueArray(std::move(param), std::move(values))};
          },
          [](const tonlib_api::ftabi_valueCell& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            TRY_RESULT(cell, from_bytes(value.value_->bytes_));
            return ftabi::ValueRef{ftabi::ValueCell(std::move(param), std::move(cell))};
          },
          [](const tonlib_api::ftabi_valueMap& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            std::vector<std::pair<ftabi::ValueRef, ftabi::ValueRef>> values{};
            values.reserve(value.values_.size());
            for (const auto& item : value.values_) {
              TRY_RESULT(keyValue, parse_value(*item->key_))
              TRY_RESULT(valueValue, parse_value(*item->value_))
              values.emplace_back(std::make_pair(std::move(keyValue), std::move(valueValue)));
            }
            return ftabi::ValueRef{ftabi::ValueMap(std::move(param), std::move(values))};
          },
          [](const tonlib_api::ftabi_valueAddress& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            const auto& account_address = value.value_->account_address_;
            TRY_RESULT(address, get_account_address(td::Slice(account_address.data(), account_address.size())))
            return ftabi::ValueRef{ftabi::ValueAddress(std::move(param), address)};
          },
          [](const tonlib_api::ftabi_valueBytes& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            std::vector<uint8_t> bytes;
            bytes.resize(value.value_.size());
            std::memcpy(bytes.data(), value.value_.data(), value.value_.size());
            return ftabi::ValueRef{ftabi::ValueBytes(std::move(param), std::move(bytes))};
          },
          [](const tonlib_api::ftabi_valueGram& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            return ftabi::ValueRef{ftabi::ValueGram(std::move(param), td::make_bigint(value.value_))};
          },
          [](const tonlib_api::ftabi_valueTime& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            return ftabi::ValueRef{ftabi::ValueTime(std::move(param), static_cast<uint64_t>(value.value_))};
          },
          [](const tonlib_api::ftabi_valueExpire& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            return ftabi::ValueRef{ftabi::ValueExpire(std::move(param), static_cast<uint32_t>(value.value_))};
          },
          [](const tonlib_api::ftabi_valuePublicKey& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            return ftabi::ValueRef{
                ftabi::ValuePublicKey(std::move(param), td::optional<td::SecureString>(value.value_.copy()))};
          }));
}

auto parse_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>& values)
    -> td::Result<std::vector<ftabi::ValueRef>> {
  std::vector<ftabi::ValueRef> result{};
  result.reserve(values.size());
  for (auto& item : values) {
    if (item == nullptr) {
      return TonlibError::EmptyField("values[i]");
    }
    TRY_RESULT(value, parse_value(*item))
    result.emplace_back(std::move(value));
  }
  return std::move(result);
}

auto parse_named_value(tonlib_api::ftabi_namedValue& named_value)
    -> td::Result<std::pair<std::string, ftabi::ValueRef>> {
  TRY_RESULT(value, parse_value(*named_value.value_))
  return std::make_pair(named_value.name_, std::move(value));
}

auto parse_named_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>>& values)
    -> td::Result<std::vector<std::pair<std::string, ftabi::ValueRef>>> {
  std::vector<std::pair<std::string, ftabi::ValueRef>> result{};
  result.reserve(values.size());
  for (auto& item : values) {
    if (item == nullptr) {
      return TonlibError::EmptyField("values[i]");
    }
    TRY_RESULT(value, parse_named_value(*item))
    result.emplace_back(std::move(value));
  }
  return std::move(result);
}

auto parse_header_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>>& values)
    -> td::Result<std::unordered_map<std::string, ftabi::ValueRef>> {
  std::unordered_map<std::string, ftabi::ValueRef> result{};
  result.reserve(values.size());
  for (auto& item : values) {
    if (item == nullptr) {
      return TonlibError::EmptyField("values[i]");
    }
    TRY_RESULT(named_value, parse_named_value(*item))
    result.emplace(std::make_pair(named_value.first, std::move(named_value.second)));
  }
  return std::move(result);
}

auto parse_function(const tonlib_api::ftabi_function& value) -> td::Result<td::Ref<ftabi::Function>> {
  auto name = value.name_;
  TRY_RESULT(header, parse_named_params(value.header_params_))
  TRY_RESULT(inputs, parse_params(value.input_params_))
  TRY_RESULT(outputs, parse_params(value.output_params_))
  return td::Ref<ftabi::Function>{
      ftabi::Function(std::move(name), std::move(header), std::move(inputs), std::move(outputs))};
}

auto parse_function_call(const ftabi::Function& function, tonlib_api_ptr<tonlib_api::ftabi_FunctionCall>& value)
    -> td::Result<td::Ref<ftabi::FunctionCall>> {
  using ReturnType = td::Result<td::Ref<ftabi::FunctionCall>>;
  return downcast_call2<ReturnType>(
      *value,
      td::overloaded(  //
          [&function](tonlib_api::ftabi_functionCallJson& value) -> ReturnType {
            TRY_RESULT(json, td::json_decode(td::MutableSlice{value.value_}))
            TRY_RESULT(call, ftabi::function_call_from_json(function, json));
            return td::Ref<ftabi::FunctionCall>{call};
          },
          [](const tonlib_api::ftabi_functionCallExternal& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            return td::Ref<ftabi::FunctionCall>{ftabi::FunctionCall(std::move(headerValues), std::move(inputValues))};
          },
          [](tonlib_api::ftabi_functionCallExternalSigned& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            return td::Ref<ftabi::FunctionCall>{ftabi::FunctionCall(
                std::move(headerValues), std::move(inputValues), false,
                td::optional<td::Ed25519::PrivateKey>{td::Ed25519::PrivateKey(std::move(value.key_))})};
          },
          [](const tonlib_api::ftabi_functionCallInternal& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            return td::Ref<ftabi::FunctionCall>{ftabi::FunctionCall(std::move(headerValues), std::move(inputValues),
                                                                    true, td::optional<td::Ed25519::PrivateKey>{})};
          }));
}

auto compute_function_signature(const tonlib_api::ftabi_computeFunctionSignature& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(inputs, parse_params(request.inputs_))
  TRY_RESULT(outputs, parse_params(request.outputs_))
  auto signature = ftabi::compute_function_signature(request.name_, inputs, outputs);
  return tonlib_api::make_object<tonlib_api::ftabi_functionSignature>(std::move(signature));
}

auto compute_function_id(const std::string& name, const ftabi::InputParams& inputs, const ftabi::OutputParams& outputs)
    -> std::pair<uint32_t, uint32_t> {
  const auto signature = ftabi::compute_function_signature(name, inputs, outputs);
  const auto id = ftabi::compute_function_id(signature);
  const auto input_id = static_cast<int32_t>(id & 0x7fffffffu);
  const auto output_id = static_cast<int32_t>(id | 0x80000000u);
  return std::make_pair(input_id, output_id);
}

auto create_function(tonlib_api::ftabi_createFunction& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  const auto& name = request.name_;

  TRY_RESULT(inputs, parse_params(request.inputs_))
  TRY_RESULT(outputs, parse_params(request.outputs_))
  const auto [input_id, output_id] = compute_function_id(name, inputs, outputs);

  return tonlib_api::make_object<tonlib_api::ftabi_function>(
      name, std::move(request.header_), std::move(request.inputs_), std::move(request.outputs_), input_id, output_id);
}

auto get_function_from_abi(tonlib_api::ftabi_getFunction& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(json, td::json_decode(td::MutableSlice{request.abi_}))
  TRY_RESULT(contract_abi, ftabi::contract_abi_from_json(json))

  auto it = contract_abi.functions.find(request.name_);
  if (it == contract_abi.functions.end()) {
    return td::Status::Error("function not found in contract abi");
  }
  auto& function = it->second;

  const auto [input_id, output_id] = compute_function_id(function.name, function.inputs, function.outputs);

  return tonlib_api::make_object<tonlib_api::ftabi_function>(  //
      function.name, to_tonlib_api(contract_abi.header), to_tonlib_api(function.inputs),
      to_tonlib_api(function.outputs), input_id, output_id);
}

auto create_message_body(tonlib_api::ftabi_createMessageBody& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(function, parse_function(*request.function_))
  TRY_RESULT(function_call, parse_function_call(*function, request.call_))
  TRY_RESULT(body, function->encode_input(function_call))
  TRY_RESULT(serialized, vm::std_boc_serialize(body))
  std::string str{serialized.data(), serialized.size()};
  return tonlib_api::make_object<tonlib_api::ftabi_messageBody>(str);
}

auto decode_output(const tonlib_api::ftabi_decodeOutput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(function, parse_function(*request.function_))
  TRY_RESULT(data, from_bytes(request.data_))
  TRY_RESULT(output, function->decode_output(vm::load_cell_slice_ref(data)))
  auto output_tl = to_tonlib_api(output);
  return tonlib_api::make_object<tonlib_api::ftabi_decodedOutput>(std::move(output_tl));
}

auto decode_input(const tonlib_api::ftabi_decodeInput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(function, parse_function(*request.function_))
  TRY_RESULT(data, from_bytes(request.data_))
  TRY_RESULT(input, function->decode_input(vm::load_cell_slice_ref(data), request.internal_))
  auto header_values_tl = to_tonlib_api(input.first);
  auto values_tl = to_tonlib_api(input.second);
  return tonlib_api::make_object<tonlib_api::ftabi_decodedInput>(std::move(header_values_tl), std::move(values_tl));
}

auto to_tonlib_api(const std::vector<ftabi::ParamRef>& params) -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_Param>> {
  std::vector<tonlib_api_ptr<tonlib_api::ftabi_Param>> results;
  results.reserve(params.size());
  for (const auto& param : params) {
    results.emplace_back(param->to_tonlib_api());
  }
  return results;
}

auto to_tonlib_api(const std::vector<std::pair<std::string, ftabi::ParamRef>>& named_params)
    -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedParam>> {
  std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedParam>> results;
  results.reserve(named_params.size());
  for (const auto& named_param : named_params) {
    auto value = named_param.second->to_tonlib_api();
    results.emplace_back(tonlib_api::make_object<tonlib_api::ftabi_namedParam>(named_param.first, std::move(value)));
  }
  return results;
}

auto to_tonlib_api(const std::vector<ftabi::ValueRef>& values) -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>> {
  std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>> results;
  results.reserve(values.size());
  for (const auto& value : values) {
    results.emplace_back(value->to_tonlib_api());
  }
  return results;
}

auto to_tonlib_api(const std::vector<std::pair<std::string, ftabi::ValueRef>>& named_values)
    -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>> {
  std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>> results;
  results.reserve(named_values.size());
  for (const auto& named_value : named_values) {
    auto value = named_value.second->to_tonlib_api();
    results.emplace_back(tonlib_api::make_object<tonlib_api::ftabi_namedValue>(named_value.first, std::move(value)));
  }
  return results;
}

auto to_tonlib_api(const ftabi::TvmOutput& output) -> tonlib_api_ptr<tonlib_api::ftabi_tvmOutput> {
  return tonlib_api::make_object<tonlib_api::ftabi_tvmOutput>(output.success, output.exit_code,
                                                              to_tonlib_api(output.values));
}

}  // namespace tonlib
