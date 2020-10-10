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
            return ftabi::ParamRef{ftabi::ParamUint(param.name_, param.size_)};
          },
          [](const tonlib_api::ftabi_paramInt& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamInt(param.name_, param.size_)};
          },
          [](const tonlib_api::ftabi_paramBool& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamBool(param.name_)};
          },
          [](const tonlib_api::ftabi_paramTuple& param) -> ReturnType {
            std::vector<ftabi::ParamRef> itemTypes{};
            itemTypes.reserve(param.itemTypes_.size());
            for (const auto& item : param.itemTypes_) {
              TRY_RESULT(itemType, parse_param(*item))
              itemTypes.emplace_back(std::move(itemType));
            }
            return ftabi::ParamRef{ftabi::ParamTuple(param.name_, std::move(itemTypes))};
          },
          [](const tonlib_api::ftabi_paramArray& param) -> ReturnType {
            TRY_RESULT(itemType, parse_param(*param.itemType_))
            return ftabi::ParamRef{ftabi::ParamArray(param.name_, std::move(itemType))};
          },
          [](const tonlib_api::ftabi_paramFixedArray& param) -> ReturnType {
            TRY_RESULT(itemType, parse_param(*param.itemType_))
            return ftabi::ParamRef{ftabi::ParamFixedArray(param.name_, std::move(itemType), param.size_)};
          },
          [](const tonlib_api::ftabi_paramCell& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamCell(param.name_)};
          },
          [](const tonlib_api::ftabi_paramMap& param) -> ReturnType {
            TRY_RESULT(keyType, parse_param(*param.keyType_))
            TRY_RESULT(valueType, parse_param(*param.valueType_))
            return ftabi::ParamRef{ftabi::ParamMap(param.name_, std::move(keyType), std::move(valueType))};
          },
          [](const tonlib_api::ftabi_paramAddress& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamAddress(param.name_)};
          },
          [](const tonlib_api::ftabi_paramBytes& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamBytes(param.name_)};
          },
          [](const tonlib_api::ftabi_paramFixedBytes& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamFixedBytes(param.name_, param.size_)};
          },
          [](const tonlib_api::ftabi_paramGram& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamGram(param.name_)};
          },
          [](const tonlib_api::ftabi_paramTime& param) -> ReturnType {
            return ftabi::ParamRef{ftabi::ParamTime{}};
          },
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
          [](const tonlib_api::ftabi_valueCell& value) -> ReturnType {
            TRY_RESULT(param, parse_param(*value.param_))
            TRY_RESULT(cell, from_bytes(value.value_->bytes_));
            return ftabi::ValueRef{ftabi::ValueCell(std::move(param), std::move(cell))};
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
            return ftabi::ValueRef{ftabi::ValueGram(std::move(param), td::make_refint(value.value_))};
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

auto parse_header_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>& values)
    -> td::Result<std::unordered_map<std::string, ftabi::ValueRef>> {
  std::unordered_map<std::string, ftabi::ValueRef> result{};
  result.reserve(values.size());
  for (auto& item : values) {
    if (item == nullptr) {
      return TonlibError::EmptyField("values[i]");
    }
    TRY_RESULT(value, parse_value(*item))
    const auto name = value->param()->name();
    result.emplace(std::make_pair(name, std::move(value)));
  }
  return std::move(result);
}

auto parse_function(const tonlib_api::ftabi_function& value) -> td::Result<ftabi::Function> {
  auto name = value.name_;
  TRY_RESULT(header, parse_params(value.header_params_))
  TRY_RESULT(inputs, parse_params(value.input_params_))
  TRY_RESULT(outputs, parse_params(value.output_params_))
  return ftabi::Function(std::move(name), std::move(header), std::move(inputs), std::move(outputs));
}

auto parse_function_call(const tonlib_api_ptr<tonlib_api::ftabi_FunctionCall>& value)
    -> td::Result<ftabi::FunctionCall> {
  using ReturnType = td::Result<ftabi::FunctionCall>;
  return downcast_call2<ReturnType>(
      *value,
      td::overloaded(  //
          [](const tonlib_api::ftabi_functionCallExternal& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            return ftabi::FunctionCall(std::move(headerValues), std::move(inputValues));
          },
          [](const tonlib_api::ftabi_functionCallExternalSigned& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            if (value.key_ == nullptr) {
              return TonlibError::EmptyField("key");
            }
            TRY_RESULT(input_key, from_tonlib_api(*value.key_))
            return ftabi::FunctionCall(
                std::move(headerValues), std::move(inputValues), false,
                td::optional<td::Ed25519::PrivateKey>{td::Ed25519::PrivateKey(std::move(input_key.key.secret))});
          },
          [](const tonlib_api::ftabi_functionCallInternal& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            return ftabi::FunctionCall(std::move(headerValues), std::move(inputValues), true,
                                       td::optional<td::Ed25519::PrivateKey>{});
          },
          [](const tonlib_api::ftabi_functionCallInternalSigned& value) -> ReturnType {
            TRY_RESULT(headerValues, parse_header_values(value.header_values_))
            TRY_RESULT(inputValues, parse_values(value.input_values_))
            if (value.key_ == nullptr) {
              return TonlibError::EmptyField("key");
            }
            TRY_RESULT(input_key, from_tonlib_api(*value.key_))
            return ftabi::FunctionCall(
                std::move(headerValues), std::move(inputValues), true,
                td::optional<td::Ed25519::PrivateKey>{td::Ed25519::PrivateKey(std::move(input_key.key.secret))});
          }));
}

auto compute_function_signature(const tonlib_api::ftabi_computeFunctionSignature& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(inputs, parse_params(request.inputs_))
  TRY_RESULT(outputs, parse_params(request.outputs_))
  auto signature = ftabi::compute_function_signature(request.name_, inputs, outputs);
  return tonlib_api::make_object<tonlib_api::ftabi_functionSignature>(std::move(signature));
}

auto create_function(tonlib_api::ftabi_createFunction& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  const auto& name = request.name_;

  TRY_RESULT(inputs, parse_params(request.inputs_))
  TRY_RESULT(outputs, parse_params(request.outputs_))

  const auto signature = ftabi::compute_function_signature(name, inputs, outputs);
  const auto id = ftabi::compute_function_id(signature);
  const auto input_id = static_cast<int32_t>(id & 0x7fffffffu);
  const auto output_id = static_cast<int32_t>(id | 0x80000000u);

  return tonlib_api::make_object<tonlib_api::ftabi_function>(
      name, std::move(request.header_), std::move(request.inputs_), std::move(request.outputs_), input_id, output_id);
}

auto create_message_body(const tonlib_api::ftabi_createMessageBody& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(function, parse_function(*request.function_))
  TRY_RESULT(function_call, parse_function_call(request.call_))
  TRY_RESULT(body, function.encode_input(function_call))
  TRY_RESULT(serialized, vm::std_boc_serialize(body))
  std::string str{serialized.data(), serialized.size()};
  return tonlib_api::make_object<tonlib_api::ftabi_messageBody>(str);
}

auto decode_output(const tonlib_api::ftabi_decodeOutput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(function, parse_function(*request.function_))
  TRY_RESULT(data, from_bytes(request.data_))
  TRY_RESULT(output, function.decode_output(vm::load_cell_slice_ref(data)))
  auto output_tl = to_tonlib_api(output);
  return tonlib_api::make_object<tonlib_api::ftabi_decodedOutput>(std::move(output_tl));
}

auto decode_input(const tonlib_api::ftabi_decodeInput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>> {
  TRY_RESULT(function, parse_function(*request.function_))
  TRY_RESULT(data, from_bytes(request.data_))
  TRY_RESULT(input, function.decode_input(vm::load_cell_slice_ref(data), request.internal_))
  auto header_values_tl = to_tonlib_api(input.first);
  auto values_tl = to_tonlib_api(input.second);
  return tonlib_api::make_object<tonlib_api::ftabi_decodedInput>(std::move(header_values_tl), std::move(values_tl));
}

auto to_tonlib_api(const std::vector<ftabi::ValueRef>& values) -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>> {
  std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>> results;
  results.reserve(values.size());
  for (const auto& value : values) {
    results.emplace_back(value->to_tonlib_api());
  }
  return results;
}

}  // namespace tonlib
