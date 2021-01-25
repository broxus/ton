#pragma once

#include "ftabi/Abi.hpp"

#include "tonlib/Stuff.h"

namespace tonlib {

using NamedParam = std::pair<std::string, ftabi::ParamRef>;
using NamedValue = std::pair<std::string, ftabi::ValueRef>;

auto parse_param(tonlib_api::ftabi_Param& param) -> td::Result<ftabi::ParamRef>;
auto parse_params(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Param>>& params)
    -> td::Result<std::vector<ftabi::ParamRef>>;

auto parse_named_param(tonlib_api::ftabi_namedParam& named_param) -> td::Result<NamedParam>;
auto parse_named_params(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedParam>>& params)
    -> td::Result<std::vector<NamedParam>>;

auto parse_value(tonlib_api::ftabi_Value& value) -> td::Result<ftabi::ValueRef>;
auto parse_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>& values)
    -> td::Result<std::vector<ftabi::ValueRef>>;

auto parse_named_value(tonlib_api::ftabi_namedValue& value) -> td::Result<NamedValue>;
auto parse_named_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>>& values)
    -> td::Result<std::vector<NamedValue>>;

auto parse_header_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>>& values)
    -> td::Result<std::unordered_map<std::string, ftabi::ValueRef>>;

auto parse_function(const tonlib_api::ftabi_function& value) -> td::Result<td::Ref<ftabi::Function>>;
auto parse_function_call(const ftabi::Function& function, tonlib_api_ptr<tonlib_api::ftabi_FunctionCall>& value)
    -> td::Result<td::Ref<ftabi::FunctionCall>>;

auto compute_function_signature(const tonlib_api::ftabi_computeFunctionSignature& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto create_function(tonlib_api::ftabi_createFunction& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto get_function_from_abi(tonlib_api::ftabi_getFunction& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto create_message_body(tonlib_api::ftabi_createMessageBody& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;

auto decode_output(const tonlib_api::ftabi_decodeOutput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto decode_input(const tonlib_api::ftabi_decodeInput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;

auto to_tonlib_api(const std::vector<ftabi::ParamRef>& params) -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_Param>>;
auto to_tonlib_api(const std::vector<std::pair<std::string, ftabi::ParamRef>>& named_params)
    -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedParam>>;
auto to_tonlib_api(const std::vector<ftabi::ValueRef>& values) -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>;
auto to_tonlib_api(const std::vector<std::pair<std::string, ftabi::ValueRef>>& named_values)
    -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_namedValue>>;

}  // namespace tonlib
