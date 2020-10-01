#pragma once

#include "ftabi/Abi.hpp"

#include "tonlib/Stuff.h"

namespace tonlib {

auto parse_param(tonlib_api::ftabi_Param& param) -> td::Result<ftabi::ParamRef>;
auto parse_params(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Param>>& params)
    -> td::Result<std::vector<ftabi::ParamRef>>;
auto parse_value(tonlib_api::ftabi_Value& value) -> td::Result<ftabi::ValueRef>;
auto parse_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>& values)
    -> td::Result<std::vector<ftabi::ValueRef>>;
auto parse_header_values(const std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>& values)
    -> td::Result<std::unordered_map<std::string, ftabi::ValueRef>>;
auto parse_function(const tonlib_api::ftabi_function& value) -> td::Result<ftabi::Function>;
auto parse_function_call(const tonlib_api_ptr<tonlib_api::ftabi_FunctionCall>& value)
    -> td::Result<ftabi::FunctionCall>;

auto compute_function_signature(const tonlib_api::ftabi_computeFunctionSignature& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto create_function(tonlib_api::ftabi_createFunction& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto create_message_body(const tonlib_api::ftabi_createMessageBody& request)
    -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;

auto decode_output(const tonlib_api::ftabi_decodeOutput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;
auto decode_input(const tonlib_api::ftabi_decodeInput& request) -> td::Result<tonlib_api_ptr<tonlib_api::Object>>;

auto to_tonlib_api(const std::vector<ftabi::ValueRef>& values) -> std::vector<tonlib_api_ptr<tonlib_api::ftabi_Value>>;

}  // namespace tonlib
