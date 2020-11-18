#include "utils.hpp"

#include <crypto/block/block-auto.h>
#include <crypto/block/check-proof.h>
#include <crypto/vm/cells/MerkleProof.h>
#include <smc-envelope/GenericAccount.h>
#include <td/utils/JsonBuilder.h>
#include <td/utils/Random.h>
#include <tl/generate/auto/tl/lite_api.h>
#include <vm/cellops.h>
#include <vm/cp0.h>
#include <vm/memo.h>
#include <vm/vm.h>
#include <tl/generate/auto/tl/tonlib_api.h>

namespace ftabi {
namespace tonlib_api = ton::tonlib_api;
constexpr static uint32_t SIGNATURE_LENGTH = 64;

namespace details {
auto to_bytes(td::Ref<vm::Cell> cell) -> std::string {
  if (cell.is_null()) {
    return "";
  }
  return vm::std_boc_serialize(cell, vm::BagOfCells::Mode::WithCRC32C).move_as_ok().as_slice().str();
}

auto find_next_bits(SliceData&& cursor, uint32_t bits) -> td::Result<SliceData> {
  if (cursor->empty()) {
    if (cursor->size_refs() != 1) {
      return td::Status::Error("invalid cellslice structure");
    }

    td::Ref<vm::Cell> cell;
    if (!cursor.write().fetch_ref_to(cell)) {
      return td::Status::Error("failed to fetch cell ref");
    }
    return vm::load_cell_slice_ref(cell);
  } else if (cursor->size() >= bits) {
    return std::move(cursor);
  } else {
    return td::Status::Error("not enought bits in the cell");
  }
}

auto put_array_to_map(const std::vector<ValueRef>& values) -> td::Result<SliceData> {
  constexpr auto key_len = 32;
  vm::Dictionary dictionary{key_len};
  for (unsigned i = 0; i < values.size(); ++i) {
    TRY_RESULT(serialized, values[i]->serialize())
    TRY_RESULT(value, pack_cells_into_chain(std::move(serialized)))
    if (!dictionary.set(td::BitArray<key_len>{i}, vm::load_cell_slice_ref(value), vm::DictionaryBase::SetMode::Add)) {
      return td::Status::Error("failed to add value");
    }
  }
  return dictionary.get_root();
}

auto get_dictionary(SliceData& cursor) -> td::Result<SliceData> {
  auto root = cursor->clone();
  bool as_ref;
  if (!cursor.write().fetch_bool_to(as_ref)) {
    return td::Status::Error("failed to fetch as_ref bit");
  }
  if (as_ref) {
    if (!cursor.write().advance_refs(1)) {
      return td::Status::Error("failed to get dictionary");
    }
  } else {
    root.advance_refs(root.size_refs());
  }
  return root.fetch_subslice(std::min(1u, root.size()), std::min(1u, root.size_refs()));
}

auto read_array_from_map(const ParamRef& param, SliceData&& cursor, uint32_t size)
    -> td::Result<std::pair<SliceData, std::vector<ValueRef>>> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 1))

  TRY_RESULT(root, details::get_dictionary(cursor))
  vm::Dictionary dictionary{root.write(), 32};

  std::vector<ValueRef> result{};
  result.reserve(size);
  for (uint32_t i = 0; i < size; ++i) {
    auto data = dictionary.lookup(td::BitArray<32>{i});
    if (data.is_null()) {
      return td::Status::Error("failed to find index");
    }
    TRY_RESULT(value, param->default_value())
    TRY_RESULT(next, value.write().deserialize(std::move(data), true))
    result.emplace_back(std::move(value));
  }
  return std::make_pair(std::move(cursor), std::move(result));
}

auto to_string(const std::vector<ValueRef>& values, const char* brackets) -> std::string {
  if (values.empty()) {
    return brackets;
  }
  std::string result{};
  result += brackets[0];
  for (size_t i = 0; i < values.size(); ++i) {
    result += values[i]->to_string();
    if (i + 1 != values.size()) {
      result += ", ";
    }
  }
  return result + brackets[1];
}
}  // namespace details

// value int

ValueInt::ValueInt(ParamRef param, const td::BigInt256& value) : Value{std::move(param)}, value{value} {
}

auto ValueInt::serialize() const -> td::Result<std::vector<BuilderData>> {
  TRY_RESULT(sgnd, try_is_signed())
  vm::CellBuilder cb{};
  CHECK(cb.store_int256_bool(value, param_->bit_len(), sgnd));
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueInt::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), param_->bit_len()))
  TRY_RESULT(sgnd, try_is_signed())
  auto fetched = cursor.write().fetch_int256(param_->bit_len(), sgnd);
  if (fetched.is_null()) {
    return td::Status::Error("invalid value type. int or uint expected");
  }
  value = *fetched;
  return std::move(cursor);
}

auto ValueInt::to_tonlib_api() const -> ApiValue {
  if (value.signed_fits_bits(64)) {
    return tonlib_api::make_object<tonlib_api::ftabi_valueInt>(param_->to_tonlib_api(), value.to_long());
  } else {
    td::BufferSlice bytes(32);
    CHECK(value.export_bytes(bytes.as_slice().ubegin(), bytes.size(), value.sgn()))
    return tonlib_api::make_object<tonlib_api::ftabi_valueBigInt>(param_->to_tonlib_api(), bytes.as_slice().str());
  }
}

auto ValueInt::to_string() const -> std::string {
  return value.to_dec_string();
}

auto ValueInt::try_is_signed() const -> td::Result<bool> {
  if (param_->type() == ParamType::Uint) {
    return false;
  } else if (param_->type() == ParamType::Int) {
    return true;
  }

  return td::Status::Error("invalid param type. int or uint expected");
}

auto ParamUint::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramUint>(static_cast<int32_t>(size));
}

auto ParamInt::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramInt>(static_cast<int32_t>(size));
}

// value bool

ValueBool::ValueBool(ParamRef param, bool value) : Value{std::move(param)}, value{value} {
}

auto ValueBool::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Bool) {
    return td::Status::Error("invalid param type. bool expected");
  }

  vm::CellBuilder cb{};
  CHECK(cb.store_bool_bool(value));
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueBool::deserialize(SliceData&& cursor, bool /*last*/) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 1))
  if (!cursor.write().fetch_bool_to(value)) {
    return td::Status::Error("invalid value type. bool expected");
  }
  return std::move(cursor);
}

auto ValueBool::to_string() const -> std::string {
  return value ? "true" : "false";
}

auto ValueBool::to_tonlib_api() const -> ApiValue {
  return tonlib_api::make_object<tonlib_api::ftabi_valueBool>(param_->to_tonlib_api(), value);
}

auto ValueBool::make_copy() const -> Value* {
  return new ValueBool{param_, value};
}

auto ParamBool::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramBool>();
}

// value tuple

ValueTuple::ValueTuple(ParamRef param, std::vector<ValueRef> values)
    : Value{std::move(param)}, values{std::move(values)} {
}

auto ValueTuple::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Tuple) {
    return td::Status::Error("invalid param type. tuple expected");
  }

  std::vector<BuilderData> result{};
  result.reserve(values.size());
  for (const auto& value : values) {
    TRY_RESULT(items, value->serialize())
    result.insert(result.end(), items.begin(), items.end());
  }
  return result;
}

auto ValueTuple::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT(default_value, param_->default_value())

  auto& result_values = dynamic_cast<ValueTuple&>(default_value.write()).values;

  for (size_t i = 0; i < result_values.size(); ++i) {
    TRY_RESULT_ASSIGN(cursor,
                      result_values[i].write().deserialize(std::move(cursor), last && (i + 1 == result_values.size())))
  }
  values = std::move(result_values);
  return std::move(cursor);
}

auto ValueTuple::to_string() const -> std::string {
  return details::to_string(values, "()");
}

auto ValueTuple::to_tonlib_api() const -> ApiValue {
  std::vector<ApiValue> api_values{};
  api_values.reserve(values.size());
  for (const auto& item : values) {
    api_values.emplace_back(item->to_tonlib_api());
  }
  return tonlib_api::make_object<tonlib_api::ftabi_valueTuple>(param_->to_tonlib_api(), std::move(api_values));
}

auto ValueTuple::make_copy() const -> Value* {
  return new ValueTuple{param_, values};
}

auto ParamTuple::to_tonlib_api() const -> ApiParam {
  std::vector<ApiParam> result{};
  result.reserve(items.size());
  for (const auto& item : items) {
    result.emplace_back(item->to_tonlib_api());
  }
  return tonlib_api::make_object<tonlib_api::ftabi_paramTuple>(std::move(result));
}

// value array

ValueArray::ValueArray(ParamRef param, std::vector<ValueRef> values)
    : Value{std::move(param)}, values{std::move(values)} {
}

auto ValueArray::serialize() const -> td::Result<std::vector<BuilderData>> {
  TRY_RESULT(array_data, details::put_array_to_map(values))
  vm::CellBuilder cb{};
  CHECK(cb.store_long_bool(values.size(), 32) && cb.append_cellslice_bool(array_data))
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueArray::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  if (param_->type() != ParamType::Array) {
    return td::Status::Error("invalid array param type");
  }
  const auto& param = dynamic_cast<const ParamArray*>(param_.get())->param;

  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 32));
  unsigned long long size;
  if (!cursor.write().fetch_ulong_bool(32, size)) {
    return td::Status::Error("failed to fetch array size");
  }

  TRY_RESULT(deserialized, details::read_array_from_map(param, std::move(cursor), static_cast<int32_t>(size)))
  values = std::move(deserialized.second);
  return std::move(deserialized.first);
}

auto ValueArray::to_string() const -> std::string {
  return details::to_string(values, "[]");
}

auto ValueArray::to_tonlib_api() const -> ApiValue {
  // TODO: add tonlib api
  return nullptr;
}

auto ValueArray::make_copy() const -> Value* {
  return new ValueArray{param_, values};
}

auto ParamArray::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramArray>(param->to_tonlib_api());
}

// value fixed array

ValueFixedArray::ValueFixedArray(ParamRef param, std::vector<ValueRef> values)
    : Value{std::move(param)}, values{std::move(values)} {
}

auto ValueFixedArray::serialize() const -> td::Result<std::vector<BuilderData>> {
  TRY_RESULT(array_data, details::put_array_to_map(values))
  vm::CellBuilder cb{};
  CHECK(cb.append_cellslice_bool(array_data))
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueFixedArray::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  if (param_->type() != ParamType::FixedArray) {
    return td::Status::Error("invalid fixed array param type");
  }
  const auto* array_param = dynamic_cast<const ParamFixedArray*>(param_.get());
  const auto& item_param = array_param->param;
  const auto size = array_param->size;

  TRY_RESULT(deserialized, details::read_array_from_map(item_param, std::move(cursor), size))
  values = std::move(deserialized.second);
  return std::move(deserialized.first);
}

auto ValueFixedArray::to_string() const -> std::string {
  return details::to_string(values, "[]");
}

auto ValueFixedArray::to_tonlib_api() const -> ApiValue {
  // TODO: add tonlib api
  return nullptr;
}

auto ValueFixedArray::make_copy() const -> Value* {
  return new ValueFixedArray{param_, values};
}

auto ParamFixedArray::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramFixedArray>(param->to_tonlib_api(), size);
}

// value cell

static auto read_cell(SliceData&& cursor, bool last) -> td::Result<std::pair<td::Ref<vm::Cell>, SliceData>> {
  if (cursor->size_refs() == 1 && !last && cursor->empty()) {
    cursor = vm::load_cell_slice_ref(cursor.write().fetch_ref());
  }

  if (cursor->size_refs() > 0) {
    auto cell = cursor.write().fetch_ref();
    return std::make_pair(std::move(cell), std::move(cursor));
  } else {
    return td::Status::Error("failed to fetch cell");
  }
}

ValueCell::ValueCell(ParamRef param, td::Ref<vm::Cell> value) : Value{std::move(param)}, value{std::move(value)} {
}

auto ValueCell::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Cell) {
    return td::Status::Error("invalid param type. cell expected");
  }

  vm::CellBuilder cb{};
  if (value.not_null()) {
    CHECK(cb.store_ref_bool(value));
  } else {
    CHECK(cb.store_ref_bool(vm::CellBuilder{}.finalize()));
  }
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueCell::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT(result, read_cell(std::move(cursor), last))
  value = std::move(result.first);
  return std::move(result.second);
}

auto ValueCell::to_string() const -> std::string {
  if (value.is_null()) {
    return "null";
  }
  std::ostringstream ss{};
  ss << "cell{\n";
  vm::load_cell_slice(value).print_rec(ss);
  ss << "\n}";
  return ss.str();
}

auto ValueCell::to_tonlib_api() const -> ApiValue {
  return tonlib_api::make_object<tonlib_api::ftabi_valueCell>(
      param_->to_tonlib_api(), tonlib_api::make_object<tonlib_api::tvm_cell>(details::to_bytes(value)));
}

auto ValueCell::make_copy() const -> Value* {
  return new ValueCell{param_, value};
}

auto ParamCell::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramCell>();
}

// value map

/*
ValueMap::ValueMap(ParamRef param, std::vector<std::pair<ValueRef, ValueRef>> values)
    : Value{std::move(param)}, values{std::move(values)} {
}

auto ValueMap::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Map) {
    return td::Status::Error("invalid map param type");
  }
  auto param = dynamic_cast<const ParamMap*>(param_.get());
  const auto& param_key = *param->key;
  const auto& param_value = *param->value;

  uint32_t bit_len{};
  std::unique_ptr<block::gen::TLB> value_type{};
  if (param_key.type() == ParamType::Uint) {
    bit_len = param_key.bit_len();
    value_type = std::make_unique<block::gen::UInt>(bit_len);
  } else if (param_key.type() == ParamType::Int) {
    bit_len = param_key.bit_len();
    value_type = std::make_unique<block::gen::Int>(bit_len);
  } else if (param_key.type() == ParamType::Address) {
    bit_len = STD_ADDRESS_BIT_LENGTH;
    value_type = std::make_unique<block::gen::MsgAddress>();
  } else {
    return td::Status::Error("only integer and std address values can be used as keys");
  }

  vm::CellBuilder cb{};
  block::gen::HashmapE map(static_cast<int>(bit_len), *value_type);
  for (const auto& item : values) {
    TRY_RESULT(serialized_key, item.first->serialize())
    if (serialized_key.size() != 1) {
      return td::Status::Error("map key must be one-cell length");
    }

    if (param_->type() == ParamType::Address && serialized_key[0]->size() != STD_ADDRESS_BIT_LENGTH) {
      return td::Status::Error("only std non-anycast address can be used as map key");
    }

    TRY_RESULT(serialized_value, item.second->serialize())
    TRY_RESULT(packed_value, pack_cells_into_chain(std::move(serialized_value)))

    auto key_cs = vm::load_cell_slice(serialized_key[0]);
    auto value_cs = vm::load_cell_slice(packed_value);
    CHECK(map.add_values(cb, key_cs, value_cs))
  }

  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueMap::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 1))
  if (param_->type() != ParamType::Map) {
    return td::Status::Error("invalid map param type");
  }
  auto param = dynamic_cast<const ParamMap*>(param_.get());
  const auto& param_key = *param->key;
  const auto& param_value = *param->value;

  uint32_t bit_len;
  if (param_key.type() == ParamType::Uint || param_key.type() == ParamType::Int) {
    bit_len = param_key.bit_len();
  } else if (param_key.type() == ParamType::Address) {
    bit_len = STD_ADDRESS_BIT_LENGTH;
  } else {
    return td::Status::Error("only integer and std address values can be used as keys");
  }

  vm::Dictionary dictionary{cursor, static_cast<int>(bit_len)};
  for (const auto& item : dictionary) {
    TRY_RESULT(value, param_value.default_value())
    SliceData cloned{item.second};
    TRY_RESULT(deserialized, value.write().deserialize(std::move(cloned), true))
  }

  // TODO: implement deserialization
  return td::Status::Error("not implemented yet");
}

auto ValueMap::to_string() const -> std::string {
  if (values.empty()) {
    return "{}";
  }
  std::ostringstream ss{};
  ss << "{";
  for (size_t i = 0; i < values.size(); ++i) {
    ss << values[i].first->to_string() << ": " << values[i].second->to_string();
    if (i + 1 != values.size()) {
      ss << ", ";
    }
  }
  ss << "}";
  return ss.str();
}

auto ValueMap::to_tonlib_api() const -> ApiValue {
  // TODO: implement api conversion
  auto status = td::Status::Error("not implemented yet");
  return nullptr;
}

auto ValueMap::make_copy() const -> Value* {
  return new ValueMap{param_, values};
}

auto ParamMap::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramMap>(name_, key->to_tonlib_api(), value->to_tonlib_api());
}

*/

// value address

ValueAddress::ValueAddress(ParamRef param, const block::StdAddress& value) : Value{std::move(param)}, value{value} {
}

auto ValueAddress::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Address) {
    return td::Status::Error("invalid param type. address expected");
  }

  vm::CellBuilder cb{};
  CHECK(cb.store_long_bool(4, 3)                   // addr_std$10 anycast:(Maybe Anycast)
        && cb.store_long_bool(value.workchain, 8)  // workchain:int8
        && cb.store_bits_bool(value.addr));        // addr:bits256
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueAddress::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 1))
  switch ((unsigned)cursor.write().fetch_ulong(2)) {
    case 0b00:                      // addr_none$00 = MsgAddressExt;
      value = block::StdAddress{};  // -> (0)
      break;
    case 0b10: {  // addr_std$10
      bool is_anycast;
      int workchain;
      ton::StdSmcAddress addr;
      if (cursor.write().fetch_bool_to(is_anycast)      // maybe anycast
          && !is_anycast                                // anycast is not supported
          && cursor.write().fetch_int_to(8, workchain)  // workchain_id:int8
          && cursor.write().fetch_bits_to(addr))        // address:bits256  = MsgAddressInt;
      {
        value = block::StdAddress{workchain, addr};
        break;
      } else {
        return td::Status::Error("failed to fetch address. invalid format");
      }
    }
    default:
      return td::Status::Error("failed to fetch address. unknown format");
  }

  return std::move(cursor);
}

auto ValueAddress::to_string() const -> std::string {
  return std::to_string(value.workchain) + ":" + value.addr.to_hex();
}

auto ValueAddress::to_tonlib_api() const -> ApiValue {
  return tonlib_api::make_object<tonlib_api::ftabi_valueAddress>(
      param_->to_tonlib_api(), tonlib_api::make_object<tonlib_api::accountAddress>(value.rserialize()));
}

auto ValueAddress::make_copy() const -> Value* {
  return new ValueAddress{param_, value};
}

auto ParamAddress::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramAddress>();
}

// value bytes

ValueBytes::ValueBytes(ParamRef param, std::vector<uint8_t> value) : Value{std::move(param)}, value{std::move(value)} {
}

auto ValueBytes::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Bytes || param_->type() != ParamType::FixedBytes) {
    return td::Status::Error("invalid param type. bytes or fixed bytes expected");
  }

  constexpr size_t cell_len = vm::DataCell::max_bits / 8;

  auto len = value.size();
  size_t cell_capacity;
  {
    const auto x = len % cell_len;
    if (x != 0) {
      cell_capacity = x;
    } else {
      cell_capacity = cell_len;
    }
  }

  vm::CellBuilder cb{};
  while (len > 0) {
    len -= cell_capacity;

    CHECK(cb.store_bytes_bool(&value[len], cell_capacity))
    auto current_cell = cb.finalize();
    CHECK(cb.store_ref_bool(std::move(current_cell)))

    cell_capacity = std::min(cell_len, len);
  }

  if (cb.size_refs() == 0) {
    BuilderData empty_cell{};
    CHECK(cb.store_ref_bool(std::move(empty_cell)))
  }

  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueBytes::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT(cell_cursor, read_cell(std::move(cursor), last))
  td::Ref<vm::Cell> cell = std::move(cell_cursor.first);

  TRY_RESULT(default_value, param_->default_value())
  auto& result_buffer = dynamic_cast<ValueBytes&>(default_value.write()).value;

  size_t total_size{};
  std::vector<td::BufferSlice> slices;

  auto cs = vm::load_cell_slice(cell);
  while (true) {
    td::BufferSlice slice{cs.size() / 8};
    if (!cs.fetch_bytes(slice.as_slice())) {
      return td::Status::Error("failed to fetch slice");
    }

    total_size += slice.size();
    slices.emplace_back(std::move(slice));

    if (cs.fetch_ref_to(cell)) {
      cs = vm::load_cell_slice(cell);
    } else {
      break;
    }
  }

  if (!result_buffer.empty() && result_buffer.size() != total_size) {
    return td::Status::Error("size of fixed bytes is not correspond to expected size");
  }

  total_size = 0;
  for (const auto& slice : slices) {
    std::memcpy(result_buffer.data() + total_size, slice.data(), slice.size());
  }

  value = std::move(result_buffer);
  return std::move(cell_cursor.second);
}

auto ValueBytes::to_string() const -> std::string {
  return td::buffer_to_hex(td::Slice{value.data(), value.size()});
}

auto ValueBytes::to_tonlib_api() const -> ApiValue {
  std::string result{};
  result.resize(value.size(), 0);

  static_assert(sizeof(decltype(result)::value_type) == sizeof(decltype(value)::value_type),
                "incompatible api bytes representation");
  std::memcpy(&result[0], value.data(), value.size());

  return tonlib_api::make_object<tonlib_api::ftabi_valueBytes>(param_->to_tonlib_api(), std::move(result));
}

auto ValueBytes::make_copy() const -> Value* {
  return new ValueBytes{param_, value};
}

auto ParamBytes::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramBytes>();
}

auto ParamFixedBytes::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramFixedBytes>(static_cast<int32_t>(size));
}

// value gram

ValueGram::ValueGram(ParamRef param, td::BigInt256 value) : Value{std::move(param)}, value{std::move(value)} {
}

auto ValueGram::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Gram) {
    return td::Status::Error("invalid param type. grams expected");
  }

  vm::CellBuilder cb{};
  CHECK(block::tlb::t_Grams.store_integer_value(cb, value))
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueGram::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 1))
  auto grams = block::tlb::t_Grams.as_integer_skip(cursor.write());
  if (grams.is_null()) {
    return td::Status::Error("failed to parse grams");
  }
  value = *grams;
  return std::move(cursor);
}

auto ValueGram::to_string() const -> std::string {
  return "$" + value.to_dec_string();
}

auto ValueGram::to_tonlib_api() const -> ApiValue {
  return tonlib_api::make_object<tonlib_api::ftabi_valueGram>(param_->to_tonlib_api(), value.to_long());
}

auto ValueGram::make_copy() const -> Value* {
  return new ValueGram{param_, value};
}

auto ParamGram::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramGram>();
}

// value time

ValueTime::ValueTime(ParamRef param, td::uint64 value) : Value{std::move(param)}, value{value} {
}

auto ValueTime::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Time) {
    return td::Status::Error("invalid param type. time expected");
  }

  vm::CellBuilder cb{};
  CHECK(cb.store_long_bool(value, 64));
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueTime::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 64))
  unsigned long long result;
  if (!cursor.write().fetch_ulong_bool(64, result)) {
    return td::Status::Error("failed to fetch time");
  }

  value = result;
  return std::move(cursor);
}

auto ValueTime::to_string() const -> std::string {
  return std::to_string(value);
}

auto ValueTime::to_tonlib_api() const -> ApiValue {
  return tonlib_api::make_object<tonlib_api::ftabi_valueTime>(param_->to_tonlib_api(), static_cast<int64_t>(value));
}

auto ValueTime::make_copy() const -> Value* {
  return new ValueTime{param_, value};
}

auto ParamTime::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramTime>();
}

// value expire

ValueExpire::ValueExpire(ParamRef param, uint32_t value) : Value{std::move(param)}, value{value} {
}

auto ValueExpire::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::Expire) {
    return td::Status::Error("invalid param type. expire expected");
  }

  vm::CellBuilder cb{};
  CHECK(cb.store_long_bool(value, 32));
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValueExpire::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 32))
  unsigned long long result;
  if (!cursor.write().fetch_ulong_bool(32, result)) {
    return td::Status::Error("failed to fetch time");
  }

  value = static_cast<uint32_t>(result);
  return std::move(cursor);
}

auto ValueExpire::to_string() const -> std::string {
  return std::to_string(value);
}

auto ValueExpire::to_tonlib_api() const -> ApiValue {
  return tonlib_api::make_object<tonlib_api::ftabi_valueExpire>(param_->to_tonlib_api(), static_cast<int32_t>(value));
}

auto ValueExpire::make_copy() const -> Value* {
  return new ValueExpire{param_, value};
}

auto ParamExpire::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramExpire>();
}

// value public key

ValuePublicKey::ValuePublicKey(ParamRef param, td::optional<td::SecureString> value)
    : Value{std::move(param)}, value{std::move(value)} {
}

auto ValuePublicKey::serialize() const -> td::Result<std::vector<BuilderData>> {
  if (param_->type() != ParamType::PublicKey) {
    return td::Status::Error("invalid param type. public key expected");
  }

  vm::CellBuilder cb{};
  if (value) {
    CHECK(cb.store_long_bool(1, 1) && cb.store_bytes_bool(value.value()));
  } else {
    CHECK(cb.store_long_bool(0, 1));
  }
  return std::vector<BuilderData>{cb.finalize()};
}

auto ValuePublicKey::deserialize(SliceData&& cursor, bool last) -> td::Result<SliceData> {
  TRY_RESULT_ASSIGN(cursor, details::find_next_bits(std::move(cursor), 1))
  bool has_value;
  if (!cursor.write().fetch_bool_to(has_value)) {
    return td::Status::Error("failed to fetch public key maybe tag");
  }
  if (has_value) {
    td::SecureString data(32);
    if (!cursor.write().fetch_bytes(data.as_mutable_slice())) {
      return td::Status::Error("failed to fetch public key data");
    }
    value = td::optional<td::SecureString>{std::move(data)};
  } else {
    value = td::optional<td::SecureString>{};
  }
  return std::move(cursor);
}

auto ValuePublicKey::to_string() const -> std::string {
  if (value) {
    return td::buffer_to_hex(value.value().as_slice());
  } else {
    return "null";
  }
}

auto ValuePublicKey::to_tonlib_api() const -> ApiValue {
  td::SecureString result{};
  if (value) {
    result = value.value().copy();
  }
  return tonlib_api::make_object<tonlib_api::ftabi_valuePublicKey>(param_->to_tonlib_api(), std::move(result));
}

auto ValuePublicKey::make_copy() const -> Value* {
  td::optional<td::SecureString> copy{};
  if (value) {
    copy = value.value().copy();
  }
  return new ValuePublicKey{param_, std::move(copy)};
}

auto ParamPublicKey::to_tonlib_api() const -> ApiParam {
  return tonlib_api::make_object<tonlib_api::ftabi_paramPublicKey>();
}

// functions

auto fill_signature(const td::optional<td::SecureString>& signature, BuilderData&& cell) -> td::Result<BuilderData> {
  vm::CellBuilder cb{};
  if (signature) {
    CHECK(cb.store_long_bool(1, 1) && cb.store_bytes_bool(signature.value().as_slice()))
  } else {
    CHECK(cb.store_long_bool(0, 1))
  }
  CHECK(cb.append_data_cell_bool(cell))

  return cb.finalize();
}

auto pack_cells_into_chain(std::vector<BuilderData>&& cells) -> td::Result<BuilderData> {
  if (cells.empty()) {
    return td::Status::Error("no cells to pack");
  }

  size_t idx = 0;

  std::vector<BuilderData> packed_data{};
  packed_data.emplace_back(std::move(cells[idx++]));

  uint64_t remaining_bits = 0;
  uint64_t remaining_refs = 0;
  for (size_t i = idx; i < cells.size(); ++i) {
    remaining_bits += cells[i]->size();
    remaining_refs += cells[i]->size_refs();
  }

  for (; idx < cells.size(); ++idx) {
    auto cell = std::move(cells[idx]);
    remaining_bits -= cell->size();
    remaining_refs -= cell->size_refs();

    auto& builder = packed_data.back();
    if (builder->size() + cell->size() > vm::CellTraits::max_bits) {
      packed_data.emplace_back(std::move(cell));
    } else if (cell->size_refs() > 0 && builder->size_refs() + cell->size_refs() == vm::CellTraits::max_refs) {
      if (remaining_refs == 0 && remaining_bits + cell->size() + builder->size() <= vm::CellTraits::max_bits) {
        vm::CellBuilder cb{};
        CHECK(cb.append_data_cell_bool(builder) && cb.append_data_cell_bool(cell))
        builder = cb.finalize();
      } else {
        packed_data.emplace_back(std::move(cell));
      }
    } else {
      vm::CellBuilder cb{};
      CHECK(cb.append_data_cell_bool(builder) && cb.append_data_cell_bool(cell))
      builder = cb.finalize();
    }
  }

  while (!packed_data.empty()) {
    auto cell = std::move(packed_data.back());
    packed_data.pop_back();

    if (packed_data.empty()) {
      return cell;
    } else {
      vm::CellBuilder cb{};
      CHECK(cb.append_data_cell_bool(packed_data.back()) && cb.store_ref_bool(cell))
      packed_data.back() = cb.finalize();
    }
  }

  return td::Status::Error("empty packed data");
}

auto check_params(const std::vector<ValueRef>& values, const std::vector<ParamRef>& params) -> bool {
  if (values.size() != params.size()) {
    return false;
  }

  for (size_t i = 0; i < values.size(); ++i) {
    if (!values[i]->check_type(params[i])) {
      return false;
    }
  }
  return true;
}

auto compute_function_id(const std::string& signature) -> uint32_t {
  uint8_t bytes[32];
  td::sha256(td::Slice{signature}, td::MutableSlice{bytes, 32});

  return static_cast<uint32_t>(bytes[0]) << 24u |  //
         static_cast<uint32_t>(bytes[1]) << 16u |  //
         static_cast<uint32_t>(bytes[2]) << 8u |   //
         static_cast<uint32_t>(bytes[3]);
}

auto compute_function_signature(const std::string& name, const InputParams& inputs, const OutputParams& outputs)
    -> std::string {
  // inputs
  std::string inputs_signature{};
  if (inputs.empty()) {
    inputs_signature = "(";
  } else {
    for (const auto& input : inputs) {
      inputs_signature += ",";
      inputs_signature += input->type_signature();
    }
    inputs_signature[0] = '(';
  }

  // outputs
  std::string outputs_signature{};
  if (outputs.empty()) {
    outputs_signature = "(";
  } else {
    for (const auto& output : outputs) {
      outputs_signature += ",";
      outputs_signature += output->type_signature();
    }
    outputs_signature[0] = '(';
  }

  // result
  return name + inputs_signature + ")" + outputs_signature + ")v" + std::to_string(ABI_VERSION);
}

auto decode_header(SliceData&& data, const HeaderParams& header_params, bool internal)
    -> td::Result<std::tuple<SliceData, uint32_t, std::vector<ValueRef>>> {
  std::vector<ValueRef> results{};
  if (!internal) {
    bool has_signature = false;
    if (!data.write().fetch_bool_to(has_signature)) {
      return td::Status::Error("failed to fetch signature option bit");
    }
    if (has_signature && !data.write().advance(SIGNATURE_LENGTH * 8)) {
      return td::Status::Error("failed to fetch signature");
    }
    for (const auto& item : header_params) {
      TRY_RESULT(default_value, item.second->default_value())
      TRY_RESULT_ASSIGN(data, default_value.write().deserialize(std::move(data), false))
      results.emplace_back(std::move(default_value));
    }
  }
  long long function_id = 0;
  if (!data.write().fetch_long_bool(32, function_id)) {
    return td::Status::Error("failed to fetch function id");
  }

  return std::make_tuple(std::move(data), static_cast<uint32_t>(function_id), results);
}

auto decode_input_id(SliceData&& data, const HeaderParams& header_params, bool internal) -> td::Result<uint32_t> {
  TRY_RESULT(decoded_header, decode_header(std::move(data), header_params, internal))
  return std::get<1>(decoded_header);
}

auto decode_output_id(SliceData&& data) -> td::Result<uint32_t> {
  long long output_id = 0;
  if (!data.write().fetch_long_bool(32, output_id)) {
    return td::Status::Error("failed to fetch output id");
  }
  return static_cast<uint32_t>(output_id);
}

auto decode_params(SliceData&& data, const std::vector<ParamRef>& params) -> td::Result<std::vector<ValueRef>> {
  std::vector<ValueRef> results;

  for (size_t i = 0; i < params.size(); ++i) {
    const auto last = i + 1 == params.size();
    TRY_RESULT(default_value, params[i]->default_value())
    TRY_RESULT_ASSIGN(data, default_value.write().deserialize(std::move(data), last))
    results.emplace_back(std::move(default_value));
  }

  if (!data->empty_ext()) {
    return td::Status::Error("incomplete deserialization");
  }

  return std::move(results);
}

FunctionCall::FunctionCall(InputValues&& inputs) : inputs{std::move(inputs)} {
}

FunctionCall::FunctionCall(HeaderValues&& header, InputValues&& inputs)
    : header{std::move(header)}, inputs{std::move(inputs)} {
}

FunctionCall::FunctionCall(HeaderValues&& header, InputValues&& inputs, bool internal,
                           td::optional<td::Ed25519::PrivateKey>&& private_key)
    : header{std::move(header)}, inputs{std::move(inputs)}, internal{internal}, private_key{std::move(private_key)} {
}

auto FunctionCall::make_copy() const -> FunctionCall* {
  auto header_copy = header;
  auto inputs_copy = inputs;
  td::optional<td::Ed25519::PrivateKey> private_key_copy{};
  if (private_key) {
    private_key_copy =
        td::optional<td::Ed25519::PrivateKey>(td::Ed25519::PrivateKey(private_key.value().as_octet_string().copy()));
  }
  return new FunctionCall{std::move(header_copy), std::move(inputs_copy), internal, std::move(private_key_copy)};
}

Function::Function(std::string&& name, HeaderParams&& header, InputParams&& inputs, OutputParams&& outputs,
                   uint32_t input_id, uint32_t output_id)
    : name_{std::move(name)}
    , header_{std::move(header)}
    , inputs_{std::move(inputs)}
    , outputs_{std::move(outputs)}
    , input_id_{input_id}
    , output_id_{output_id} {
}

Function::Function(std::string&& name, HeaderParams&& header, InputParams&& inputs, OutputParams&& outputs)
    : Function(std::move(name), std::move(header), std::move(inputs), std::move(outputs), 0, 0) {
  const auto signature = compute_function_signature(name_, inputs_, outputs_);
  const auto id = compute_function_id(signature);
  input_id_ = id & 0x7fffffffu;
  output_id_ = id | 0x80000000u;
}

Function::Function(std::string&& name, HeaderParams&& header, InputParams&& inputs, OutputParams&& outputs, uint32_t id)
    : Function{std::move(name), std::move(header), std::move(inputs), std::move(outputs), id, id} {
}

auto Function::encode_input(FunctionCall& call) const -> td::Result<BuilderData> {
  return encode_input(call.header, call.inputs, call.internal, call.private_key);
}

auto Function::encode_input(const td::Ref<FunctionCall>& call) const -> td::Result<BuilderData> {
  return encode_input(call->header, call->inputs, call->internal, call->private_key);
}

auto Function::encode_input(const HeaderValues& header, const InputValues& inputs, bool internal,
                            const td::optional<td::Ed25519::PrivateKey>& private_key) const -> td::Result<BuilderData> {
  TRY_RESULT(unsigned_call, create_unsigned_call(header, inputs, internal, !!private_key))
  auto message = std::move(unsigned_call.first);
  const auto& hash = unsigned_call.second;

  if (!internal) {
    if (private_key) {
      TRY_RESULT(signature, private_key.value().sign(hash.as_slice()))
      TRY_RESULT_ASSIGN(message,
                        fill_signature(td::optional<td::SecureString>{std::move(signature)}, std::move(message)))
    } else {
      TRY_RESULT_ASSIGN(message, fill_signature(td::optional<td::SecureString>{}, std::move(message)))
    }
  }

  return message;
}

auto Function::decode_input(SliceData&& data, bool internal) const
    -> td::Result<std::pair<std::vector<ValueRef>, std::vector<ValueRef>>> {
  TRY_RESULT(decoded_header, decode_header(std::move(data), header_, internal))
  auto [cursor, input_id, header_values] = std::move(decoded_header);

  if (input_id != input_id_) {
    return td::Status::Error("invalid input_id");
  }

  TRY_RESULT(values, decode_params(std::move(cursor), inputs_));
  return std::make_pair(std::move(header_values), std::move(values));
}

auto Function::decode_output(SliceData&& data) const -> td::Result<std::vector<ValueRef>> {
  unsigned long long output_id;
  if (!data.write().fetch_ulong_bool(32, output_id)) {
    return td::Status::Error("failed to fetch output_id");
  }

  if (output_id != output_id_) {
    return td::Status::Error("invalid output_id");
  }

  return decode_params(std::move(data), outputs_);
}

auto Function::encode_header(const HeaderValues& header, bool internal) const -> td::Result<std::vector<BuilderData>> {
  std::vector<BuilderData> result{};
  if (!internal) {
    for (const auto& item : header_) {
      const auto& name = item.first;
      const auto& param = item.second;

      auto it = header.find(name);
      if (it == header.end()) {
        TRY_RESULT(default_value, param->default_value());
        TRY_RESULT(builder_data, default_value->serialize());
        TRY_RESULT(cell, pack_cells_into_chain(std::move(builder_data)))
        result.emplace_back(std::move(cell));
      } else {
        const auto& value = it->second;
        if (!value->check_type(param)) {
          return td::Status::Error("wrong parameter type");
        }

        TRY_RESULT(builder_data, value->serialize())
        TRY_RESULT(cell, pack_cells_into_chain(std::move(builder_data)))
        result.emplace_back(std::move(cell));
      }
    }
  }

  vm::CellBuilder cb{};
  CHECK(cb.store_long_bool(input_id_, 32))
  result.emplace_back(cb.finalize());
  return result;
}

auto Function::create_unsigned_call(const HeaderValues& header, const InputValues& inputs, bool internal,
                                    bool reserve_sign) const -> td::Result<std::pair<BuilderData, vm::CellHash>> {
  if (!check_params(inputs, inputs_)) {
    return td::Status::Error("invalid inputs");
  }

  TRY_RESULT(cells, encode_header(header, internal))

  uint32_t remove_bits = 1;

  if (!internal) {
    vm::CellBuilder cb{};
    if (reserve_sign) {
      uint8_t signature_buffer[SIGNATURE_LENGTH] = {};
      CHECK(cb.store_ones_bool(1) && cb.store_bytes_bool(signature_buffer, SIGNATURE_LENGTH))
      remove_bits += SIGNATURE_LENGTH * 8;
    } else {
      CHECK(cb.store_zeroes_bool(1))
    }
    cells.insert(cells.begin(), cb.finalize());
  }

  for (const auto& input : inputs) {
    TRY_RESULT(builder_data, input->serialize())
    cells.insert(cells.end(), builder_data.begin(), builder_data.end());
  }

  TRY_RESULT(result, pack_cells_into_chain(std::move(cells)))

  if (!internal && remove_bits > 0) {
    auto slice = vm::load_cell_slice(result);
    vm::CellBuilder cb{};
    CHECK(slice.advance(remove_bits) && cb.append_cellslice_bool(slice));
    result = cb.finalize();
  }

  const auto hash = result->get_hash();

  return std::make_pair(std::move(result), hash);
}

auto Function::make_copy() const -> Function* {
  auto name = name_;
  auto header = header_;
  auto inputs = inputs_;
  auto outputs = outputs_;
  return new Function{std::move(name), std::move(header), std::move(inputs), std::move(outputs), input_id_, output_id_};
}

auto generate_state_init(const td::Ref<vm::Cell>& tvc, const td::Ed25519::PublicKey& public_key)
    -> td::Result<td::Ref<vm::Cell>> {
  block::gen::StateInit::Record state_init;
  if (!tlb::unpack_cell(tvc, state_init)) {
    return td::Status::Error("Failed to unpack state_init");
  }

  vm::CellBuilder value_cb{};
  if (!value_cb.store_bytes_bool(public_key.as_octet_string())) {
    return td::Status::Error("Failed to create public key value");
  }

  try {
    auto data = vm::load_cell_slice_ref(state_init.data->prefetch_ref());
    vm::Dictionary map{data, 64};
    td::BitArray<64> key{};
    map.set(key, value_cb.as_cellslice_ref(), vm::Dictionary::SetMode::Replace);

    value_cb.reset();
    auto packed_map = value_cb.store_ones(1).store_ref(map.get_root_cell()).finalize();
    state_init.data = value_cb.store_ones(1).store_ref(packed_map).as_cellslice_ref();
  } catch (const vm::VmError& e) {
    return td::Status::Error(PSLICE() << "VM error: " << e.as_status().message());
  }

  td::Ref<vm::Cell> new_state;
  if (!tlb::pack_cell(new_state, state_init)) {
    return td::Status::Error("Failed to pack state_init");
  }

  return new_state;
}

// smc stuff
static auto unpack_internal_address_opt(vm::CellSlice& cs, td::optional<block::StdAddress>& address) -> bool {
  const auto tag = cs.fetch_ulong(2);

  if (tag == 0) {
    address = td::optional<block::StdAddress>{};
    return true;
  }

  block::StdAddress result{};
  td::Ref<vm::CellSlice> anycast;
  const auto success = tag == 2                                              //
                       && block::gen::t_Maybe_Anycast.fetch_to(cs, anycast)  //
                       && cs.fetch_int_to(8, result.workchain)               //
                       && cs.fetch_bits_to(result.addr.bits(), 256);
  if (success) {
    address = td::optional<block::StdAddress>(result);
  }
  return success;
}

auto unpack_result_message_body(vm::CellSlice& cs) -> td::Result<td::Ref<vm::CellSlice>> {
  td::Ref<vm::CellSlice> init;
  td::optional<block::StdAddress> src_address;
  auto has_valid_header = cs.fetch_ulong(2) == 3                                     //
                          && unpack_internal_address_opt(cs, src_address)            //
                          && block::gen::t_MsgAddressExt.validate_skip(nullptr, cs)  //
                          && cs.advance(64 + 32);
  if (!has_valid_header) {
    return td::Status::Error("failed to fetch message header");
  }

  if (!block::gen::t_Maybe_Either_StateInit_Ref_StateInit.fetch_to(cs, init)) {
    return td::Status::Error("failed to fetch init state");
  }

  bool body_in_reference;
  if (!cs.fetch_bool_to(body_in_reference)) {
    return td::Status::Error("failed to fetch body state");
  }

  td::Ref<vm::Cell> cell;
  if (body_in_reference) {
    if (!cs.fetch_ref_to(cell)) {
      return td::Status::Error("failed to fetch body cell");
    } else {
      return vm::load_cell_slice_ref(cell);
    }
  } else {
    if (cs.empty()) {
      return vm::CellBuilder{}.as_cellslice_ref();
    } else {
      return vm::CellBuilder{}.append_cellslice(cs).as_cellslice_ref();
    }
  }
}

static auto prepare_vm_c7(ton::UnixTime now, ton::LogicalTime lt, td::Ref<vm::CellSlice> my_addr,
                          const block::CurrencyCollection& balance) -> td::Ref<vm::Tuple> {
  td::BitArray<256> rand_seed{};
  td::RefInt256 rand_seed_int{true};
  td::Random::secure_bytes(rand_seed.as_slice());
  if (!rand_seed_int.unique_write().import_bits(rand_seed.cbits(), 256, false)) {
    return {};
  }
  auto tuple = vm::make_tuple_ref(td::make_refint(0x076ef1ea),  // [ magic:0x076ef1ea
                                  td::make_refint(0),           //   actions:Integer
                                  td::make_refint(0),           //   msgs_sent:Integer
                                  td::make_refint(now),         //   unixtime:Integer
                                  td::make_refint(lt),          //   block_lt:Integer
                                  td::make_refint(lt),          //   trans_lt:Integer
                                  std::move(rand_seed_int),     //   rand_seed:Integer
                                  balance.as_vm_tuple(),        //   balance_remaining:[Integer (Maybe Cell)]
                                  my_addr,                      //  myself:MsgAddressInt
                                  vm::StackEntry());            //  global_config:(Maybe Cell) ] = SmartContractInfo;
  LOG(DEBUG) << "SmartContractInfo initialized with " << vm::StackEntry(tuple).to_string();
  return vm::make_tuple_ref(std::move(tuple));
}

auto run_smc_method(const block::StdAddress& address, block::AccountState::Info&& info, FunctionRef&& function,
                    FunctionCallRef&& function_call) -> td::Result<std::vector<ValueRef>> {
  TRY_RESULT(message_body, function->encode_input(function_call))
  return run_smc_method(address, std::move(info), std::move(function), {}, std::move(message_body));
}

auto run_smc_method(const block::StdAddress& address, block::AccountState::Info&& info, FunctionRef&& function,
                    td::Ref<vm::Cell>&& message_state_init, td::Ref<vm::Cell>&& message_body)
    -> td::Result<std::vector<ValueRef>> {
  try {
    if (info.root.is_null()) {
      LOG(ERROR) << "account state of " << address.workchain << ":" << address.addr.to_hex() << " is empty";
      return td::Status::Error(PSLICE() << "account state of " << address.workchain << ":" << address.addr.to_hex()
                                        << " is empty");
    }

    // unpack account state
    block::gen::Account::Record_account acc;
    block::gen::AccountStorage::Record store;
    block::CurrencyCollection balance;
    if (!(tlb::unpack_cell(info.root, acc) && tlb::csr_unpack(acc.storage, store) &&
          balance.validate_unpack(store.balance))) {
      LOG(ERROR) << "error unpacking account state";
      return td::Status::Error("error unpacking account state");
    }

    // validate account state
    switch (block::gen::t_AccountState.get_tag(*store.state)) {
      case block::gen::AccountState::account_uninit:
        LOG(ERROR) << "account " << address.workchain << ":" << address.addr.to_hex()
                   << " not initialized yet (cannot run any methods)";
        return td::Status::Error(PSLICE() << "account " << address.workchain << ":" << address.addr.to_hex()
                                          << " not initialized yet (cannot run any methods)");
      case block::gen::AccountState::account_frozen:
        LOG(ERROR) << "account " << address.workchain << ":" << address.addr.to_hex()
                   << " frozen (cannot run any methods)";
        return td::Status::Error(PSLICE() << "account " << address.workchain << ":" << address.addr.to_hex()
                                          << " frozen (cannot run any methods)");
      default:
        break;
    }

    CHECK(store.state.write().fetch_ulong(1) == 1)  // account_init$1 _:StateInit = AccountState;
    block::gen::StateInit::Record state_init;
    CHECK(tlb::csr_unpack(store.state, state_init));

    // encode message and it's body

    auto ext_in_message = ton::GenericAccount::create_ext_message(block::StdAddress{address.workchain, address.addr},
                                                                  message_state_init, message_body);

    auto message_body_cs = vm::load_cell_slice_ref(message_body);

    // fill stack
    auto stack = td::make_ref<vm::Stack>();
    stack.write().push(vm::StackEntry{balance.grams});
    stack.write().push_smallint(0);
    stack.write().push_cell(ext_in_message);
    stack.write().push_cellslice(message_body_cs);
    stack.write().push_smallint(-1);

    // create vm
    LOG(DEBUG) << "creating VM";

    vm::init_op_cp0();

    vm::VmState vm{state_init.code->prefetch_ref(),
                   std::move(stack),
                   vm::GasLimits{1'000'000'000},
                   /* flags */ 1,
                   state_init.data->prefetch_ref(),
                   vm::VmLog{}};

    // initialize registers with SmartContractInfo
    auto my_addr = td::make_ref<vm::CellSlice>(acc.addr->clone());
    vm.set_c7(prepare_vm_c7(info.gen_utime, info.gen_lt, my_addr, balance));

    // execute
    LOG(DEBUG) << "starting VM to run method of smart contract " << address.workchain << ":" << address.addr.to_hex();

    int exit_code;
    try {
      exit_code = ~vm.run();
    } catch (vm::VmVirtError& err) {
      LOG(ERROR) << "virtualization error while running VM to locally compute runSmcMethod result: " << err.get_msg();
      return td::Status::Error(
          PSLICE() << "virtualization error while running VM to locally compute runSmcMethod result: "
                   << err.get_msg());
    } catch (vm::VmError& err) {
      LOG(ERROR) << "error while running VM to locally compute runSmcMethod result: " << err.get_msg();
      return td::Status::Error(PSLICE() << "error while running VM to locally compute runSmcMethod result: "
                                        << err.get_msg());
    } catch (vm::VmFatal& err) {
      LOG(ERROR) << "error while running VM";
      return td::Status::Error("Fatal VM error");
    }

    LOG(DEBUG) << "VM terminated with exit code " << exit_code;

    if (exit_code != 0) {
      return td::Status::Error(PSLICE() << "VM terminated with non-zero exit code " << exit_code);
    }

    // process output messages
    if (function->has_output() && vm.get_committed_state().committed) {
      auto actions_cs = vm::load_cell_slice(vm.get_committed_state().c5);

      while (actions_cs.size_refs()) {
        td::Ref<vm::Cell> next;
        CHECK(actions_cs.fetch_ref_to(next))

        unsigned long long magic;
        if (actions_cs.fetch_ulong_bool(32, magic) && magic == 0x0ec3c86du && actions_cs.size_refs() == 1) {
          td::Ref<vm::Cell> msg;
          CHECK(actions_cs.fetch_ref_to(msg))

          auto msg_cs = vm::load_cell_slice(msg);
          if (msg_cs.prefetch_ulong(2) != 3) {
            continue;
          }

          TRY_RESULT(body, unpack_result_message_body(msg_cs))
          TRY_RESULT(result, function->decode_output(std::move(body)))
          return result;
        } else {
          LOG(ERROR) << "Failed to read message";
        }

        actions_cs = vm::load_cell_slice(next);
      }
    }

    return std::vector<ValueRef>{};
  } catch (vm::VmVirtError& err) {
    LOG(ERROR) << "virtualization error while parsing runSmcMethod result: " << err.get_msg();
    return td::Status::Error(PSLICE() << "virtualization error while parsing runSmcMethod result: " << err.get_msg());
  } catch (vm::VmError& err) {
    LOG(ERROR) << "error while parsing runSmcMethod result: " << err.get_msg();
    return td::Status::Error(PSLICE() << "error while parsing runSmcMethod result: " << err.get_msg());
  } catch (vm::VmFatal& err) {
    LOG(ERROR) << "error while running VM";
    return td::Status::Error("Fatal VM error");
  }
}

}  // namespace ftabi
