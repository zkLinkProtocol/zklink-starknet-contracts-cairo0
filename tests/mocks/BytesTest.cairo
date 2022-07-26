%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from contracts.utils.Bytes import (
    Bytes,
    read_felt,
    read_felt_array,
    read_uint256,
    read_uint256_array,
    read_bytes,
    FELT_MAX_BYTES,
)

@view
func readBytes{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    _offset : felt,
    _len : felt,
    _size : felt,
    _data_len : felt,
    _data : felt*
) -> (new_offset : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(0, FELT_MAX_BYTES, _size, _data_len, _data)
    let (new_offset, sub : Bytes) = read_bytes(bytes, _offset, _len)
    return (new_offset, sub.data_length, sub.data)
end

@view
func readFelt{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    _offset : felt,
    _len : felt,
    _size : felt,
    _data_len : felt,
    _data : felt*
) -> (new_offset : felt, data : felt):
    alloc_locals
    local bytes : Bytes = Bytes(0, FELT_MAX_BYTES, _size, _data_len, _data)
    let (new_offset, data) = read_felt(bytes, _offset, _len)
    return (new_offset, data)
end

@view
func readUint256{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    _offset : felt,
    _size : felt,
    _data_len : felt,
    _data : felt*
) -> (new_offset : felt, data : Uint256):
    alloc_locals
    local bytes : Bytes = Bytes(0, FELT_MAX_BYTES, _size, _data_len, _data)
    let (new_offset, data : Uint256) = read_uint256(bytes, _offset)
    return (new_offset, data)
end

@view
func readFeltArray{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    _offset : felt,
    _array_len : felt,
    _element_size : felt,
    _size : felt,
    _data_len : felt,
    _data : felt*
) -> (new_offset : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(0, FELT_MAX_BYTES, _size, _data_len, _data)
    let (new_offset, data : felt*) = read_felt_array(bytes, _offset, _array_len, _element_size)
    return (new_offset, _array_len, data)
end

@view
func readUint256Array{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    _offset : felt,
    _array_len : felt,
    _size : felt,
    _data_len : felt,
    _data : felt*
) -> (new_offset : felt, data_len : felt, data : Uint256*):
    alloc_locals
    local bytes : Bytes = Bytes(0, FELT_MAX_BYTES, _size, _data_len, _data)
    let (new_offset, data : Uint256*) = read_uint256_array(bytes, _offset, _array_len)
    return (new_offset, _array_len, data)
end