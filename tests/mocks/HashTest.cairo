%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_bigend
from starkware.cairo.common.uint256 import Uint256, word_reverse_endian
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, assert_lt
from starkware.cairo.common.math_cmp import is_in_range

from contracts.utils.Bytes import (
    Bytes,
    BYTES_PER_FELT
)

from contracts.utils.Utils import (
    concatHash,
    concatTwoHash,
    hashBytesToBytes20,
    hashBytes,
    hashUint256s
)

@view
func testHashBytes{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*) -> (hash : Uint256):
    alloc_locals

    local bytes : Bytes = Bytes(
        size=size,
        data_length=data_len,
        data=data
    )

    let (hash) = hashBytes(bytes)
    return (hash)
end

@view
func testHashUint256s{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(data_len : felt, data : Uint256*) -> (hash : Uint256):
    let (hash) = hashUint256s(data_len, data)
    return (hash)
end

@view
func testconcatTwoHash{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(a : Uint256, b : Uint256) -> (hash : Uint256):
    let (hash) = concatTwoHash(a, b)
    return (hash)
end

@view
func testconcatHash{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(hash : Uint256, size : felt, data_len : felt, data : felt*) -> (hash : Uint256):
    alloc_locals

    local bytes : Bytes = Bytes(
        size=size,
        data_length=data_len,
        data=data
    )
    let (hash) = concatHash(hash, bytes)
    return (hash)
end

@view
func testhashBytesToBytes20{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*) -> (hash : felt):
    alloc_locals

    local bytes : Bytes = Bytes(
        size=size,
        data_length=data_len,
        data=data
    )
    let (hash) = hashBytesToBytes20(bytes)
    return (hash)
end