%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_felts
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le
from contracts.utils.Bytes import Bytes, split_bytes, join_bytes

# Computes the keccak hash of the given input
func hash_array_to_uint160{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(n_elements : felt, elements : felt*) -> (res : felt):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (hash) = keccak_felts{keccak_ptr=keccak_ptr}(n_elements, elements)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    # Uint256 has two 16 bytes(128 bit) part
    let (high_32) = split_bytes(16, hash.high, 12, 4)
    let (output) = join_bytes(high_32, hash.low, 16)

    return (res=output)
end

func hash_array_to_uint256{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(n_elements : felt, elements : felt*) -> (res : Uint256):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (hash) = keccak_felts{keccak_ptr=keccak_ptr}(n_elements, elements)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (res=hash)
end

# Convert felt to Uint256, felt should less than 2 ** 128 - 1
func felt_to_uint256{range_check_ptr}(input : felt) -> (output : Uint256):
    assert_nn_le(input, 2 ** 128 - 1)
    return (Uint256(input, 0))
end

# Convert Uint256 to felt, Uint256 high part should be 0
func uint256_to_felt{range_check_ptr}(input : Uint256) -> (output : felt):
    assert input.high = 0
    return (input.low)
end

# Return lesser of two felt
func min_felt{range_check_ptr}(a : felt, b : felt) -> (min : felt):
    let (is_less) = is_le(a, b)
    if is_less == 1:
        return (a)
    else:
        return (b)
    end
end

func concat_hash{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(_hash : Uint256, _bytes : Bytes) -> (res : Uint256):
    # TODO : keccak
    return (Uint256(0, 0))
end

func concat_two_hash{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(a : Uint256, b : Uint256) -> (res : Uint256):
    # TODO : keccak
    return (Uint256(0, 0))
end

func hashBytesToBytes20{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(bytes : Bytes) -> (res : felt):
    # TODO : keccak
    return (0)
end