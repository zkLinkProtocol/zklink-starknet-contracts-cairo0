%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_felts
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem, assert_not_equal
from starkware.cairo.common.math_cmp import is_le
from contracts.utils.Bytes import Bytes, split_bytes, join_bytes

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

func deserialize_address{range_check_ptr}(
    address : Uint256, len1 : felt, len2 : felt, len3 : felt
) -> (
    data_len : felt, data : felt*
):
    alloc_locals
    # make sure deserialize into 3 part, and second part len must be 16 bytes
    assert len1 + len2 + len3 = 32
    assert_not_equal(len1, 0)
    assert_nn_le(len1, 16)

    let (data : felt*) = alloc()

    let (data1) = split_bytes(16, address.high, 0, len1)
    assert data[0] = data1

    let (data2_1) = split_bytes(16, address.high, len1, 16 - len1)
    let (data2_2) = split_bytes(16, address.low, 0, len1 + len2 - 16)
    let (data2) = join_bytes(data2_1, data2_2, len1 + len2 - 16)
    assert data[1] = data2

    let (data3) = split_bytes(16, address.low, len1 + len2 - 16, len3)
    assert data[2] = data3
    return (3, data)
end

func address_to_felt(input : Uint256) -> (output : felt):
    return(input.high * 2**128 + input.low)
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