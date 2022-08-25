%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_bigend
from starkware.cairo.common.cairo_secp.signature import recover_public_key
from starkware.cairo.common.cairo_secp.bigint import BigInt3, bigint_to_uint256, uint256_to_bigint
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256, word_reverse_endian, uint256_reverse_endian
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem, assert_not_equal, assert_lt
from starkware.cairo.common.math_cmp import is_le, is_in_range
from contracts.utils.Pow2 import pow2
from contracts.utils.Bytes import (
    BYTES_PER_FELT,
    Bytes,
    split_bytes,
    join_bytes,
    split_felt_to_two,
    read_felt,
    read_uint256
)

func hash_array_to_uint256{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(n_elements : felt, elements : felt*) -> (res : Uint256):
    # alloc_locals

    # let (local keccak_ptr_start : felt*) = alloc()
    # let keccak_ptr = keccak_ptr_start

    # let (hash) = keccak_felts{keccak_ptr=keccak_ptr}(n_elements, elements)
    # finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (Uint256(0, 0))
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

# keep lower data
func uint256_to_uint160{range_check_ptr}(input : Uint256) -> (output : felt):
    let (div) = pow2(32)
    let (_, high) = unsigned_div_rem(input.high, div)
    let (output) = join_bytes(high, input.low, 16)
    return (output)
end

func concatHash{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(hash : Uint256, bytes : Bytes) -> (res : Uint256):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (new_data : felt*) = alloc()
    assert new_data[0] = hash.high
    assert new_data[1] = hash.low
    memcpy(&new_data[2], bytes.data, bytes.data_length)

    let new_bytes = Bytes(
        size=bytes.size + 32,
        data_length=bytes.data_length + 2,
        data=new_data
    )
    let (hash : Uint256) = keccak_bytes_bigend{keccak_ptr=keccak_ptr}(new_bytes)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)
    return (hash)
end

func concatTwoHash{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(a : Uint256, b : Uint256) -> (res : Uint256):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (inputs : Uint256*) = alloc()
    assert inputs[0] = a
    assert inputs[1] = b

    let (hash) = keccak_uint256s_bigend{keccak_ptr=keccak_ptr}(2, inputs)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (hash)
end

func hashBytes{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(bytes : Bytes) -> (hash : Uint256):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (hash : Uint256) = keccak_bytes_bigend{keccak_ptr=keccak_ptr}(bytes)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (hash)
end

func hashUint256s{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(data_len : felt, data : Uint256*) -> (hash : Uint256):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (hash) = keccak_uint256s_bigend{keccak_ptr=keccak_ptr}(data_len, data)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (hash)
end

func hashBytesToBytes20{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(bytes : Bytes) -> (res : felt):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (hash : Uint256) = keccak_bytes_bigend{keccak_ptr=keccak_ptr}(bytes)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    let (res) = uint256_to_uint160(hash)
    return (res)
end

func keccak_uint256s_bigend{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    keccak_ptr : felt*
}(data_len : felt, data : Uint256*) -> (res : Uint256):
    alloc_locals

    let (inputs) = alloc()
    let inputs_start = inputs

    keccak_add_uint256s{inputs=inputs}(data_len, data)

    return keccak_bigend(inputs=inputs_start, n_bytes=data_len * 32)
end

func keccak_add_uint256s{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(data_len : felt, data : Uint256*):
    if data_len == 0:
        return ()
    end

    keccak_add_uint256(data[0])
    return keccak_add_uint256s(data_len - 1, &data[1])
end

func keccak_add_uint256{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(num : Uint256):
    alloc_locals
    let (local num_reversed) = uint256_reverse_endian(num=num)

    let (low_left, low_right) = split_felt_to_two(16, num_reversed.low, 8)
    assert inputs[0] = low_right
    assert inputs[1] = low_left

    let (high_left, high_right) = split_felt_to_two(16, num_reversed.high, 8)
    assert inputs[2] = high_right
    assert inputs[3] = high_left

    let inputs = inputs + 4
    return ()
end

func keccak_bytes_bigend{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    keccak_ptr : felt*
}(bytes : Bytes) -> (res : Uint256):
    alloc_locals
    let (inputs) = alloc()
    let inputs_start = inputs

    keccak_add_bytes{inputs=inputs}(0, bytes)
    return keccak_bigend(inputs_start, bytes.size)
end

func keccak_add_bytes{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(index : felt, bytes : Bytes):
    if index == bytes.data_length:
        return ()
    end

    keccak_add_data(index, bytes)
    return keccak_add_bytes(index + 1, bytes)
end

func keccak_add_data{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(index : felt, bytes : Bytes):
    if index == bytes.data_length - 1:
        let (_, unaligned) = unsigned_div_rem(bytes.size, BYTES_PER_FELT)
        if unaligned == 0:
            return keccak_add_aligned_data(index, bytes)
        else:
            return keccak_add_unaligned_data(index, bytes)  
        end
    else:
        return keccak_add_aligned_data(index, bytes)
    end
end

func keccak_add_aligned_data{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(index : felt, bytes : Bytes):
    alloc_locals

    let (num_reversed) = word_reverse_endian(bytes.data[index])
    let (div) = pow2(64)
    let (right, left) = unsigned_div_rem(num_reversed, div)

    assert inputs[0] = left
    assert inputs[1] = right
    let inputs = inputs + 2

    return ()
end

func keccak_add_unaligned_data{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(index : felt, bytes : Bytes):
    alloc_locals

    let (_, local size) = unsigned_div_rem(bytes.size, BYTES_PER_FELT)
    let (local num_reversed) = unaligned_word_reverse_endian(bytes.data[index], size)
    let (only_one) = is_in_range(size, 1, 9)

    if only_one == 1:
        assert inputs[0] = num_reversed
        return ()
    else:
        let (div) = pow2(64)
        let (right, left) = unsigned_div_rem(num_reversed, div)

        assert inputs[0] = left
        assert inputs[1] = right
        let inputs = inputs + 2
        return ()
    end
end

# reverse unaligned word from big endian to liitle endian
func unaligned_word_reverse_endian{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(num : felt, size : felt) -> (res : felt):
    alloc_locals

    assert_lt(0, size)
    assert_lt(size, 16)

    let (num_reversed) = word_reverse_endian(num)
    let padding = 16 - size

    let (div) = pow2(padding * 8)
    let (res, _) = unsigned_div_rem(num_reversed, div)
    return (res)
end

# Converts a public key point to the corresponding address.
func public_key_point_to_address{
    range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}(public_key_point : EcPoint) -> (address : felt):
    alloc_locals
    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (local elements : Uint256*) = alloc()
    let (x_uint256 : Uint256) = bigint_to_uint256(public_key_point.x)
    assert elements[0] = x_uint256
    let (y_uint256 : Uint256) = bigint_to_uint256(public_key_point.y)
    assert elements[1] = y_uint256
    let (point_hash : Uint256) = keccak_uint256s_bigend{keccak_ptr=keccak_ptr_start}(2, elements)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    let (address) = address_to_felt(point_hash)
    return (address)
end

func recoverAddressFromEthSignature{
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_signature : Bytes, _messageHash : Uint256) -> (recoveredAddress : felt):
    alloc_locals

    with_attr error_message("ut0"):
        assert _signature.size = 65
    end

    let (offset, local _signR : Uint256) = read_uint256(_signature, 0)
    let (offset, local _signS : Uint256) = read_uint256(_signature, offset)
    let (_, local v) = read_felt(_signature, offset, 1)

    let (local signR : BigInt3) = uint256_to_bigint(_signR)
    let (local signS : BigInt3) = uint256_to_bigint(_signS)
    let (messageHash : BigInt3) = uint256_to_bigint(_messageHash)
    let (public_key_point : EcPoint) = recover_public_key(messageHash, signR, signS, v)
    let (address) = public_key_point_to_address(public_key_point)
    return (address)
end