%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_bigend
from starkware.cairo.common.uint256 import Uint256, word_reverse_endian
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, assert_lt
from starkware.cairo.common.math_cmp import is_in_range
from starkware.cairo.common.pow import pow
from contracts.utils.Bytes import Bytes, FELT_MAX_BYTES


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

# reverse unaligned word from big endian to liitle endian
func unaligned_word_reverse_endian{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(num : felt, size : felt) -> (res : felt):
    alloc_locals

    assert_lt(0, size)
    assert_lt(size, 16)

    let (local num_reversed) = word_reverse_endian(num)
    tempvar padding = 16 - size

    let (div) = pow(256, padding)
    let (res, _) = unsigned_div_rem(num_reversed, div)
    return (res)
end

func keccak_add_aligned_data{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(index : felt, bytes : Bytes):
    alloc_locals

    let (local num_reversed) = word_reverse_endian(bytes.data[index])
    let (div) = pow(256, 8)
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

    let (_, local size) = unsigned_div_rem(bytes.size, bytes.bytes_per_felt)
    let (local num_reversed) = unaligned_word_reverse_endian(bytes.data[index], size)
    let (only_one) = is_in_range(size, 1, 9)

    if only_one == 1:
        assert inputs[0] = num_reversed
        return ()
    else:
        let (div) = pow(256, 8)
        let (right, left) = unsigned_div_rem(num_reversed, div)

        assert inputs[0] = left
        assert inputs[1] = right
        let inputs = inputs + 2
        return ()
    end
end

func keccak_add_data{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*,
    inputs : felt*
}(index : felt, bytes : Bytes):
    if index == bytes.data_length - 1:
        let (_, unaligned) = unsigned_div_rem(bytes.size, bytes.bytes_per_felt)
        if unaligned == 0:
            return keccak_add_aligned_data(index, bytes)
        else:
            return keccak_add_unaligned_data(index, bytes)  
        end
    else:
        return keccak_add_aligned_data(index, bytes)
    end
end

@view
func testReverse{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(num : felt, size : felt) -> (res : felt):
    let (res) = unaligned_word_reverse_endian(num, size)
    return (res)
end

@view
func testAddBytes{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*) -> (input_len : felt, input : felt*):
    alloc_locals

    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )

    let (inputs) = alloc()
    let inputs_start = inputs

    keccak_add_bytes{inputs=inputs}(0, bytes)

    return (2, inputs_start)
end

@view
func computeBytesHash{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*) -> (hash : Uint256):
    alloc_locals

    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (hash) = keccak_bytes_bigend{keccak_ptr=keccak_ptr}(bytes)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (hash)
end