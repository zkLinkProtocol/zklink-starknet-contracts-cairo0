%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.pow import pow
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.memcpy import memcpy

# bytes of per felt
const FELT_MAX_BYTES = 31

struct Bytes:
    member _start : felt            # cause get a sub Bytes from a Bytes, firt actual data maybe not at 0
    member bytes_per_felt : felt
    member size : felt
    member data_length : felt
    member data : felt* 
end

# read bytes of a felt
# data length in bytes
func split_bytes{
    range_check_ptr
}(input_bytes : felt, input : felt, offset : felt, data_length : felt) -> (output : felt):
    alloc_locals
    assert_nn_le(data_length, input_bytes)

    tempvar offset_end = offset + data_length
    tempvar data_end = input_bytes - offset_end

    let (move1) = pow(256, data_end)
    let (local res1, _) = unsigned_div_rem(input, move1)

    let (shit) = pow(256, data_length)
    let (_, res2) = unsigned_div_rem(res1, shit)
    
    return (output=res2)
end

func join_bytes{range_check_ptr}(a : felt, b : felt, b_length : felt) -> (res : felt):
    let (shit) = pow(256, b_length)
    let res = a * shit + b
    return (res)
end

# read data from bytes, return a felt
# bytes : Bytes instance
# offset : logic offset of bytes stream
# size : size of data to read, in bytes
func read_felt{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
    size : felt
) -> (new_offset : felt, res : felt):
    alloc_locals
    # checks
    assert_nn_le(offset + size, bytes.size)
    assert_nn_le(size * 8, 252)

    tempvar actual_offset = offset + bytes._start

    # data in one felt or two felts
    let (local index, local felt_offset) = unsigned_div_rem(actual_offset, bytes.bytes_per_felt)
    let (one_felt) = is_le(felt_offset + size, bytes.bytes_per_felt)

    if one_felt == 1:
        let (data1) = split_bytes(bytes.bytes_per_felt, bytes.data[index], felt_offset, size)
        return (offset + size, data1)
    else:
        let (data2_1) = split_bytes(bytes.bytes_per_felt, bytes.data[index], felt_offset, bytes.bytes_per_felt - felt_offset)
        let (data2_2) = split_bytes(bytes.bytes_per_felt, bytes.data[index + 1], 0, size - bytes.bytes_per_felt + felt_offset)
        let (data2) = join_bytes(data2_1, data2_2, size - bytes.bytes_per_felt + felt_offset)
        return (offset + size, data2)
    end
end

# read uint256 from bytes(big-endian)
func read_uint256{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
) -> (new_offset : felt, res : Uint256):
    alloc_locals
    # checks
    assert_nn_le(offset + 32, bytes.size)

    let (local high_offset, local high_part) = read_felt(bytes, offset, 16)
    let (local low_offset, local low_part) = read_felt(bytes, high_offset, 16)
    return (low_offset, Uint256(low_part, high_part))
end

func read_bytes{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
    size : felt
) -> (new_offset : felt, res : Bytes):
    alloc_locals
    let (local data : felt*) = alloc()
    # checks
    assert_nn_le(offset + size, bytes.size)
    with_attr error_message("size is smaller than a felt, maybe not use this function"):
        assert_nn_le(252, size * 8)
    end

    tempvar actual_offset = offset + bytes._start
    # get first felt of Bytes data
    let (local start_index, local start) = unsigned_div_rem(actual_offset, bytes.bytes_per_felt)
    let (first) = split_bytes(bytes.bytes_per_felt, bytes.data[start_index], start, bytes.bytes_per_felt - start)
    assert data[0] = first

    # copy middle felt*
    let (local end_index, local end_offset) = unsigned_div_rem(offset + size + bytes._start, bytes.bytes_per_felt)
    memcpy(data + 1, bytes.data + start_index + 1, end_index - start_index - 1)

    # get last felt of Bytes data
    let (last) = split_bytes(bytes.bytes_per_felt, bytes.data[end_index], 0, end_offset)
    assert data[end_index - start_index] = last
    return (offset + size, Bytes(
        _start=start,
        bytes_per_felt=bytes.bytes_per_felt,
        size=size,
        data_length=end_index - start_index,
        data=data
    ))
end

func create_empty_bytes() -> (bytes : Bytes):
    let (empty_data : felt*) = alloc()
    assert empty_data[0] = 0
    return (Bytes(_start=0, bytes_per_felt=FELT_MAX_BYTES, size=0, data_length=0, data=empty_data))
end