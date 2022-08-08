%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem, assert_not_zero
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.pow import pow
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.memcpy import memcpy

# bytes of per felt
const FELT_MAX_BYTES = 16

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
    assert_not_zero(input_bytes)
    assert_not_zero(data_length)
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

    # data in one felt or two felts
    let (local index, local felt_offset) = unsigned_div_rem(offset + bytes._start, bytes.bytes_per_felt)
    # if the last felt of bytes.data is full filled data, full is zero
    let (_, local full) = unsigned_div_rem(bytes.size + bytes._start, bytes.bytes_per_felt)
    let (one_felt) = is_le(felt_offset + size, bytes.bytes_per_felt)

    if one_felt == 1:
        if index == bytes.data_length - 1:
            if full == 0:
                let (data) = split_bytes(bytes.bytes_per_felt, bytes.data[index], felt_offset, size)
                return (offset + size, data)
            else:
                let (data) = split_bytes(full, bytes.data[index], felt_offset, size)
                return (offset + size, data)
            end
        else:
            let (data) = split_bytes(bytes.bytes_per_felt, bytes.data[index], felt_offset, size)
            return (offset + size, data)
        end
    else:
        let (data1) = split_bytes(bytes.bytes_per_felt, bytes.data[index], felt_offset, bytes.bytes_per_felt - felt_offset)
        if index + 1 == bytes.data_length - 1:
            if full == 0:
                let (data2) = split_bytes(bytes.bytes_per_felt, bytes.data[index + 1], 0, size - bytes.bytes_per_felt + felt_offset)
                let (data) = join_bytes(data1, data2, size - bytes.bytes_per_felt + felt_offset)
                return (offset + size, data)
            else:
                let (data2) = split_bytes(full, bytes.data[index + 1], 0, size - bytes.bytes_per_felt + felt_offset)
                let (data) = join_bytes(data1, data2, size - bytes.bytes_per_felt + felt_offset)
                return (offset + size, data)
            end
        else:
            let (data2) = split_bytes(bytes.bytes_per_felt, bytes.data[index + 1], 0, size - bytes.bytes_per_felt + felt_offset)
            let (data) = join_bytes(data1, data2, size - bytes.bytes_per_felt + felt_offset)
            return (offset + size, data)
        end

    end
end

func read_felt_array{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
    array_len : felt,
    element_size : felt
) -> (new_offset : felt, res : felt*):
    alloc_locals
    let (res : felt*) = alloc()
    let (new_offset) = _read_felt_array(bytes, offset, res, array_len - 1, element_size)
    return (new_offset, res)
end

func _read_felt_array{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
    array : felt*,
    i : felt,
    element_size : felt
) -> (new_offset : felt):
    if i == -1:
        return (offset)
    end
    let (old_offset) = _read_felt_array(bytes, offset, array, i - 1, element_size)
    let (new_offset, data) = read_felt(bytes, old_offset, element_size)
    assert array[i] = data
    return (new_offset)
end

# read uint256 from bytes(big-endian)
func read_uint256{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
) -> (new_offset : felt, res : Uint256):
    alloc_locals
    # checks
    assert_nn_le(offset + 32, bytes.size)

    let (local base) = pow(256, 8)

    let (new_offset, data1) = read_felt(bytes, offset, 8)
    let (new_offset, data2) = read_felt(bytes, new_offset, 8)
    let (new_offset, data3) = read_felt(bytes, new_offset, 8)
    let (new_offset, data4) = read_felt(bytes, new_offset, 8)
    return (new_offset, Uint256(data3 * base + data4, data1 * base + data2))
end

func read_uint256_array{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
    array_len : felt,
) -> (new_offset : felt, res : Uint256*):
    alloc_locals
    let (res : Uint256*) = alloc()
    let (new_offset) = _read_uint256_array(bytes, offset, res, array_len - 1)
    return (new_offset, res)

end

func _read_uint256_array{range_check_ptr}(
    bytes : Bytes,
    offset : felt,
    array : Uint256*,
    i : felt,
) -> (new_offset : felt):
    if i == -1:
        return (offset)
    end
    let (old_offset) = _read_uint256_array(bytes, offset, array, i - 1)
    let (new_offset, data : Uint256) = read_uint256(bytes, old_offset)
    assert array[i] = data
    return (new_offset)
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


    let (local start_index, local start) = unsigned_div_rem(offset + bytes._start, bytes.bytes_per_felt)
    let (local end_index, local end_offset) = unsigned_div_rem(offset + size + bytes._start, bytes.bytes_per_felt)
    # if the last felt of bytes.data is full filled data, full is zero
    let (_, local full) = unsigned_div_rem(bytes.size + bytes._start, bytes.bytes_per_felt)

    if start_index == end_index:
        tempvar first = 0
        if start_index == bytes.data_length - 1:
            if full == 0:
                let (first) = split_bytes(bytes.bytes_per_felt, bytes.data[start_index], start, size)
            else:
                let (first) = split_bytes(full, bytes.data[start_index], start, size)
            end
        else:
            let (first) = split_bytes(bytes.bytes_per_felt, bytes.data[start_index], start, size)
        end
        
        assert data[0] = first
        return (offset + size, Bytes(
            _start=start,
            bytes_per_felt=bytes.bytes_per_felt,
            size=size,
            data_length=1,
            data=data
        ))
    else:
        if end_index - start_index == 1:
            let (first) = split_bytes(bytes.bytes_per_felt, bytes.data[start_index], start, bytes.bytes_per_felt - start)
            assert data[0] = first
            tempvar last = 0
            if end_index == bytes.data_length - 1:
                if full == 0:
                    let (last) = split_bytes(bytes.bytes_per_felt, bytes.data[end_index], 0, end_offset)
                else:
                    let (last) = split_bytes(full, bytes.data[end_index], 0, end_offset)
                end
            else:
                let (last) = split_bytes(bytes.bytes_per_felt, bytes.data[end_index], 0, end_offset)
            end
            assert data[1] = last
            return (offset + size, Bytes(
                _start=start,
                bytes_per_felt=bytes.bytes_per_felt,
                size=size,
                data_length=2,
                data=data
            ))
        else:
            let (first) = split_bytes(bytes.bytes_per_felt, bytes.data[start_index], start, bytes.bytes_per_felt - start)
            assert data[0] = first
            

            memcpy(data + 1, bytes.data + start_index + 1, end_index - start_index - 1)

            tempvar last = 0
            if end_index == bytes.data_length - 1:
                if full == 0:
                    let (last) = split_bytes(bytes.bytes_per_felt, bytes.data[end_index], 0, end_offset)
                else:
                    let (last) = split_bytes(full, bytes.data[end_index], 0, end_offset)
                end
            else:
                let (last) = split_bytes(bytes.bytes_per_felt, bytes.data[end_index], 0, end_offset)
            end
            assert data[end_index - start_index] = last
            return (offset + size, Bytes(
                _start=start,
                bytes_per_felt=bytes.bytes_per_felt,
                size=size,
                data_length=end_index - start_index + 1,
                data=data
            ))
        end
    end
end

func read_address{range_check_ptr}(
    bytes : Bytes,
    offset : felt
) -> (new_offset : felt, res : felt):
    let (new_offset, data : Uint256) = read_uint256(bytes, offset)
    return (new_offset, data.high * 2**128 + data.low)
end

func create_empty_bytes() -> (bytes : Bytes):
    let (empty_data : felt*) = alloc()
    assert empty_data[0] = 0
    return (Bytes(_start=0, bytes_per_felt=FELT_MAX_BYTES, size=0, data_length=0, data=empty_data))
end