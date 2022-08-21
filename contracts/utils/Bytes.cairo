%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem, assert_not_zero, assert_lt
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.pow import pow
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.memcpy import memcpy

# bytes of per felt
const BYTES_PER_FELT = 16

struct Bytes:
    member size : felt
    member data_length : felt
    member data : felt* 
end

# split a felt into two parts, [0, at] and (at, end]
func split_felt_to_two{
    range_check_ptr
}(input_bytes : felt, input : felt, at : felt) -> (left : felt, right):
    assert_not_zero(at)
    assert_lt(at, input_bytes)

    let base = input_bytes - at

    let (move1) = pow(256, base)
    let (left, right) = unsigned_div_rem(input, move1)
    
    return (left, right)
end

# read bytes of a felt
# data length in bytes
func split_bytes{
    range_check_ptr
}(input_bytes : felt, input : felt, offset : felt, data_length : felt) -> (output : felt):
    alloc_locals
    assert_not_zero(input_bytes)
    assert_not_zero(data_length)
    assert_nn_le(offset + data_length, input_bytes)

    if data_length == input_bytes:
        return (input)
    end

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

# In case of that, offset is 0, index will plus 1 for real index
func get_end_bytes_index_and_offset{range_check_ptr}(_offset : felt, _bytes_per_felt : felt) -> (index : felt, offset : felt):
    let (index, offset) = unsigned_div_rem(_offset, _bytes_per_felt)
    if offset == 0:
        return (index - 1, _bytes_per_felt)
    else:
        return (index, offset)
    end
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
    let (local index, local felt_offset) = unsigned_div_rem(offset, BYTES_PER_FELT)
    # if the last felt of bytes.data is aligned, unaligned is zero
    let (_, local unaligned) = unsigned_div_rem(bytes.size, BYTES_PER_FELT)
    let (one_felt) = is_le(felt_offset + size, BYTES_PER_FELT)

    if one_felt == 1:
        if index == bytes.data_length - 1:
            if unaligned == 0:
                let (data) = split_bytes(BYTES_PER_FELT, bytes.data[index], felt_offset, size)
                return (offset + size, data)
            else:
                let (data) = split_bytes(unaligned, bytes.data[index], felt_offset, size)
                return (offset + size, data)
            end
        else:
            let (data) = split_bytes(BYTES_PER_FELT, bytes.data[index], felt_offset, size)
            return (offset + size, data)
        end
    else:
        let (data1) = split_bytes(BYTES_PER_FELT, bytes.data[index], felt_offset, BYTES_PER_FELT - felt_offset)
        if index + 1 == bytes.data_length - 1:
            if unaligned == 0:
                let (data2) = split_bytes(BYTES_PER_FELT, bytes.data[index + 1], 0, size - BYTES_PER_FELT + felt_offset)
                let (data) = join_bytes(data1, data2, size - BYTES_PER_FELT + felt_offset)
                return (offset + size, data)
            else:
                let (data2) = split_bytes(unaligned, bytes.data[index + 1], 0, size - BYTES_PER_FELT + felt_offset)
                let (data) = join_bytes(data1, data2, size - BYTES_PER_FELT + felt_offset)
                return (offset + size, data)
            end
        else:
            let (data2) = split_bytes(BYTES_PER_FELT, bytes.data[index + 1], 0, size - BYTES_PER_FELT + felt_offset)
            let (data) = join_bytes(data1, data2, size - BYTES_PER_FELT + felt_offset)
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


    let (local start_index, local start_offset) = unsigned_div_rem(offset, BYTES_PER_FELT)
    let (local end_index, local end_offset) = get_end_bytes_index_and_offset(offset + size, BYTES_PER_FELT)

    # if the last felt of bytes.data is aligned, unaligned is zero
    let (_, local unaligned) = unsigned_div_rem(bytes.size, BYTES_PER_FELT)

    if start_index == end_index:
        if start_index == bytes.data_length - 1:
            if unaligned == 0:
                let (first) = split_bytes(BYTES_PER_FELT, bytes.data[start_index], start_offset, size)
            else:
                let (first) = split_bytes(unaligned, bytes.data[start_index], start_offset, size)
            end 
        else:
            let (first) = split_bytes(BYTES_PER_FELT, bytes.data[start_index], start_offset, size)
        end
        
        assert data[0] = first
        return (offset + size, Bytes(
            size=size,
            data_length=1,
            data=data
        ))
    else:
        if end_index - start_index == 1:
            # one or two felt
            let (local one_felt) = is_le(size, BYTES_PER_FELT)
            let (local first) = split_bytes(BYTES_PER_FELT, bytes.data[start_index], start_offset, BYTES_PER_FELT - start_offset)
            if end_index == bytes.data_length - 1:
                if unaligned == 0:
                    let (last) = split_bytes(BYTES_PER_FELT, bytes.data[end_index], 0, end_offset)
                else:
                    let (last) = split_bytes(unaligned, bytes.data[end_index], 0, end_offset)
                end
            else:
                let (last) = split_bytes(BYTES_PER_FELT, bytes.data[end_index], 0, end_offset)
            end
            
            if one_felt == 1:
                let (joined_data) = join_bytes(first, last, end_offset)
                assert data[0] = joined_data
                return (offset + size, Bytes(
                    size=size,
                    data_length=1,
                    data=data
                ))
            else:
                if start_offset == 0:
                    assert data[0] = first
                    assert data[1] = last
                    return (offset + size, Bytes(
                        size=size,
                        data_length=2,
                        data=data
                    ))
                else:
                    let (data2_1, data2_2) = split_felt_to_two(end_offset, last, start_offset)
                    let (data1) = join_bytes(first, data2_1, start_offset)
                    assert data[0] = data1
                    assert data[1] = data2_2
                    return (offset + size, Bytes(
                        size=size,
                        data_length=2,
                        data=data
                    ))
                end
            end
        else:
            # align front data
            align_sub_bytes(bytes, start_index, end_index, data, 0, start_offset)

            # last
            let (local one_felt) = is_le(0, start_offset - end_offset)
            let (local first) = split_bytes(BYTES_PER_FELT, bytes.data[end_index - 1], offset, BYTES_PER_FELT - offset)
            if end_index == bytes.data_length - 1:
                if unaligned == 0:
                    let (last) = split_bytes(BYTES_PER_FELT, bytes.data[end_index], 0, end_offset)
                else:
                    let (last) = split_bytes(unaligned, bytes.data[end_index], 0, end_offset)
                end
            else:
                let (last) = split_bytes(BYTES_PER_FELT, bytes.data[end_index], 0, end_offset)
            end

            if one_felt == 1:
                let (joined_data) = join_bytes(first, last, end_offset)
                assert data[end_index - start_index - 1] = joined_data
                return (offset + size, Bytes(
                    size=size,
                    data_length=end_index - start_index,
                    data=data
                ))
            else:
                if start_offset == 0:
                    assert data[end_index - start_index - 1] = first
                    assert data[end_index - start_index] = last
                    return (offset + size, Bytes(
                        size=size,
                        data_length=end_index - start_index + 1,
                        data=data
                    ))
                else:
                    let (data2_1, data2_2) = split_felt_to_two(end_offset, last, start_offset)
                    let (data1) = join_bytes(first, data2_1, start_offset)
                    assert data[end_index - start_index - 1] = data1
                    assert data[end_index - start_index] = data2_2
                    return (offset + size, Bytes(
                        size=size,
                        data_length=end_index - start_index + 1,
                        data=data
                    ))
                end
            end
        end
    end
end

func align_sub_bytes{
    range_check_ptr
}(
    bytes : Bytes,
    bytes_index : felt,
    bytes_end_offset : felt,
    new_bytes_data : felt*,
    new_bytes_index : felt,
    offset : felt
):
    alloc_locals
    if bytes_index == bytes_end_offset - 1:
        return ()
    end

    if offset == 0:
        assert new_bytes_data[new_bytes_index] = bytes.data[bytes_index]
        tempvar range_check_ptr = range_check_ptr
    else:
        let (data1) = split_bytes(BYTES_PER_FELT, bytes.data[bytes_index], offset, BYTES_PER_FELT - offset)
        let (data2) = split_bytes(BYTES_PER_FELT, bytes.data[bytes_index + 1], 0, offset)
        let (data) = join_bytes(data1, data2, offset)
        assert new_bytes_data[new_bytes_index] = data
        tempvar range_check_ptr = range_check_ptr
    end

    return align_sub_bytes(bytes, bytes_index + 1, bytes_end_offset, new_bytes_data, new_bytes_index + 1, offset)
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
    return (Bytes(size=0, data_length=0, data=empty_data))
end