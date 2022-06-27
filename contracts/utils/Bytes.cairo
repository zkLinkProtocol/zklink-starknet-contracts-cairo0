%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn_le

struct Bytes:
    member data_length : felt
    member size : felt
    member data : felt* 
end

# read bytes of a felt
# data length in bytes
func split_bytes{
    range_check_ptr
}(input_bytes : felt, input : felt, offset : felt, data_length : felt) -> (output : felt):
    assert_nn_le(data_length, input_bytes)

    tempvar offset_end = offset + data_length
    tempvar data_end = input_bytes - offset_end

    let (move1) = pow(256, data_end)
    let (res1, _) = unsigned_div_rem(input, move1)

    let (shit) = pow(256, data_length)
    let (_, res2) = unsigned_div_rem(res1, shit)
    
    return (output=res2)
end

func join_bytes{range_check_ptr}(a : felt, b : felt, b_length : felt) -> (res : felt):
    let (shit) = pow(256, b_length)
    let res = a * shit + b
    return (res)
end