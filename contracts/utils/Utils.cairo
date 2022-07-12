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
    let output = Uint256(low=input, high=0)
    return (output)
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

# # read element in pubdata
# # pubdata : array of felt, and every felt has PUBLIC_DATA_ELEMENT_BYTES bytes
# # pubdata_len : length of pubdata array, it shold be OPERATION_CHUNK_SIZE
# # bytes : size of data in bytes
# func read_pubdata{range_check_ptr}(pubdata : felt*, _offset : felt, bytes : felt) -> (offset, data):
#     # checks
#     assert_nn_le(_offset, PUBLIC_DATA_ELEMENT_BYTES * OPERATION_CHUNK_SIZE)

#     # data in one chunk or two chunks
#     let (index, chunk_offset) = unsigned_div_rem(_offset, PUBLIC_DATA_ELEMENT_BYTES)
#     let (one_chunk) = is_le(chunk_offset + bytes, PUBLIC_DATA_ELEMENT_BYTES)

#     if one_chunk == 1:
#         let (data1) = split_bytes(PUBLIC_DATA_ELEMENT_BYTES, pubdata[index], chunk_offset, bytes)
#         return (_offset + bytes, data1)
#     else:
#         let (data2_1) = split_bytes(PUBLIC_DATA_ELEMENT_BYTES, pubdata[index], chunk_offset, PUBLIC_DATA_ELEMENT_BYTES - chunk_offset)
#         let (data2_2) = split_bytes(PUBLIC_DATA_ELEMENT_BYTES, pubdata[index + 1], 0, bytes - PUBLIC_DATA_ELEMENT_BYTES + chunk_offset)
#         let (data2) = join_bytes(data1, data2, bytes - PUBLIC_DATA_ELEMENT_BYTES + chunk_offset)
#         return (_offset + bytes, data2)
#     end

# end

# func slice_public_data{range_check_ptr}(pubdata : felt*, pubdata_offset : felt, size : felt) -> (data : felt*):
#     alloc_locals
#     let (local data : felt*) = alloc()
#     _slice_public_data(pubdata=pubdata + pubdata_index, new_data=data, index=size, length=size)
# end

# func _slice_public_data{range_check_ptr}(pubdata : felt*, new_data : felt*, index : felt, length : felt):
#     if index == 0:
#         return ()
#     end
#     _slice_public_data(pubdata, new_data=new_data + 1, index=index - 1)
#     assert new_data[0] = pubdata[lenght - index]
#     return ()
# end