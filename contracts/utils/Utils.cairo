%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_felts
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

# Computes the keccak hash of the given input
func hash_array_to_uint256{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(n_elements : felt, elements : felt*) -> (res : Uint256):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (output) = keccak_felts{keccak_ptr=keccak_ptr}(n_elements, elements)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (res=output)
end