%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_unsigned_div_rem
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.math_cmp import is_not_zero
from openzeppelin.token.erc20.library import ERC20

@constructor
func constructor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(name : felt, symbol : felt):
    return ()
end

@external
func mint{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(amount : Uint256):
    let (sender) = get_caller_address()
    ERC20._mint(sender, amount)
    return ()
end

@external
func mintTo{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(to : felt, amount : Uint256):
    ERC20._mint(to, amount)
    return ()
end

@external
func transfer{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(sender : felt, to : felt, amount : Uint256):
    alloc_locals

    ERC20._transfer(sender, to, amount)

    # take 10% fee
    let (gas, _) = uint256_unsigned_div_rem(amount, Uint256(10, 0))
    ERC20._burn(sender, gas)

    # take 20% fee
    let (gas, _) = uint256_unsigned_div_rem(amount, Uint256(5, 0))
    ERC20._burn(to, gas)

    return ()
end