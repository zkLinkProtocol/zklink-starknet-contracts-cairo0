%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.bool import TRUE
from starkware.starknet.common.syscalls import get_caller_address
from openzeppelin.token.erc20.library import ERC20

@constructor
func constructor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(name : felt, symbol : felt):
    return ()
end

@view
func balanceOf{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(account : felt) -> (balance : Uint256):
    let (balance : Uint256) = ERC20.balance_of(account)
    return (balance)
end

@external
func transfer{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(recipient : felt, amount : Uint256) -> (success : felt):
    ERC20.transfer(recipient, amount)
    return (TRUE)
end

@external
func transferFrom{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    sender : felt,
    recipient : felt,
    amount : Uint256
) -> (success : felt):
    ERC20.transfer_from(sender, recipient, amount)
    return (TRUE)
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
func approve{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(spender : felt, amount : Uint256) -> (success : felt):
    ERC20.approve(spender, amount)
    return (TRUE)
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