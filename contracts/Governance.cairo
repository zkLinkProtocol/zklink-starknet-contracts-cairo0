# Governance Contract
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_contract_address

struct RegisteredToken:
    member registered : felt
    member paused : felt
    member token_address : felt
end

# A map of token address to id, 0 is invalid token id
@storage_var
func token_ids(address : felt) -> (token_id : felt):
end

# A map of registered token infos
@storage_var
func tokens(token_id : felt) -> (token : RegisteredToken):
end

# Governance contract address
@storage_var
func governance_address() -> (address : felt):
end

@view
func get_governance_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address : felt):
    let (address) = governance_address.read()
    return (address=address)
end

@view
func get_token_id{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_address : felt) -> (token_id : felt):
    let (token_id) = token_ids.read(token_address)
    return (token_id=token_id)
end

@view
func get_token{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_id : felt) -> (token : RegisteredToken):
    let (token : RegisteredToken) = tokens.read(token_id)
    return (token=token)
end

# Used for debug
@external
func set_token_id{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_id : felt, token_address : felt) -> ():
    token_ids.write(token_address, token_id)
    return ()
end

@external
func set_token{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_id : felt, token_address : felt) -> ():
    let token = RegisteredToken(
        registered=1,
        paused=0,
        token_address=token_address
    )
    tokens.write(token_id, token)
    return ()
end

# @external
# func init{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
#     let (current_contract_address) = get_contract_address()
#     governance_address.write(value=current_contract_address)
#     return ()
# end