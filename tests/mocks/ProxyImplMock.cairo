%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

from contracts.utils.ProxyLib import Proxy

#
# Storage
#

@storage_var
func value() -> (res: felt):
end

#
# Initializer
#

@external
func initializer{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(_networkGovernor: felt):
    Proxy.initializer(_networkGovernor)
    return ()
end

#
# Getters
#

@view
func getValue{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (val: felt):
    let (val) = value.read()
    return (val)
end

@view
func getGovernor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address: felt):
    let (address) = Proxy.get_governor()
    return (address)
end

#
# Setters
#

@external
func setValue{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(val: felt):
    value.write(val)
    return ()
end

@external
func setGovernor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(governor : felt):
    Proxy.assert_only_governor()
    Proxy._set_governor(governor)
    return ()
end