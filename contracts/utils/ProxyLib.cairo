%lang starknet

from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math import assert_not_zero

from contracts.utils.Events import NewGovernor, Upgraded

#
# Storage variables
#
@storage_var
func Proxy_implementation_version() -> (version : felt):
end

@storage_var
func Proxy_implementation_hash() -> (class_hash : felt):
end

@storage_var
func Proxy_governor() -> (_governor : felt):
end

@storage_var
func Proxy_initialized() -> (initialized : felt):
end

namespace Proxy:
    #
    # Initializer
    #

    func initializer{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(_governor : felt):
        let (initialized) = Proxy_initialized.read()
        with_attr error_message("Proxy: contract already initialized"):
            assert initialized = FALSE
        end

        Proxy_initialized.write(TRUE)
        _set_governor(_governor)
        return ()
    end

    #
    # Guards
    #

    func assert_only_governor{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }():
        let (caller) = get_caller_address()
        let (governor) = Proxy_governor.read()
        with_attr error_message("Proxy: caller is not governor"):
            assert governor = caller
        end
        return ()
    end

    #
    # Getters
    #

    func get_implementation_hash{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (implementation : felt):
        let (implementation) = Proxy_implementation_hash.read()
        return (implementation)
    end

    func get_implementation_version{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (version : felt):
        let (version) = Proxy_implementation_version.read()
        return (version)
    end

    func get_governor{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (governor : felt):
        let (governor) = Proxy_governor.read()
        return (governor)
    end

    #
    # Unprotected
    #

    func _set_governor{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_governor : felt):
        Proxy_governor.write(new_governor)
        NewGovernor.emit(new_governor)
        return ()
    end

    #
    # Upgrade
    #

    func _set_implementation_hash{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_implementation : felt):
        with_attr error_message("Proxy: implementation hash cannot be zero"):
            assert_not_zero(new_implementation)
        end
        let (version) = get_implementation_version()
        Proxy_implementation_hash.write(new_implementation)
        Proxy_implementation_version.write(version + 1)
        Upgraded.emit(version + 1, new_implementation)
        return ()
    end

end
