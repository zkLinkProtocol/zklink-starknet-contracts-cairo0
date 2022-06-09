# Reentancy guard prevent reentrant calls to a function.
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

# Reentrancy gurad stattus, 0 is not inital
const REENTRANCY_GUARD_NOT_ENTERED = 1
const REENTRANCY_GUARD_ENTERED = 2

# Lock flag variable.
@storage_var
func reentrancy_guard() -> (res : felt):
end

func reentrancy_guard_init{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals
    let (local lock_slot_old_value) = reentrancy_guard.read()
    with_attr error_message("1B"):
        assert lock_slot_old_value = 0
    end
    reentrancy_guard.write(value=REENTRANCY_GUARD_NOT_ENTERED)
    return ()
end

func reentrancy_guard_lock{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    let (lock) = reentrancy_guard.read()
    with_attr error_message("1C"):
        assert lock = REENTRANCY_GUARD_NOT_ENTERED
    end
    reentrancy_guard.write(value=REENTRANCY_GUARD_ENTERED)
    return ()
end

func reentrancy_guard_unlock{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    reentrancy_guard.write(value=REENTRANCY_GUARD_NOT_ENTERED)
    return ()
end