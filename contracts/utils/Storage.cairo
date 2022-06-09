# ZkLink storage contract
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.alloc import alloc

from contracts.utils.Operations import PriorityOperation

# Total number of requests
@storage_var
func total_open_priority_requests() -> (requests : felt):
end

@view
func get_total_open_priority_requests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (requests : felt):
    let (requests) = total_open_priority_requests.read()
    return (requests=requests)
end

# func increase_total_open_priority_requests{
#     syscall_ptr : felt*,
#     pedersen_ptr : HashBuiltin*,
#     range_check_ptr
# }():
#     return ()
# end

# Chain id defined by ZkLink
@storage_var
func chain_id() -> (chain_id : felt):
end

@view
func get_chain_id{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (chain_id : felt):
    let (id) = chain_id.read()
    return (chain_id=id)
end

# First open priority request id
@storage_var
func first_priority_request_id() -> (request_id : felt):
end

@view
func get_first_priority_request_id{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (request_id : felt):
    let (id) = first_priority_request_id.read()
    return (request_id=id)
end

func increase_first_priority_request_id{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(requests : felt):
    alloc_locals
    let (old_request_id) = get_first_priority_request_id()
    assert_nn(requests)
    local new_request_id = old_request_id + requests
    first_priority_request_id.write(new_request_id)
    return ()
end

# Priority Requests mapping (request id - operation)
# Contains op type, pubdata and expiration block of unsatisfied requests.
# Numbers are in order of requests receiving
@storage_var
func priority_requests(priority_request_id : felt) -> (operation : PriorityOperation):
end

@view
func get_priority_request{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(priority_request_id : felt) -> (operation : PriorityOperation):
    let (op : PriorityOperation) = priority_requests.read(priority_request_id)
    return (operation=op)
end

func set_priority_request{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(priority_request_id : felt, operation : PriorityOperation) -> ():
    priority_requests.write(priority_request_id, operation)
    return ()
end