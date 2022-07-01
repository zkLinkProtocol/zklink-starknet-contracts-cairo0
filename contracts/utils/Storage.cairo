# ZkLink storage contract
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_nn, assert_not_equal
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_contract_address, get_caller_address
from starkware.cairo.common.uint256 import Uint256

from contracts.utils.Operations import PriorityOperation
from contracts.utils.Bytes import Bytes, read_felt, read_uint256

# Indicates that exodus (mass exit) mode is triggered.
# Once it was raised, it can not be cleared again, and all users must exit
@storage_var
func exodus_mode() -> (res : felt):
end

@view
func get_exodus_mode{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (res : felt):
    let (mode) = exodus_mode.read()
    return (mode)
end

func active{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}():
    let (exodus_mode_stat) = get_exodus_mode()
    with_attr error_message("0"):
        assert exodus_mode_stat = 0
    end
    return ()
end

func not_active{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}():
    let (exodus_mode_stat) = get_exodus_mode()
    with_attr error_message("1"):
        assert exodus_mode_stat = 1
    end
    return ()
end

# Verifier contract address. Used to verify block proof and exit proof
@storage_var
func verifier_contract_address() -> (address : felt):
end

@view
func get_verifier_contract_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address : felt):
    let (address) = verifier_contract_address.read()
    return (address)
end

func set_verifier_contract_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt):
    verifier_contract_address.write(address)
    return ()
end

# Periphery contract address. Contains some auxiliary features
@storage_var
func periphery_contract_address() -> (address : felt):
end

@view
func get_periphery_contract_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address : felt):
    let (address) = periphery_contract_address.read()
    return (address)
end

func set_periphery_contract_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt):
    periphery_contract_address.write(address)
    return ()
end

# Network Governor address. The the owner of whole system
@storage_var
func network_governor_address() -> (address : felt):
end

@view
func get_network_governor_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address : felt):
    let (address) = network_governor_address.read()
    return (address)
end

func set_network_governor_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt):
    network_governor_address.write(address)
    return ()
end

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

# Total number of committed requests.
@storage_var
func total_committed_priority_requests() -> (requests : felt):
end

@view
func get_total_committed_priority_requests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (requests : felt):
    let (requests) = total_committed_priority_requests.read()
    return (requests=requests)
end

func add_total_committed_priority_requests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(amount : felt):
    let (old_total_committed_priority_requests) = get_total_committed_priority_requests()
    total_committed_priority_requests.write(old_total_committed_priority_requests + amount)
    return ()
end

# Priority Requests mapping (request id - operation)
# Contains op type, pubdata and expiration block of unsatisfied requests.
# Numbers are in order of requests receiving
@storage_var
func priority_requests(request_id : felt) -> (op : PriorityOperation):
end

@view
func get_priority_requests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(request_id : felt) -> (op : PriorityOperation):
    let (op : PriorityOperation) = priority_requests.read(request_id)
    return (op)
end

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

struct RegisteredToken:
    member registered : felt    # whether token registered to ZkLink or not, default is false
    member paused : felt        # whether token can deposit to ZkLink or not, default is false
    member token_address : felt # the token address
    member standard : felt      # if a standard token
end

# A map of token address to id, 0 is invalid token id
@storage_var
func token_ids(address : felt) -> (token_id : felt):
end

# A map of registered token infos
@storage_var
func tokens(token_id : felt) -> (token : RegisteredToken):
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

# @external
# func set_token{
#     syscall_ptr : felt*,
#     pedersen_ptr : HashBuiltin*,
#     range_check_ptr
# }(token_id : felt, token_address : felt) -> ():
#     let token = RegisteredToken(
#         registered=1,
#         paused=0,
#         token_address=token_address,

#     )
#     tokens.write(token_id, token)
#     return ()
# end

func only_delegate_call{syscall_ptr : felt*}():
    let (sender) = get_caller_address()
    let (current_contract_address) = get_contract_address()
    with_attr error_message("2"):
        assert_not_equal(sender, current_contract_address)
    end
    return ()
end

# List of permitted validators
@storage_var
func validators(address : felt) -> (valid : felt):
end

@view
func get_validator{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt) -> (valid : felt):
    let (valid) = validators.read(address)
    return (valid)
end

func add_validator{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt):
    validators.write(address, 1)
    return ()
end

func only_validator{syscall_ptr : felt*}():
    let (sender) = get_caller_address()
    let (valid) = get_validator(sender)
    with_attr error_message("4"):
        assert valid = 1
    end
    return ()
end

# Total number of committed blocks i.e. blocks[totalBlocksCommitted] points at the latest committed block
@storage_var
func total_blocks_committed() -> (res : felt):
end

@view
func get_total_blocks_committed{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (res : felt):
    let (res) = total_blocks_committed.read()
    return (res)
end

struct StoredBlockInfo:
    member block_number : felt                          # uint32, Rollup block number
    member priority_operations : felt                   # uint64, Number of priority operations processed
    member pending_onchain_operations_hash : Uint256    # bytes32, Hash of all operations that must be processed after verify
    member timestamp : Uint256                          # uint256, Rollup block timestamp, have the same format as Ethereum block constant
    member state_hash : Uint256                         # bytes32, Root hash of the rollup state
    member commitment : Uint256                         # bytes32, Verified input for the ZkLink circuit
    member sync_hash : Uint256                          # bytes32, Used for cross chain block verify
end

func parse_stored_block_info{range_check_ptr}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : StoredBlockInfo):
    let (offset, block_number) = read_felt(bytes, _offset, 4)
    let (offset, priority_operations) = read_felt(bytes, offset, 8)
    let (offset, pending_onchain_operations_hash : Uint256) = read_uint256(bytes, offset)
    let (offset, timestamp : Uint256) = read_uint256(bytes, offset)
    let (offset, state_hash : Uint256) = read_uint256(bytes, offset)
    let (offset, commitment : Uint256) = read_uint256(bytes, offset)
    let (offset, sync_hash : Uint256) = read_uint256(bytes, offset)

    return (offset, StoredBlockInfo(
        block_number=block_number,
        priority_operations=priority_operations,
        pending_onchain_operations_hash=pending_onchain_operations_hash,
        timestamp=timestamp,
        state_hash=state_hash,
        commitment=commitment,
        sync_hash=sync_hash
    ))
end

func convert_stored_block_info_to_array(data : StoredBlockInfo) -> (n_elements : felt, elements : felt*):
    alloc_locals
    local elements : felt*
    let (local elements : felt*) = alloc()

    assert elements[0] = data.block_number
    assert elements[1] = data.priority_operations
    assert elements[2] = data.pending_onchain_operations_hash
    assert elements[3] = data.timestamp
    assert elements[4] = data.state_hash
    assert elements[5] = data.commitment
    assert elements[6] = data.sync_hash

    return (n_elements=7, elements=elements)
end

# Stored hashed StoredBlockInfo for some block number
@storage_var
func storedBlockHashes(block_id : felt) -> (hash : Uint256):
end

@view
func get_storedBlockHashes{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(block_id : felt) -> (hash : Uint256):
    let (hash : Uint256) = storedBlockHashes.read(block_id)
    return (hash)
end

func add_storedBlockHashes{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(block_id : felt, hash : Uint256):
    storedBlockHashes.write(block_id, hash)
    return ()
end

# Root-chain balances (per owner and token id) to withdraw
@storage_var
func pending_balance(owner_and_token_id : (felt, felt)) -> (balance : felt):
end

@view
func get_pending_balance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_token_id : (felt, felt)) -> (balance : felt):
    let (balance) = pending_balance.read(owner_and_token_id)
    return (balance)
end

func add_pending_balance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_token_id : (felt, felt), balance : felt):
    pending_balance.write(owner_and_token_id, balance)
    return ()
end

@storage_var
func auth_facts(owner_and_nonce : (felt, felt)) -> (res : Uint256):
end

@view
func get_auth_facts{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_nonce : (felt, felt)) -> (res : Uint256):
    let (res) = auth_facts.read(owner_and_nonce)
    return (res)
end

func add_auth_facts{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_nonce : (felt, felt), res : Uint256):
    auth_facts.write(owner_and_nonce, res)
    return ()
end
