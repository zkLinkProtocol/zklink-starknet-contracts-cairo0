# ZkLink storage contract
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.math import assert_nn, assert_not_equal, assert_lt
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_contract_address, get_caller_address
from starkware.cairo.common.uint256 import Uint256

from contracts.utils.Operations import PriorityOperation
from contracts.utils.Bytes import Bytes, read_felt, read_uint256, join_bytes, split_felt_to_two
from contracts.utils.ProxyLib import Proxy
from contracts.utils.Utils import hashBytes

# ETH_ADDRESS
@storage_var
func eth_address() -> (address : felt):
end

@view
func get_eth_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address : felt):
    let (address) = eth_address.read()
    return (address)
end

@external
func set_eth_address{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt):
    Proxy.assert_only_governor()
    eth_address.write(address)
    return ()
end

# Total number of executed blocks i.e. blocks[totalBlocksExecuted] points at the latest executed block (block 0 is genesis)
@storage_var
func totalBlocksExecuted() -> (blocks : felt):
end

@view
func get_totalBlocksExecuted{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (res : felt):
    let (blocks) = totalBlocksExecuted.read()
    return (blocks)
end

func set_totalBlocksExecuted{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(blocks : felt):
    assert_nn(blocks)
    totalBlocksExecuted.write(blocks)
    return ()
end

func increase_totalBlocksExecuted{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(blocks : felt):
    let (old_totalBlocksExecuted) = get_totalBlocksExecuted()
    tempvar new_totalBlocksExecuted = old_totalBlocksExecuted + blocks
    assert_nn(new_totalBlocksExecuted)
    totalBlocksExecuted.write(new_totalBlocksExecuted)
    return ()
end

# Indicates that exodus (mass exit) mode is triggered.
# Once it was raised, it can not be cleared again, and all users must exit
@storage_var
func exodusMode() -> (res : felt):
end

@view
func get_exodusMode{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (res : felt):
    let (mode) = exodusMode.read()
    return (mode)
end

func set_exodusMode{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(value : felt):
    exodusMode.write(value)
    return ()
end

func active{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}():
    let (exodus_mode_stat) = get_exodusMode()
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
    let (exodus_mode_stat) = get_exodusMode()
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

# Total number of committed blocks i.e. blocks[totalBlocksCommitted] points at the latest committed block
@storage_var
func totalBlocksCommitted() -> (blocks : felt):
end

@view
func get_totalBlocksCommitted{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (blocks : felt):
    let (blocks) = totalBlocksCommitted.read()
    return (blocks)
end

func set_totalBlocksCommitted{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(blocks : felt):
    totalBlocksCommitted.write(blocks)
    return ()
end

# Total blocks proven.
@storage_var
func totalBlocksProven() -> (blocks : felt):
end

@view
func get_totalBlocksProven{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (blocks : felt):
    let (blocks) = totalBlocksProven.read()
    return (blocks)
end

func set_totalBlocksProven{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(blocks : felt):
    totalBlocksProven.write(blocks)
    return ()
end

# Latest synchronized block height
@storage_var
func totalBlocksSynchronized() -> (height : felt):
end

@view
func get_totalBlocksSynchronized{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (height : felt):
    let (blocks) = totalBlocksSynchronized.read()
    return (blocks)
end

func set_totalBlocksSynchronized{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(height : felt):
    totalBlocksSynchronized.write(height)
    return ()
end

# Total number of requests
@storage_var
func totalOpenPriorityRequests() -> (requests : felt):
end

@view
func get_totalOpenPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (requests : felt):
    let (requests) = totalOpenPriorityRequests.read()
    return (requests=requests)
end

func set_totalOpenPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(requests : felt):
    totalOpenPriorityRequests.write(requests)
    return ()
end

func sub_totalOpenPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(requests : felt):
    let (old_totalOpenPriorityRequests) = get_totalOpenPriorityRequests()
    tempvar new_totalOpenPriorityRequests = old_totalOpenPriorityRequests - requests
    assert_nn(new_totalOpenPriorityRequests)
    totalOpenPriorityRequests.write(new_totalOpenPriorityRequests)
    return ()
end

# Total number of committed requests.
@storage_var
func totalCommittedPriorityRequests() -> (requests : felt):
end

@view
func get_totalCommittedPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (requests : felt):
    let (requests) = totalCommittedPriorityRequests.read()
    return (requests=requests)
end

func increase_totalCommittedPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(amount : felt):
    let (old_totalCommittedPriorityRequests) = get_totalCommittedPriorityRequests()
    tempvar new_totalCommittedPriorityRequests = old_totalCommittedPriorityRequests + amount
    assert_nn(new_totalCommittedPriorityRequests)
    totalCommittedPriorityRequests.write(new_totalCommittedPriorityRequests)
    return ()
end

func sub_totalCommittedPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(amount : felt):
    let (old_totalCommittedPriorityRequests) = get_totalCommittedPriorityRequests()
    tempvar new_totalCommittedPriorityRequests = old_totalCommittedPriorityRequests - amount
    assert_nn(new_totalCommittedPriorityRequests)
    totalCommittedPriorityRequests.write(new_totalCommittedPriorityRequests)
    return ()
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
func firstPriorityRequestId() -> (request_id : felt):
end

@view
func get_firstPriorityRequestId{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (request_id : felt):
    let (id) = firstPriorityRequestId.read()
    return (request_id=id)
end

func increase_firstPriorityRequestId{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(requests : felt):
    alloc_locals
    let (old_firstPriorityRequestId) = get_firstPriorityRequestId()
    tempvar new_firstPriorityRequestId = old_firstPriorityRequestId + requests
    assert_nn(new_firstPriorityRequestId)
    firstPriorityRequestId.write(new_firstPriorityRequestId)
    return ()
end

# Priority Requests mapping (request id - operation)
# Contains op type, pubdata and expiration block of unsatisfied requests.
# Numbers are in order of requests receiving
@storage_var
func priorityRequests(priority_request_id : felt) -> (operation : PriorityOperation):
end

@view
func get_priorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(priority_request_id : felt) -> (operation : PriorityOperation):
    let (op : PriorityOperation) = priorityRequests.read(priority_request_id)
    return (operation=op)
end

func set_priorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(priority_request_id : felt, operation : PriorityOperation) -> ():
    priorityRequests.write(priority_request_id, operation)
    return ()
end

func delete_priorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(priority_request_id : felt) -> ():
    priorityRequests.write(priority_request_id, PriorityOperation(0, 0, 0))
    return ()
end

struct RegisteredToken:
    member registered : felt        # whether token registered to ZkLink or not, default is false
    member paused : felt            # whether token can deposit to ZkLink or not, default is false
    member tokenAddress : felt      # the token address
    member standard : felt          # if a standard token
    member mappingTokenId : felt    # eg. USDC -> USD, zero means no mapping token
end

# A map of token address to id, 0 is invalid token id
@storage_var
func token_ids(address : felt) -> (token_id : felt):
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


func set_token_id{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_address : felt, token_id : felt) -> ():
    token_ids.write(token_address, token_id)
    return ()
end

# A map of registered token infos
@storage_var
func tokens(token_id : felt) -> (token : RegisteredToken):
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

func set_token{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_id : felt, rt : RegisteredToken) -> ():
    tokens.write(token_id, rt)
    return ()
end

# We can set `enableBridgeTo` and `enableBridgeTo` to false to disable bridge when `bridge` is compromised
struct BridgeInfo:
    member bridge : felt    # bridge address
    member enableBridgeTo : felt
    member enableBridgeFrom : felt
end

@storage_var
func bridge_length() -> (n : felt):
end

@view
func get_bridge_length{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (length : felt):
    let (length) = bridge_length.read()
    return (length)
end

@storage_var
func bridges(index : felt) -> (info : BridgeInfo):
end

@view
func get_bridge{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(index : felt) -> (info : BridgeInfo):
    let (info : BridgeInfo) = bridges.read(index)
    return (info)
end

func add_bridge{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(info : BridgeInfo):
    let (index) = bridge_length.read()
    bridges.write(index + 1, info)
    bridge_length.write(index + 1)
    return ()
end

func update_bridge{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(index : felt, info : BridgeInfo):
    bridges.write(index, info)
    return ()
end

@storage_var
func bridgeIndex(address : felt) -> (index : felt):
end

@view
func get_bridgeIndex{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt) -> (index : felt):
    let (index) = bridgeIndex.read(address)
    return (index)
end

func set_bridgeIndex{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt):
    let (index) = bridge_length.read()
    bridgeIndex.write(address, index)
    return ()
end

# Accept infos of fast withdraw of account
# uint32 is the account id
# byte32 is keccak256(abi.encodePacked(receiver, tokenId, amount, withdrawFeeRate, nonce))
# address is the accepter
@storage_var
func accepts(accountId_and_hash : (felt, Uint256)) -> (address : felt):
end

@view
func get_accept{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(accountId_and_hash : (felt, Uint256)) -> (address : felt):
    let (address) = accepts.read(accountId_and_hash)
    return (address)
end

func set_accept{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(accountId_and_hash : (felt, Uint256), address : felt):
    accepts.write(accountId_and_hash, address)
    return ()
end

# Broker allowance used in accept
@storage_var
func brokerAllowances(key : (felt, felt, felt)) -> (allowance : felt):
end

@view
func get_brokerAllowances{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(key : (felt, felt, felt)) -> (allowance : felt):
    let (allowance) = brokerAllowances.read(key)
    return (allowance)
end

func set_brokerAllowances{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(key : (felt, felt, felt), allowance : felt):
    brokerAllowances.write(key, allowance)
    return ()
end



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

func set_validator{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(address : felt, _active : felt):
    validators.write(address, _active)
    return ()
end

func only_validator{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}():
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
    alloc_locals
    let (offset, local block_number) = read_felt(bytes, _offset, 4)
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

func writeStoredBlockInfoForHash{range_check_ptr}(info : StoredBlockInfo) -> (bytes : Bytes):
    alloc_locals
    let (data : felt*) = alloc()

    # bytes of Withdraw member (172 bytes)
    # block_number :                    4
    # priority_operations :             8
    # pending_onchain_operations_hash : 32
    # timestamp :                       32
    # state_hash :                      32
    # commitment :                      32
    # sync_hash :                       32

    # data[0] = block_number + priority_operations + pending_onchain_operations_hash_high (4 bytes)
    let (value) = join_bytes(info.block_number, info.priority_operations, 8)
    let (pending_onchain_operations_hash_high1, local pending_onchain_operations_hash_high2) = split_felt_to_two(16, info.pending_onchain_operations_hash.high, 4)
    let (value) = join_bytes(value, pending_onchain_operations_hash_high1, 4)
    assert data[0] = value
    # data[1] = pending_onchain_operations_hash_high(12 bytes) + pending_onchain_operations_hash_low(4 bytes)
    let (pending_onchain_operations_hash_low1, local pending_onchain_operations_hash_low2) = split_felt_to_two(16, info.pending_onchain_operations_hash.low, 4)
    let (value) = join_bytes(pending_onchain_operations_hash_high2, pending_onchain_operations_hash_low1, 4)
    assert data[1] = value
    # data[2] = pending_onchain_operations_hash_low(12 bytes) + timestamp_high(4 bytes)
    let (timestamp_high1, local timestamp_high2) = split_felt_to_two(16, info.timestamp.high, 4)
    let (value) = join_bytes(pending_onchain_operations_hash_low2, timestamp_high1, 4)
    assert data[2] = value
    # data[3] = timestamp_high(12 bytes) + timestamp_low(4 bytes)
    let (timestamp_low1, local timestamp_low2) = split_felt_to_two(16, info.timestamp.low, 4)
    let (value) = join_bytes(timestamp_high2, timestamp_low1, 4)
    assert data[3] = value
    # data[4] = timestamp_low(12 bytes) + state_hash_high(4 bytes)
    let (state_hash_high1, local state_hash_high2) = split_felt_to_two(16, info.state_hash.high, 4)
    let (value) = join_bytes(timestamp_low2, state_hash_high1, 4)
    assert data[4] = value
    # data[5] = state_hash_high(12 bytes) + state_hash_low(4 bytes)
    let (state_hash_low1, local state_hash_low2) = split_felt_to_two(16, info.state_hash.low, 4)
    let (value) = join_bytes(state_hash_high2, state_hash_low1, 4)
    assert data[5] = value
    # data[6] = state_hash_low(12 bytes) + commitment_high(4 bytes)
    let (commitment_high1, local commitment_high2) = split_felt_to_two(16, info.commitment.high, 4)
    let (value) = join_bytes(state_hash_low2, commitment_high1, 4)
    assert data[6] = value
    # data[7] = commitment_high(12 bytes) + commitment_low(4 bytes)
    let (commitment_low1, local commitment_low2) = split_felt_to_two(16, info.commitment.low, 4)
    let (value) = join_bytes(commitment_high2, commitment_low1, 4)
    assert data[7] = value
    # data[8] = commitment_low(12 bytes) + sync_hash_high(4 bytes)
    let (sync_hash_high1, local sync_hash_high2) = split_felt_to_two(16, info.sync_hash.high, 4)
    let (value) = join_bytes(commitment_low2, sync_hash_high1, 4)
    assert data[8] = value
    # data[9] = sync_hash_high(12 bytes) + sync_hash_low(4 bytes)
    let (sync_hash_low1, local sync_hash_low2) = split_felt_to_two(16, info.sync_hash.low, 4)
    let (value) = join_bytes(sync_hash_high2, sync_hash_low1, 4)
    assert data[9] = value
    # data[10] = sync_hash_low(12 bytes)
    assert data[10] = sync_hash_low2

    return (Bytes(
        size=172,
        data_length=11,
        data=data
    ))
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

func set_storedBlockHashes{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(block_id : felt, hash : Uint256):
    storedBlockHashes.write(block_id, hash)
    return ()
end

# if `synchronizedChains` | CHAIN_INDEX equals to `ALL_CHAINS` defined in `Config.sol` then blocks at `blockHeight` and before it can be executed
# the key is the `syncHash` of `StoredBlockInfo`
# the value is the `synchronizedChains` of `syncHash` collected from all other chains
@storage_var
func synchronizedChains(key : Uint256) -> (value : Uint256):
end

@view
func get_synchronizedChains{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(key : Uint256) -> (value : Uint256):
    let (value : Uint256) = synchronizedChains.read(key)
    return (value)
end

func set_synchronizedChains{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(key : Uint256, value : Uint256):
    synchronizedChains.write(key, value)
    return ()
end

# Root-chain balances (per owner and token id) to withdraw
@storage_var
func pendingBalances(owner_and_token_id : (felt, felt)) -> (balance : felt):
end

@view
func get_pendingBalances{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_token_id : (felt, felt)) -> (balance : felt):
    let (balance) = pendingBalances.read(owner_and_token_id)
    return (balance)
end

func set_pendingBalances{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_token_id : (felt, felt), amount : felt):
    pendingBalances.write(owner_and_token_id, amount)
    return ()
end

# Flag indicates that a user has exited in the exodus mode certain token balance (accountId, subAccountId, tokenId, srcTokenId)
@storage_var
func performedExodus(key : (felt, felt, felt, felt)) -> (res : felt):
end

@view
func get_performedExodus{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(key : (felt, felt, felt, felt)) -> (res : felt):
    let (res) = performedExodus.read(key)
    return (res)
end

func set_performedExodus{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(key : (felt, felt, felt, felt), value):
    performedExodus.write(key, value)
    return ()
end

@storage_var
func authFacts(owner_and_nonce : (felt, felt)) -> (res : Uint256):
end

@view
func get_authFacts{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_nonce : (felt, felt)) -> (res : Uint256):
    let (res) = authFacts.read(owner_and_nonce)
    return (res)
end

func set_authFacts{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_nonce : (felt, felt), res : Uint256):
    authFacts.write(owner_and_nonce, res)
    return ()
end

# Timer for authFacts entry reset (address, nonce -> timer).
# Used when user wants to reset `authFacts` for some nonce.
@storage_var
func authFactsResetTimer(owner_and_nonce : (felt, felt)) -> (res : Uint256):
end

@view
func get_authFactsResetTimer{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_nonce : (felt, felt)) -> (res : Uint256):
    let (res) = authFactsResetTimer.read(owner_and_nonce)
    return (res)
end

func set_authFactsResetTimer{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner_and_nonce : (felt, felt), res : Uint256):
    authFactsResetTimer.write(owner_and_nonce, res)
    return ()
end

# Returns the keccak hash of the ABI-encoded StoredBlockInfo
func hashStoredBlockInfo{
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_storedBlockInfo : StoredBlockInfo) -> (hash : Uint256):
    let (bytes : Bytes) = writeStoredBlockInfoForHash(_storedBlockInfo)
    let (hash : Uint256) = hashBytes(bytes)
    return (hash)
end

func increaseBalanceToWithdraw{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(_packedBalanceKey : (felt, felt), _amount : felt):
    let (balance) = get_pendingBalances(_packedBalanceKey)

    # check for overflow
    tempvar new_balance = balance + _amount
    assert_nn(new_balance - _amount)

    set_pendingBalances(_packedBalanceKey, new_balance)
    return ()
end