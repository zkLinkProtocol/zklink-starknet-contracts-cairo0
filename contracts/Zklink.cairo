# ZKLink main contract: deposit, withdraw, add or remove liquidity, swap
%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_sub, uint256_eq
from starkware.cairo.common.bitwise import bitwise_and, bitwise_or
from openzeppelin.token.erc20.interfaces.IERC20 import IERC20
from starkware.cairo.common.cairo_builtins import (
    HashBuiltin,
    BitwiseBuiltin
)
from starkware.cairo.common.math import assert_not_equal, assert_nn_le, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_not_zero, is_le, is_nn
from starkware.cairo.common.pow import pow
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.dict import dict_write, dict_read, dict_update
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.squash_dict import squash_dict

from starkware.starknet.common.syscalls import (
    get_block_number,
    get_caller_address,
    get_block_timestamp,
    get_tx_info
)

from contracts.utils.Bytes import (
    Bytes,
    read_felt,
    read_uint256,
    read_bytes,
    FELT_MAX_BYTES,
    split_bytes,
    create_empty_bytes
)
from contracts.utils.Operations import (
    OpType,
    PriorityOperation,
    DepositOperation,
    FullExit,
    convert_deposit_operation_to_array,
    convert_fullexit_operation_to_array,
    read_deposit_pubdata,
    check_deposit_with_priority_operation,
    read_fullexit_pubdata,
    check_fullexit_with_priority_operation,
    ChangePubKey,
    read_changepubkey_pubdata
)

from contracts.utils.Utils import (
    hash_array_to_uint160,
    hash_array_to_uint256,
    felt_to_uint256,
    uint256_to_felt,
    min_felt,
    concat_hash,
    concat_two_hash
)

from contracts.utils.Config import (
    EMPTY_STRING_KECCAK_LOW,
    EMPTY_STRING_KECCAK_HIGH,
    ETH_ADDRESS,
    EXODUS_MODE_ON,
    MAX_PRIORITY_REQUESTS,
    MAX_DEPOSIT_AMOUNT,
    MAX_ACCOUNT_ID,
    MAX_SUB_ACCOUNT_ID,
    PRIORITY_EXPIRATION,
    UPGRADE_NOTICE_PERIOD,
    COMMIT_TIMESTAMP_NOT_OLDER,
    COMMIT_TIMESTAMP_APPROXIMATION_DELTA,
    ENABLE_COMMIT_COMPRESSED_BLOCK,
    MIN_CHAIN_ID,
    MAX_CHAIN_ID,
    ALL_CHAINS,
    CHUNK_BYTES,
    DEPOSIT_BYTES,
    FULL_EXIT_BYTES,
    WITHDRAW_BYTES,
    FORCED_EXIT_BYTES,
    CHANGE_PUBKEY_BYTES,
    OPERATION_CHUNK_SIZE
)

from contracts.utils.Storage import (
    get_exodus_mode,
    set_verifier_contract_address,
    set_periphery_contract_address,
    set_network_governor_address,
    RegisteredToken,
    get_token_id,
    get_token,
    get_total_open_priority_requests,
    get_total_committed_priority_requests,
    add_total_committed_priority_requests,
    get_chain_id,
    get_first_priority_request_id,
    set_priority_request,
    only_delegate_call,
    StoredBlockInfo,
    parse_stored_block_info,
    get_storedBlockHashes,
    add_storedBlockHashes,
    convert_stored_block_info_to_array,
    get_pending_balance,
    add_pending_balance,
    active,
    only_validator,
    get_total_blocks_committed,
    get_priority_requests,
    get_auth_facts
)

from contracts.utils.Events import (
    new_priority_request,
    with_draw,
    block_commit
)

from contracts.utils.ReentrancyGuard import (
    reentrancy_guard_init,
    reentrancy_guard_lock,
    reentrancy_guard_unlock
)

#
# Storage section.
#

# Zklink contract initialized was 1
@storage_var
func was_initialized() -> (res : felt):
end

#
# Struct section
#

struct ChangePubkeyType:
    member ECRECOVER : felt
    member CREATE2 : felt
end

# Data needed to process onchain operation from block public data.
# Onchain operations is operations that need some processing on L1: Deposits, Withdrawals, ChangePubKey.
struct OnchainOperationData:
    member public_data_offset : felt    # offset in public data for onchain operation
    member eth_witness : Bytes          # ethWitness Some external data that can be needed for operation processing
end

func parse_onchain_operations_data{range_check_ptr}(
    bytes : Bytes,
    _offset : felt,
    size : felt
) -> (new_offset : felt, res : OnchainOperationData*):
    alloc_locals
    let (local onchain_operations : OnchainOperationData*) = alloc()
    let (new_offset) = parse_onchain_operation_data(bytes, _offset, size - 1, onchain_operations)
    return (new_offset, onchain_operations)
end

func parse_onchain_operation_data{range_check_ptr}(
    bytes : Bytes,
    _offset : felt,
    index : felt,
    onchain_operations : OnchainOperationData*
) -> (new_offset):
    if index == -1:
        return (_offset)
    let (offset) = parse_onchain_operation_data(bytes, _offset, index - 1, onchain_operations)
    let (offset, sub_size) = read_felt(bytes, offset, 4)
    let (offset, public_data_offset) = read_felt(bytes, offset, 4)
    let (offset, eth_witness) = read_bytes(bytes, offset, sub_size)
    assert onchain_operations[index] = OnchainOperationData(
        public_data_offset=public_data_offset,
        eth_witness=eth_witness
    )
    return (offset)
end

# Data needed to commit new block
struct CommitBlockInfo:
    member new_state_hash : Uint256
    member timestamp : Uint256
    member block_number : felt
    member fee_account : felt
    member public_data : Bytes
    member onchain_operations_size : felt               # uint32
    member onchain_operations : OnchainOperationData*
end

func CommitBlockInfo_new() -> (res : CommitBlockInfo):
    alloc_locals()
    let (public_data : Bytes) = create_empty_bytes()
    let (onchain_operations : OnchainOperationData*) = alloc()
    return (
        CommitBlockInfo(
            new_state_hash=Uint256(0, 0),
            timestamp=Uint256(0, 0),
            block_number=0,
            fee_account=0,
            public_data=public_data,
            onchain_operations_size=0,
            onchain_operations=onchain_operations
        )
    )
end

func parse_commit_block_info{range_check_ptr}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : CommitBlockInfo):
    let (offset, new_state_hash : Uint256) = read_uint256(bytes, _offset)
    let (offset, timestamp : Uint256) = read_uint256(bytes, offset)
    let (offset, block_number) = read_felt(bytes, offset, 4)
    let (offset, fee_account) = read_felt(bytes, offset, 4)
    let (offset, pub_data_size) = read_felt(bytes, offset, 4)
    let (offset, public_data : Bytes) = read_bytes(bytes, offset, pub_data_size)
    let (offset, onchain_operations_size) = read_felt(bytes, offset, 4)
    let (offset, onchain_operations : OnchainOperationData*) = parse_onchain_operations_data(bytes, offset, onchain_operations_size)

    return (offset, CommitBlockInfo(
        new_state_hash=new_state_hash,
        timestamp=timestamp,
        block_number=block_number,
        fee_account=fee_account,
        public_data=public_data,
        onchain_operations_size=onchain_operations_size,
        onchain_operations=onchain_operations
    ))
end

struct CompressedBlockExtraInfo:
    member public_data_hash : Uint256                       # pubdata hash of all chains
    member offset_commitment_hash : Uint256                 # all chains pubdata offset commitment hash
    member onchain_operation_pubdata_hash_len : felt        # array length of onchain_operation_pubdata_hashs
    member onchain_operation_pubdata_hashs : Uint256*       # onchain operation pubdata hash of the all other chains
end

func parse_CompressedBlockExtraInfo{range_check_ptr}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : CompressedBlockExtraInfo):
    let (offset, public_data_hash : Uint256) = read_uint256(bytes, _offset)
    let (offset, offset_commitment_hash : Uint256) = read_uint256(bytes, offset)
    let (offset, onchain_operations_size) = read_felt(bytes, offset, 4)
    let (offset, onchain_operations : OnchainOperationData*) = parse_onchain_operations_data(bytes, offset, onchain_operations_size)

    return (offset, CompressedBlockExtraInfo(
        public_data_hash=public_data_hash,
        offset_commitment_hash=offset_commitment_hash,
        onchain_operations_size=onchain_operations_size,
        onchain_operation_pubdata_hashs=onchain_operation_pubdata_hashs
    ))
end

# Data needed to execute committed and verified block
struct ExecuteBlockInfo:
    member stored_block : StoredBlockInfo
    member pending_onchain_ops_pubdata_len : felt
    member pending_onchain_ops_pubdata : Bytes*
end

#
# Upgrade interface
#

# Notice period before activation preparation status of upgrade mode
@external
func get_notice_period() -> (res : felt):
    return (UPGRADE_NOTICE_PERIOD)
end

# Checks that contract is ready for upgrade
@external
func is_ready_for_upgrade{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (res : felt):
    let (exodus_mode_value) = get_exodus_mode()
    if exodus_mode_value == 0:
        return (1)
    else:
        return (0)
end

# ZkLink contract initialization.
# Can be external because Proxy contract intercepts illegal calls of this function.
@external
func initialize{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    vierfier_address : felt,
    periphery_address : felt,
    network_governor_address : felt,
    genesis_state_hash
):
    # Check if Zklink contract was already initialized
    let (was_initialized_read) = was_initialized.read()
    assert was_initialized_read = 0

    only_delegate_call()
    reentrancy_guard_init()
    
    set_verifier_contract_address(vierfier_address)
    set_periphery_contract_address(periphery_address)
    set_network_governor_address(network_governor_address)

    # We need initial state hash because it is used in the commitment of the next block
    let stored_block_zero = StoredBlockInfo(
        block_number=0,
        priority_operations=0,
        pending_onchain_operations_hash=EMPTY_STRING_KECCAK,
        timestamp=0,
        state_hash=genesis_state_hash,
        commitment=0,
        sync_hash=EMPTY_STRING_KECCAK
    )

    let (n_elements : felt, elements : felt*) = convert_stored_block_info_to_array(stored_block_zero)
    let (hash : Uint256) = hash_array_to_uint256(n_elements, elements)
    store_block_hash(0, hash)

    # Mark that Zklink contract was initialized
    was_initialized.write(1)

    return ()
end

# ZkLink contract upgrade. Can be external because Proxy contract intercepts illegal calls of this function.
@external
func upgrade{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(periphery_address : felt):
    only_delegate_call()
    set_periphery_contract_address(periphery_address)
end

#
# Delegate call
#

# Will run when no functions matches call data
@external
func fallback():
end

# Same as fallback but called when calldata is empty
@external
func receive():
end

#
# User interface
#

# Deposit ETH to Layer 2 - transfer ether from user into contract, validate it, register deposit.
@external
func deposit_ETH{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(zklink_address : felt, sub_account_id : felt, amount : felt):
    # Lock with reentrancy_guard
    reentrancy_guard_lock()
    
    # deposit
    deposit(
        token_address=ETH_ADDRESS,
        amount=amount,
        zklink_address=zklink_address,
        sub_account_id=sub_account_id
    )

    # Unlock
    reentrancy_guard_unlock()
    return ()
end

# # Deposit ERC20 token to Layer 2 - transfer ERC20 tokens from user into contract, validate it, register deposit
# # it MUST be ok to call other external functions within from this function
# # when the token(eg. erc777,erc1155) is not a pure erc20 token
@external
func deposit_ERC20{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(token_address : felt, amount : felt, zklink_address : felt, sub_account_id : felt):
    # Lock with reentrancy_guard
    reentrancy_guard_lock()
    # support non-standard tokens
    let (current_contract_address) = get_contract_address()
    let (sender) = get_caller_address()
    let (balance_before : Uint256) = IERC20.balanceOf(
        contract_address=token_address,
        account=current_contract_address
    )

    # NOTE, if the token is not a pure erc20 token, it could do anything within the transferFrom
    let (amount_uint256 : Uint256) = felt_to_uint256(amount)
    IERC20.transferFrom(
        contract_address=token_address,
        sender=sender,
        recipient=current_contract_address,
        amount=amount_uint256
    )

    let (balance_after : Uint256) = IERC20.balanceOf(
        contract_address=token_address,
        account=current_contract_address
    )
    let (deposit_amount_uint256 : Uint256) = uint256_sub(balance_after, balance_before)
    let (deposit_amount) = uint256_to_felt(deposit_amount_uint256)
    
    # deposit
    deposit(
        token_address=token_address,
        amount=deposit_amount,
        zklink_address=zklink_address,
        sub_account_id=sub_account_id
    )

    # Unlock
    reentrancy_guard_unlock()
    return ()
end

# Register full exit request - pack pubdata, add priority request
@external
func request_full_exit{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(account_id : felt, sub_account_id : felt, token_id : felt):
    # Lock with reentrancy_guard
    reentrancy_guard_lock()

    # Checks
    # account_id and sub_account_id MUST be valid
    with_attr error_message("a0"):
        assert_nn_le(account_id, MAX_ACCOUNT_ID)
    end
    with_attr error_message("a1"):
        assert_nn_le(sub_account_id, MAX_SUB_ACCOUNT_ID)
    end
    # token MUST be registered to ZkLink
    let (rt : RegisteredToken) = get_token(token_id)
    with_attr error_message("a2"):
        assert rt.registered = 1
    end
    # to prevent ddos
    let (requests) = get_total_open_priority_requests()
    with_attr error_message("a3"):
        assert_nn_le(requests, MAX_PRIORITY_REQUESTS-1)
    end

    # Effects
    # Priority Queue request
    let (chain_id) = get_chain_id()
    let (sender) = get_caller_address()
    let op = FullExit(
        chain_id=chain_id,
        account_id=account_id,
        sub_account_id=sub_account_id,
        owner=sender,   # Only the owner of account can fullExit for them self
        token_id=token_id,
        amount=0    # unknown at this point
    )
    let (num, pub_data) = convert_fullexit_operation_to_array(op)
    add_priority_request(op_type=OPERATIONS_OPTYPE_FULL_EXIT, pub_data=pub_data, n_elements=num)
    # Unlock
    reentrancy_guard_unlock()
    return ()
end

# Withdraws tokens from zkLink contract to the owner
# NOTE: We will call ERC20.transfer(.., _amount), but if according to internal logic of ERC20 token zkLink contract
# balance will be decreased by value more then _amount we will try to subtract this value from user pending balance
@external
func withdraw_pending_balance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(owner : felt, token_id : felt, _amount : felt):
    # Lock with reentrancy_guard
    reentrancy_guard_lock()
    # Checks
    # token MUST be registered to ZkLink
    let (rt : RegisteredToken) = get_token(token_id)
    with_attr error_message("b0"):
        assert rt.registered = 1
    end

    # Set the available amount to withdraw
    let (balance) = get_pending_balance((owner, token_id))
    let (amount) = min_felt(balance, _amount)
    with_attr error_message("b1"):
        assert_nn(amount)
    end

    # Effects
    add_pending_balance((owner, token_id), balance - amount)    # amount <= balance

    # Interactions
    let token_address = rt.token_address
    let (amount : Uint256) = felt_to_uint256(_amount)
    let (max_amount : Uint256) = felt_to_uint256(balance)
    if token_address == ETH_ADDRESS:
        # TODO
        # send (amount) eth to owner
    else:
        let (amount_1 : Uint256) = transfer_ERC20(token_address, owner, amount, max_amount, rt.standard)
        if uint256_eq(amount, amount1) == 0:
            let pending_balance = uint256_to_felt(max_amount - amount1)
            add_pending_balance((owner, token_id), pending_balance)
            let amount2 = uint256_to_felt(amount1)
            with_draw.emit(token_id=token_id, amount2)
        end
    end
    # Unlock
    reentrancy_guard_unlock()
    return ()
end

# Sends tokens
# NOTE: will revert if transfer call fails or rollup balance difference (before and after transfer) is bigger than _maxAmount
# This function is used to allow tokens to spend zkLink contract balance up to amount that is requested
@external
func transfer_ERC20{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(token_address : felt, to : felt, _amount : Uint256, max_amount : felt, is_standard : felt) -> (amount : Uint256):
    # can be called only from this contract as one "external" call 
    # (to revert all this function state changes if it is needed)
    let (sender) = get_caller_address()
    let (current_contract_address) = get_contract_address()
    with_attr error_message("n0"):
        assert sender = current_contract_address
    end

    # most tokens are standard, fewer query token balance can save gas
    if is_standard == 1:
        IERC20.transfer(recipient=to, amount=_amount)
        return (_amount)
    else:
        let (balance_before : Uint256) = IERC20.balanceOf(current_contract_address)
        IERC20.transfer(recipient=to, amount=_amount)
        let (balance_after : Uint256) = IERC20.balanceOf(current_contract_address)
        let (balance_diff : Uint256) = uint256_sub(balance_before, balance_after)
        # transfer is considered successful only if the balance of the contract decreased after transfer
        with_attr error_message("n1"):
            assert_nn(balance_diff)
        end
        # rollup balance difference (before and after transfer) is bigger than `_maxAmount`
        with_attr error_message("n2"):
            assert_nn_le(balance_diff, max_amount)
        end
        return (balance_diff)
    end
end

#
# Validator interface
#

# Commit block
# 1. Checks onchain operations of all chains, timestamp.
# 2. Store block commitments, sync hash
@external
func commit_block{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*):
    tempvar bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (offset, _lastCommittedBlockData : StoredBlockInfo) = parse_stored_block_info(bytes, 0)
    let (_, _newBlocksData : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
    let (_newBlockExtraData : CompressedBlockExtraInfo)= CommitBlockInfo_new()

    _commit_block(_lastCommittedBlockData, new_block_data, false, _newBlockExtraData)
end

# Commit compressed block
# 1. Checks onchain operations of current chain, timestamp.
# 2. Store block commitments, sync hash
@external
@external
func commit_compressed_block{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*):
    tempvar bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (offset, _lastCommittedBlockData : StoredBlockInfo) = parse_stored_block_info(bytes, 0)
    let (offset, _newBlocksData : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
    let (_, _newBlockExtraData : CompressedBlockExtraInfo) = parse_CompressedBlockExtraInfo(bytes, offset)

    _commit_block(_lastCommittedBlockData, new_block_data, true, _newBlockExtraData)
end


#
# Internal function
#

func deposit{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(token_address : felt, amount : felt, zklink_address : felt, sub_account_id : felt):
    alloc_locals
    # Checks that current state not is exodus mode
    let (exodus_mode_stat) = get_exodus_mode()
    with_attr error_message("Z0"):
        assert_not_equal(exodus_mode_stat, EXODUS_MODE_ON)
    end

    # Checks
    # disable deposit to zero address or with zero amount
    with_attr error_message("Z33"):
        assert_nn_le(amount, MAX_DEPOSIT_AMOUNT)
    end

    with_attr error_message("Z34"):
        assert_not_equal(zklink_address, 0)
    end

    # sub account id must be valid
    with_attr error_message("Z30"):
        assert_nn_le(sub_account_id, MAX_SUB_ACCOUNT_ID)
    end

    let (token_id) = get_token_id(token_address)
    let (rt : RegisteredToken) = get_token(token_id)

    # token MUST be registered to ZkLink and deposit MUST be enabled
    with_attr error_message("e3"):
        assert rt.registered = 1
    end
    with_attr error_message("e4"):
        assert rt.paused = 0
    end

    # To prevent DDOS atack
    let (requests) = get_total_open_priority_requests()
    with_attr error_message("e5"):
        assert_nn_le(requests, MAX_PRIORITY_REQUESTS-1)
    end

    # Effects
    # Priority Queue request
    let (chain_id) = get_chain_id()
    let op = DepositOperation(
        chain_id=chain_id,
        account_id=0,
        sub_account_id=sub_account_id,
        token_id=token_id,
        amount=amount,
        owner=zklink_address
    )
    let (num, pub_data) = convert_deposit_operation_to_array(op)
    add_priority_request(op_type=OPERATIONS_OPTYPE_DEPOSIT, pub_data=pub_data, n_elements=num)

    return ()
end

func add_priority_request{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(op_type : felt, pub_data : felt*, n_elements : felt):
    alloc_locals
    # Expiration block is: current block number + priority expiration delta, overflow is impossible
    let (block_number) = get_block_number()
    local expiration_block = block_number + PRIORITY_EXPIRATION

    # overflow is impossible
    let (first_priority_request_id) = get_first_priority_request_id()
    let (total_open_priority_requests) = get_total_open_priority_requests()
    let next_priority_request_id = first_priority_request_id + total_open_priority_requests

    let (hashed_pub_data) = hash_array_to_uint160(n_elements, pub_data)

    let op = PriorityOperation(
        hashed_pub_data=hashed_pub_data,
        expiration_block=expiration_block,
        op_type=op_type
    )
    set_priority_request(next_priority_request_id, op)

    let (sender) = get_caller_address() 
    new_priority_request.emit(
        sender=sender,
        serial_id=next_priority_request_id,
        op_type=op_type,
        pub_data_len=n_elements,
        pub_data=pub_data,
        expiration_block=expiration_block
    )
    
    return ()
end

func _commit_block{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _lastCommittedBlockData : StoredBlockInfo,
    _newBlocksData : CommitBlockInfo,
    compressed : felt,
    _newBlocksExtraData : CompressedBlockExtraInfo
):
    # Lock with reentrancy_guard
    reentrancy_guard_lock()

    # active and only validator
    active()
    only_validator()

    # Checks
    # Check that we commit blocks after last committed block
    with_attr error_message("f1"):
        let (total_blocks_committed) = get_total_blocks_committed()
        let (old_stored_block_hash : Uint256) = get_storedBlockHashes(total_blocks_committed)

        let (n_elements : felt, elements : felt*) = convert_stored_block_info_to_array(_lastCommittedBlockData)
        let (last_committed_block_hash : Uint256) = hash_array_to_uint256(n_elements, elements)

        assert uint256_eq(old_stored_block_hash, last_committed_block_hash) = 1
    end

    # Effects
    let (_lastCommittedBlockData) = commit_one_block(_lastCommittedBlockData, _newBlocksData, compressed, _newBlocksExtraData)
    add_total_committed_priority_requests(_lastCommittedBlockData.priority_operations)
    let (n_elements : felt, elements : felt*) = convert_stored_block_info_to_array(_lastCommittedBlockData)
    let (new_stored_block_hash : Uint256) = hash_array_to_uint256(n_elements, elements)
    add_storedBlockHashes(_lastCommittedBlockData.block_number, new_stored_block_hash)


    with_attr error_message("f2"):
        let (total_committed_priority_requests) = get_total_committed_priority_requests()
        let (total_open_priority_requests) = get_total_open_priority_requests()

        assert_nn_le(total_committed_priority_requests, total_open_priority_requests)
    end

    block_number.emit(_lastCommittedBlockData.block_number)

    # Unlock
    reentrancy_guard_unlock()
    return ()
end

# Process one block commit using previous block StoredBlockInfo, returns new block StoredBlockInfo.
# Does not change storage (except events, so we can't mark it view), only ZkLink can call this function to add more security.
func commit_one_block{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _previousBlock : StoredBlockInfo,
    _newBlock : CommitBlockInfo,
    _compressed : felt,
    _newBlockExtra : CompressedBlockExtraInfo
) -> (stored_new_block : StoredBlockInfo):
    # Checks
    with_attr error_message("g0"):
        assert _newBlock.block_number - _previousBlock.block_number = 1
    end
    with_attr error_message("g1"):
        if ENABLE_COMMIT_COMPRESSED_BLOCK == 0:
            assert _compressed = 0
        end
    end

    # Check timestamp of new block
    with_attr error_message("g2"):
        assert_nn_le(_previousBlock.timestamp, _newBlock.timestamp)
    end
    # MUST be in a range of [block.timestamp - COMMIT_TIMESTAMP_NOT_OLDER, block.timestamp + COMMIT_TIMESTAMP_APPROXIMATION_DELTA]
    let (current_block_timestamp) = get_block_timestamp()
    with_attr error_message("g3"):
        assert_nn_le(current_block_timestamp - COMMIT_TIMESTAMP_NOT_OLDER, _newBlock.timestamp)
        assert_nn_le(_newBlock.timestamp, current_block_timestamp + COMMIT_TIMESTAMP_APPROXIMATION_DELTA)
    end

    # Check onchain operations
    let (
        pendingOnchainOpsHash : Uint256,
        priorityReqCommitted,
        onchainOpsOffsetCommitment,
        onchainOperationPubdataHashs : DictAccess*
    ) = collect_onchain_ops(_newBlock)

    # Create synchronization hash for cross chain block verify
    let (commitment) = createBlockCommitment(_previousBlock, _newBlock, _compressed, _newBlockExtra, onchainOpsOffsetCommitment)

    # Create synchronization hash for cross chain block verify
    if _compressed == 1:
        create_sync_hashs(onchainOperationPubdataHashs, _newBlockExtra.onchainOperationPubdataHashs, MAX_CHAIN_ID)
    end

    let (syncHash : Uint256) = create_sync_hash(commitment, onchainOperationPubdataHashs)
    return (
        StoredBlockInfo(
            block_number=_newBlock.block_number,
            priority_operations=priorityReqCommitted,
            pending_onchain_operations_hash=pendingOnchainOpsHash,
            timestamp=_newBlock.timestamp,
            state_hash=_newBlock.new_state_hash,
            commitment=commitment,
            sync_hash=syncHash
        )
    )
end

func create_sync_hashs{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(dict : DictAccess*, onchainOperationPubdataHashs : Uint256*, i : felt):
    if i == MIN_CHAIN_ID - 1:
        return ()
    end

    create_sync_hashs(dict, onchainOperationPubdataHashs, index - 1)
    let (not_eq) = is_not_zero(i, CHAIN_ID)
    if not_eq == 1:
        dict_update{dict_ptr=dict}(key=i, new_value=onchainOperationPubdataHashs[i])
    end
end

# Create synchronization hash for cross chain block verify
func create_sync_hash{
    range_check_ptr, 
    bitwise_ptr : BitwiseBuiltin*
}(commitment : Uint256, onchainOperationPubdataHashs : DictAccess*) -> (syncHash : Uint256):
    let (syncHash : Uint256) = _create_sync_hash(commitment, onchainOperationPubdataHashs, MAX_CHAIN_ID)
    return (syncHash)
end

func _create_sync_hash{
    range_check_ptr, 
    bitwise_ptr : BitwiseBuiltin*
}(commitment : Uint256, onchainOperationPubdataHashs : DictAccess*, i : felt) -> (syncHash : Uint256):
    if i == MIN_CHAIN_ID - 1:
        return (commitment)
    end

    let (before_commitment) = _create_sync_hash(commitment, onchainOperationPubdataHashs, i - 1)
    let (chainIndex_plus_1) = pow(2, i)
    tempvar chainIndex = chainIndex_plus_1 - 1
    let chainIndex_and_ALL_CHAINS = bitwise_and(chainIndex, ALL_CHAINS)
    if chainIndex_and_ALL_CHAINS == chainIndex:
        let (hash : Uint256) = dict_read{dict_ptr=onchainOperationPubdataHashs}(key=i)
        let (syncHash) = = concat_two_hash(before_commitment, hash)
        return (syncHash)
    else:
        return (before_commitment)
    end
end

# Gets operations packed in bytes array. Unpacks it and stores onchain operations.
# Priority operations must be committed in the same order as they are in the priority queue.
# NOTE: does not change storage! (only emits events)
func collect_onchain_ops{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(new_block_data : CommitBlockInfo) -> (
    processable_operations_hash : Uint256,
    priority_operations_processed : felt,
    offsets_commitment : felt,
    onchain_operation_pubdata_hashs : DictAccess*
):
    alloc_locals
    let pub_data = new_block_data.public_data

    let (offsets_commitmemt_size, rem) = unsigned_div_rem(pub_data.size, CHUNK_BYTES)
    with_attr error_message("h0"):
        assert rem = 0
    end

    # overflow is impossible
    let (first_priority_request_id) = get_first_priority_request_id()
    let (total_committed_priority_requests) = total_committed_priority_requests()
    tempvar uncommitted_priority_requests_offset = first_priority_request_id + total_committed_priority_requests

    let (onchain_operation_pubdata_hashs : DictAccess*) = init_onchain_operation_pubdata_hashs()

    # loop
    let (
        offsets_commitmemt,
        priority_operations_processed,
        processable_operations_hash : Uint256
    ) = _collect_onchain_ops(
        pub_data,
        new_block_data.onchain_operations,
        new_block_data.onchain_operations_size - 1,
        0,
        uncommitted_priority_requests_offset,
        onchain_operation_pubdata_hashs
    )
    return (processable_operations_hash, priority_operations_processed, offsets_commitmemt, onchain_operation_pubdata_hashs)
end

func _collect_onchain_ops{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _pub_data : Bytes,
    onchain_op_data : OnchainOperationData*,
    index : felt,
    _offsets_commitmemt : felt,
    _uncommitted_priority_requests_offset : felt,
    onchain_operation_pubdata_hashs : DictAccess*
) -> (
    offsets_commitmemt : felt,
    priority_operations_processed : felt,
    processable_operations_hash : Uint256
):
    if index == -1:
        return (_offsets_commitmemt, 0, Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH))
    end
    let (
        before_offsets_commitmemt,
        before_priority_operations_processed,
        before_processable_operations_hash
    ) = _collect_onchain_ops(
        _pub_data,
        onchain_op_data=onchain_op_data,
        index = index - 1,
        _offsets_commitmemt
    )

    tempvar pubdata_offset = onchain_op_data[index].public_data_offset
    with_attr error_message("h1"):
        assert_nn_le(pubdata_offset + 1, _pub_data.size)
    end
    let (chunk_id, rem) = unsigned_div_rem(pubdata_offset, CHUNK_BYTES)
    with_attr error_message("h2"):
        assert rem = 0
    end

    let (x) = pow(2, chunk_id)
    let (x_and_before_offsets_commitmemt) = bitwise_and(x, before_offsets_commitmemt)
    with_attr error_message("h3"):
        assert x_and_offsets_commitmemt = 0
    end
    let (offsets_commitmemt) = bitwise_or(x, before_offsets_commitmemt)

    let chain_id = read_felt(_pub_data, pubdata_offset + 1, 1)
    check_chain_id(chain_id)

    let op_type = read_felt(_pub_data, pubdata_offset, 1)
    let next_priority_op_index = _uncommitted_priority_requests_offset + before_priority_operations_processed

    let (newPriorityProceeded, opPubData : Bytes, processablePubData : Bytes) = check_onchain_op(
        op_type, chain_id, _pub_data, pubdata_offset, next_priority_op_index, onchain_op_data[index].ethWitness
    )
    let priority_operations_processed = before_priority_operations_processed + newPriorityProceeded
    let (old_onchain_operation_pubdata_hash : Uint256) = dict_read{dict_ptr=onchain_operation_pubdata_hashs}(key=chain_id)
    let (new_onchain_operation_pubdata_hash : Uint256) = concat_hash(old_onchain_operation_pubdata_hash, opPubData)
    dict_update{dict_ptr=onchain_operation_pubdata_hashs}(key=chain_id, new_value=new_onchain_operation_pubdata_hash)
    let has_processable_pubdata = is_nn(processablePubData.size - 1)
    if has_processable_pubdata == 1:
        let (processable_operations_hash : Uint256) = concat_hash(before_processable_operations_hash, processablePubData)
        return (offsets_commitmemt, priority_operations_processed, processable_operations_hash)
    else:
        return (offsets_commitmemt, priority_operations_processed, before_processable_operations_hash)
    end
end

func init_onchain_operation_pubdata_hashs{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}() -> (onchain_operation_pubdata_hashs : DictAccess*):
    alloc_locals
    tempvar initial_value = Uint256(0, 0)
    let (local onchain_operation_pubdata_hashs : DictAccess*) = default_dict_new(default_value=initial_value)
    default_dict_finalize(
        dict_accesses_start=onchain_operation_pubdata_hashs,
        dict_accesses_end=dict_accesses_end,
        default_value=initial_value
    )
    _init_onchain_operation_pubdata_hash(onchain_operation_pubdata_hashs, MAX_CHAIN_ID)
    return (onchain_operation_pubdata_hashs)
end

func _init_onchain_operation_pubdata_hash{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(hashs : DictAccess*, i : felt) -> ():
    if i == MIN_CHAIN_ID - 1:
        return ()
    end

    _init_onchain_operation_pubdata_hash(hashs=hashs, i=i - 1)

    let (chain_index_plus_1) = pow(2, i)
    tempvar chain_index = chain_index_plus_1 - 1

    let (res) = bitwise_and(chain_index, ALL_CHAINS)
    if res == chain_index:
        dict_write{dict_ptr=hashs}(key=i, new_value=Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH))
    end
    return ()
end

func check_chain_id{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(chain_id : felt):
    with_attr error_message("i1"):
        assert_nn_le(MIN_CHAIN_ID, chain_id)
        assert_nn_le(chain_id, MAX_CHAIN_ID)
    end
    let (r) = pow(2, chain_id)
    tempvar chain_index = r - 1
    let (x_and_y) = bitwise_and(chain_index, ALL_CHAINS)
    with_attr error_message("i2"):
        assert x_and_y = chain_index
    end
end

func check_onchain_op{
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(
    op_type : felt,
    chain_id : felt,
    pub_data : Bytes,
    public_data_offset : felt,
    next_priority_op_index : felt,
    eth_witness : Bytes
) -> (
    priority_operations_processed : felt,
    op_pubdata : Bytes,
    processable_pubdata : Bytes
):
    alloc_locals
    let (local empty_bytes : Bytes) = create_empty_bytes()
    # ignore check if ops are not part of the current chain
    if op_type == OpType.Deposit:
        let (op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, DEPOSIT_BYTES)
        if chain_id == CHAIN_ID:
            let (op : DepositOperation) = read_deposit_pubdata(op_pubdata)
            let (pop : PriorityOperation) = get_priority_requests(next_priority_op_index)
            check_deposit_with_priority_operation(op, pop)
            let (processable_pubdata : Bytes) = read_bytes(op_pubdata, 0, op_pubdata.size)
            return (priority_operations_processed=1, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
        end
    else:
        if op_type == OpType.ChangePubKey:
            let (op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, CHANGE_PUBKEY_BYTES)
            if chain_id == CHAIN_ID:
                let (op : ChangePubKey) = read_changepubkey_pubdata(op_pubdata)
                let (processable_pubdata : Bytes) = read_bytes(op_pubdata, 0, op_pubdata.size)
                if eth_witness.size == 0 :
                    let (af : Uint256) = get_auth_facts((op.owner, op.nonce))
                    # TODO: keccak
                    return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
                else:
                    let (valid) = verify_changepubkey(eth_witness, op)
                    with_attr error_message("k0"):
                        assert valid = 1
                    end
                    return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
                end
            end
        else:
            if op_type == OpType.Withdraw:
                let (op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, WITHDRAW_BYTES)
                return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=empty_bytes)
            else:
                if op_type == OpType.ForcedExit:
                    let (op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, FORCED_EXIT_BYTES)
                    return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=empty_bytes)
                else:
                    if op_type == OpType.FullExit:
                        let (op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, FULL_EXIT_BYTES)
                        if chain_id == CHAIN_ID:
                            let (op : FullExit) = read_fullexit_pubdata(op_pubdata)
                            let (pop : PriorityOperation) = get_priority_requests(next_priority_op_index)
                            check_fullexit_with_priority_operation(op, pop)
                            let (processable_pubdata : Bytes) = read_bytes(op_pubdata, 0, op_pubdata.size)
                            return (priority_operations_processed=1, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
                        end
                    else:
                        # TODO:  revert("k2")
                    end
                end
            end
        end
    end
end

# Checks that change operation is correct
# True return 1, False return 0
func verify_changepubkey{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(eth_witness : Bytes, change_pk : ChangePubKey) -> (res : felt):
    let (changePkType) = read_felt(eth_witness, 0, 1)
    if changePkType == ChangePubkeyType.ECRECOVER:
        let (res_ECRECOVER) = verify_changepubkey_ECRECOVERP(eth_witness, change_pk)
        return (res_ECRECOVER)
    else:
        let (res_CREATE2) = verify_changepubkey_CREATE2(eth_witness, change_pk)
        return (res_CREATE2)
    end
end

func verify_changepubkey_ECRECOVERP{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(eth_witness : Bytes,change_pk : ChangePubKey) -> (res : felt):
    # offset is 1 because we skip type of ChangePubkey
    let (_, signature : Bytes) = read_bytes(eth_witness, 1, 65)
    let (tx_info) = get_tx_info()
    tempvar cid = tx_info.chain_id
    
    # TODO: keccak

    return (1)
end

func verify_changepubkey_CREATE2{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(eth_witness : Bytes,change_pk : ChangePubKey) -> (res : felt):
    
    # TODO: keccak

    return (1)
end

# Creates block commitment from its data
# offsetCommitment - hash of the array where 1 is stored in chunk where onchainOperation begins and 0 for other chunks
func createBlockCommitment{range_check_ptr}(
    _previousBlock : StoredBlockInfo,
    _newBlockData : CommitBlockInfo,
    _compressed : felt,
    _newBlockExtraData : CompressedBlockExtraInfo,
    offsetsCommitment : felt
) -> (commitment : Uint256):
    # TODO: sha256
    return Uint256(0, 0)
end