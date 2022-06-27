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
from starkware.cairo.common.math_cmp import is_not_zero, is_le
from starkware.cairo.common.pow import pow

from starkware.starknet.common.syscalls import (
    get_block_number,
    get_caller_address,
    get_block_timestamp
)

from contracts.utls.Bytes import split_bytes
from contracts.utils.Operations import (
    OPERATIONS_OPTYPE_DEPOSIT,
    OPERATIONS_OPTYPE_FULL_EXIT,
    PriorityOperation,
    DepositOperation,
    FullExit,
    convert_deposit_operation_to_array,
    convert_fullexit_operation_to_array,
    read_deposit_pubdata,
    check_priority_operation,
    read_changepubkey_pubdata
)

from contracts.utils.Utils import (
    hash_array_to_uint160,
    hash_array_to_uint256,
    felt_to_uint256,
    uint256_to_felt,
    min_felt,
    slice_public_data
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
    PUBLIC_DATA_ELEMENT_BYTES,
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
    total_committed_priority_requests,
    get_chain_id,
    get_first_priority_request_id,
    set_priority_request,
    only_delegate_call,
    StoredBlockInfo,
    get_block_hash,
    store_block_hash,
    convert_stored_block_info_to_array,
    get_pending_balance,
    add_pending_balance,
    active,
    only_validator,
    get_total_blocks_committed,
    get_priority_requests
)

from contracts.utils.Events import (
    new_priority_request,
    with_draw
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

# Data needed to process onchain operation from block public data.
# Onchain operations is operations that need some processing on L1: Deposits, Withdrawals, ChangePubKey.
struct OnchainOperationData:
    member eth_witness : felt          # ethWitness Some external data that can be needed for operation processing
    member public_data_offset : felt   # offset in public data for onchain operation
end

# Data needed to commit new block
struct CommitBlockInfo:
    member new_state_hash : felt
    member public_data_size : felt      # all public data elememt size summary
    member public_data_len : felt       # public data array size
    member public_data : felt*          # public data store in an array of felt
    member timestamp : felt
    member onchain_operations_len : felt
    member onchain_operations : OnchainOperationData*
    member block_number : felt
    member fee_account : felt
end

struct CompressedBlockExtraInfo:
    member public_data_hash : felt                      # pubdata hash of all chains
    member offset_commitment_hash : felt                # all chains pubdata offset commitment hash
    member onchain_operation_pubdata_hash_len : felt    # array length of onchain_operation_pubdata_hashs
    member onchain_operation_pubdata_hashs : felt*      # onchain operation pubdata hash of the all other chains
end

# Data needed to execute committed and verified block
struct ExecuteBlockInfo:
    member stored_block : StoredBlockInfo
    member pending_onchain_ops_pubdata_len : felt
    member pending_onchain_ops_pubdata : felt*
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
@external
func commit_blocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(last_committed_block_data : StoredBlockInfo, new_blocks_data_len : felt, new_blocks_data : CommitBlockInfo*):
    alloc_locals
    let (local new_blocks_extra_data : CompressedBlockExtraInfo*) = alloc()

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

func _commit_blocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    last_committed_block_data : StoredBlockInfo,
    new_blocks_data_len : felt,
    new_blocks_data : CommitBlockInfo*,
    compressed : felt,
    new_blocks_extra_data_len : felt,
    new_blocks_extra_data : CompressedBlockExtraInfo*
):
    # Lock with reentrancy_guard
    reentrancy_guard_lock()

    # active and only validator
    active()
    only_validator()

    # Checks
    with_attr error_message("f0"):
        assert_nn(new_blocks_data_len)
        assert_nn(new_blocks_extra_data_len)
        assert new_blocks_data_len = new_blocks_extra_data_len
    end
    let (total_blocks_committed) = get_total_blocks_committed()
    let (stored_block_hash : Uint256) = get_block_hash(total_blocks_committed)
    let (n_elements : felt, elements : felt*) = convert_stored_block_info_to_array(last_committed_block_data)
    let (last_committed_block_hash : Uint256) = hash_array_to_uint256(n_elements, elements)
    with_attr error_message("f1"):
        assert uint256_eq(stored_block_hash, last_committed_block_hash) = 1
    end

    # Effects


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
    previous_block : StoredBlockInfo,
    new_block : CommitBlockInfo,
    compressed : felt,
    new_block_extra : CompressedBlockExtraInfo
) -> (stored_new_block : StoredBlockInfo):
    # Checks
    with_attr error_message("g0"):
        assert new_block.block_number - previous_block.block_number = 1
    end
    with_attr error_message("g1"):
        if ENABLE_COMMIT_COMPRESSED_BLOCK == 0:
            assert compressed = 0
        end
    end

    # Check timestamp of new block
    with_attr error_message("g2"):
        assert_nn_le(previous_block.timestamp, new_block.timestamp)
    end
    # MUST be in a range of [block.timestamp - COMMIT_TIMESTAMP_NOT_OLDER, block.timestamp + COMMIT_TIMESTAMP_APPROXIMATION_DELTA]
    let (current_block_timestamp) = get_block_timestamp()
    with_attr error_message("g3"):
        assert_nn_le(current_block_timestamp - COMMIT_TIMESTAMP_NOT_OLDER, new_block.timestamp)
        assert_nn_le(new_block.timestamp, current_block_timestamp + COMMIT_TIMESTAMP_APPROXIMATION_DELTA)
    end

    # Check onchain operations

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
    onchain_operation_pubdata_hash_len : felt,
    onchain_operation_pubdata_hashs : Uint256*
):
    alloc_locals
    let pub_data = new_block_data.public_data
    let pub_data_size = new_block_data.public_data_size

    let (offsets_commitmemt, rem) = unsigned_div_rem(pub_data_size, CHUNK_BYTES)
    with_attr error_message("h0"):
        assert rem = 0
    end


    
    # overflow is impossible
    let (first_priority_request_id) = get_first_priority_request_id()
    let (total_committed_priority_requests) = total_committed_priority_requests()
    tempvar uncommitted_priority_requests_offset = first_priority_request_id + total_committed_priority_requests

    let (onchain_operation_pubdata_hashs : Uint256*) = init_onchain_operation_pubdata_hashs()
    let (processable_operations_hash) = Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH)


end

func _collect_onchain_ops{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _pub_data : felt*,
    onchain_op_data : OnchainOperationData*,
    index : felt,
    pub_data_size : felt,
    _offsets_commitmemt : felt,
    _uncommitted_priority_requests_offset : felt,
    _priority_operations_processed : felt
) -> (offsets_commitmemt : felt, priority_operations_processed : felt):
    if is_le(-1) == 1:
        return ()
    end
    let (
        before_offsets_commitmemt,
        before_priority_operations_processed
    ) = _collect_onchain_ops(
        pub_data,
        onchain_op_data=onchain_op_data + 1,
        index = index - 1,
        pub_data_size,
        _offsets_commitmemt)

    tempvar pubdata_offset = onchain_op_data.public_data_offset
    with_attr error_message("h1"):
        assert_nn_le(pubdata_offset + 1, pub_data_size)
    end
    let (chunk_id, rem) = unsigned_div_rem(pubdata_offset, pub_data_size)
    with_attr error_message("h2"):
        assert rem = 0
    end

    let (x) = pow(2, chunk_id)
    let (x_and_before_offsets_commitmemt) = bitwise_and(x, before_offsets_commitmemt)
    with_attr error_message("h3"):
        assert x_and_offsets_commitmemt = 0
    end
    let (offsets_commitmemt) = bitwise_or(x, before_offsets_commitmemt)

    let (pubdata_index, _) = unsigned_div_rem(pubdata_offset, PUBLIC_DATA_ELEMENT_BYTES)
    let pub_data = _pub_data[pubdata_index]
    let chain_id = split_bytes(PUBLIC_DATA_ELEMENT_BYTES, pub_data, 1, 1)
    check_chain_id(chain_id)

    let op_type = split_bytes(PUBLIC_DATA_ELEMENT_BYTES, pub_data, 0, 1)
    let next_priority_op_index = _uncommitted_priority_requests_offset + before_priority_operations_processed


    let next

end

func init_onchain_operation_pubdata_hashs{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}() -> (onchain_operation_pubdata_hashs : Uint256*):
    alloc_locals
    let (local onchain_operation_pubdata_hashs : Uint256*) = alloc()
    _init_onchain_operation_pubdata_hash(onchain_operation_pubdata_hashs, MAX_CHAIN_ID)
    return (onchain_operation_pubdata_hashs)
end

func _init_onchain_operation_pubdata_hash{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(hashs : Uint256*, i : felt) -> ():
    if i == MIN_CHAIN_ID - 1:
        return ()
    end

    _init_onchain_operation_pubdata_hash(hashs=hashs + 1, i=i - 1)

    let (chain_index_plus_1) = pow(2, i)
    let chain_index = chain_index_plus_1 - 1

    let (res) = bitwise_and(chain_index, ALL_CHAINS)
    if res == chain_index:
        assert hashs[0] = Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH)
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
}(
    op_type : felt,
    chain_id : felt,
    pub_data : felt*,
    pubdata_index : felt,
    element_offset : felt,
    next_priority_op_index : felt,
    eth_witness : felt
) -> (
    priority_operations_processed : felt,
    op_pubdata : felt,
    processable_pubdata : felt
):
    # ignore check if ops are not part of the current chain
    if op_type = OPERATIONS_OPTYPE_DEPOSIT:
        let (op_pubdata : felt*) = slice_public_data(pubdata, pubdata_index, DEPOSIT_BYTES)
        if chain_id == CHAIN_ID:
            let (op : DepositOperation) = read_deposit_pubdata(op_pubdata)
            let (pop : PriorityOperation) = get_priority_requests(next_priority_op_index)
            check_priority_operation(op, pop)
            return (priority_operations_processed=1, op_pubdata=op_pubdata, processable_pubdata=0)
        end
    else:
        if op_type == OPERATIONS_OPTYPE_CHANGE_PUBKEY:
            let (op_pubdata : felt*) = slice_public_data(pubdata, pubdata_index, CHANGE_PUBKEY_BYTES)
            if chain_id == CHAIN_ID:
                let (op : ChangePubKey) = read_changepubkey_pubdata(op_pubdata)
                if eth_witness == 0 :
                    let (hash) = 
                else:

                end
            end
        else:
            if op_type == OPERATIONS_OPTYPE_WITHDRAW:

            else:
                if op_type == OPERATIONS_OPTYPE_FORCE_EXIT:

                else:
                    if op_type == OPERATIONS_OPTYPE_FULL_EXIT:

                    else:
                        # TODO
                    end
                end
            end
        end
    end
end