# ZKLink main contract: deposit, withdraw, add or remove liquidity, swap
%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_sub,
    uint256_eq,
    uint256_lt,
    uint256_le,
    uint256_and,
    uint256_or,
    uint256_not
)
from starkware.cairo.common.bitwise import bitwise_and, bitwise_or
from starkware.cairo.common.cairo_builtins import (
    HashBuiltin,
    BitwiseBuiltin
)
from starkware.cairo.common.math import assert_not_equal, assert_nn_le, unsigned_div_rem, assert_nn, assert_not_zero, assert_lt, assert_le
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
    get_tx_info,
    get_contract_address
)

from openzeppelin.token.erc20.interfaces.IERC20 import IERC20
from openzeppelin.security.initializable import Initializable
from openzeppelin.security.reentrancyguard import ReentrancyGuard

from contracts.utils.ProxyLib import Proxy
from contracts.utils.Bytes import (
    Bytes,
    read_felt,
    read_felt_array,
    read_uint256,
    read_uint256_array,
    read_bytes,
    FELT_MAX_BYTES,
    split_bytes,
    join_bytes,
    create_empty_bytes
)
from contracts.utils.Operations import (
    OpType,
    PriorityOperation,
    DepositOperation,
    FullExit,
    writeDepositPubdataForPriorityQueue,
    writeFullExitPubdataForPriorityQueue,
    read_deposit_pubdata,
    check_deposit_with_priority_operation,
    read_fullexit_pubdata,
    check_fullexit_with_priority_operation,
    ChangePubKey,
    read_changepubkey_pubdata,
    Withdraw,
    read_withdraw_pubdata,
    ForcedExit,
    read_forcedexit_pubdata,
)

from contracts.utils.Utils import (
    hash_array_to_uint256,
    felt_to_uint256,
    uint256_to_felt,
    address_to_felt,
    min_felt,
    concat_hash,
    concat_two_hash,
    hashBytesToBytes20
)

from contracts.utils.Config import (
    EMPTY_STRING_KECCAK_LOW,
    EMPTY_STRING_KECCAK_HIGH,
    EXODUS_MODE_ON,
    MAX_PRIORITY_REQUESTS,
    MAX_DEPOSIT_AMOUNT,
    MAX_AMOUNT_OF_REGISTERED_TOKENS,
    MAX_ACCOUNT_ID,
    MAX_SUB_ACCOUNT_ID,
    PRIORITY_EXPIRATION,
    UPGRADE_NOTICE_PERIOD,
    COMMIT_TIMESTAMP_NOT_OLDER,
    COMMIT_TIMESTAMP_APPROXIMATION_DELTA,
    ENABLE_COMMIT_COMPRESSED_BLOCK,
    CHAIN_ID,
    MIN_CHAIN_ID,
    MAX_CHAIN_ID,
    ALL_CHAINS,
    CHAIN_INDEX,
    CHUNK_BYTES,
    DEPOSIT_BYTES,
    FULL_EXIT_BYTES,
    WITHDRAW_BYTES,
    FORCED_EXIT_BYTES,
    CHANGE_PUBKEY_BYTES,
    OPERATION_CHUNK_SIZE,
    AUTH_FACT_RESET_TIMELOCK,
    INPUT_MASK_LOW,
    INPUT_MASK_HIGH,
    MAX_ACCEPT_FEE_RATE
)

from contracts.utils.Storage import (
    get_eth_address,
    get_totalBlocksExecuted,
    set_totalBlocksExecuted,
    increase_totalBlocksExecuted,
    get_exodusMode,
    set_exodusMode,
    get_verifier_contract_address,
    set_verifier_contract_address,
    set_periphery_contract_address,
    RegisteredToken,
    get_token_id,
    set_token_id,
    get_token,
    set_token,
    BridgeInfo,
    get_bridge_length,
    get_bridge,
    add_bridge,
    update_bridge,
    get_bridgeIndex,
    set_bridgeIndex,
    get_totalBlocksCommitted,
    set_totalBlocksCommitted,
    get_totalBlocksProven,
    set_totalBlocksProven,
    get_totalOpenPriorityRequests,
    set_totalOpenPriorityRequests,
    sub_totalOpenPriorityRequests,
    get_totalCommittedPriorityRequests,
    increase_totalCommittedPriorityRequests,
    sub_totalCommittedPriorityRequests,
    get_totalBlocksSynchronized,
    set_totalBlocksSynchronized,
    get_chain_id,
    get_firstPriorityRequestId,
    increase_firstPriorityRequestId,
    only_delegate_call,
    StoredBlockInfo,
    hashStoredBlockInfo,
    parse_stored_block_info,
    get_storedBlockHashes,
    set_storedBlockHashes,
    convert_stored_block_info_to_array,
    get_synchronizedChains,
    set_synchronizedChains,
    get_pendingBalances,
    set_pendingBalances,
    active,
    not_active,
    get_performedExodus,
    set_performedExodus,
    get_validator,
    set_validator,
    only_validator,
    get_total_blocks_committed,
    get_priorityRequests,
    set_priorityRequests,
    delete_priorityRequests,
    get_authFacts,
    set_authFacts,
    get_authFactsResetTimer,
    set_authFactsResetTimer,
    increaseBalanceToWithdraw,
    get_accept,
    set_accept,
    get_brokerAllowances,
    set_brokerAllowances
)

from contracts.utils.Events import (
    NewPriorityRequest,
    Withdrawal,
    BlockCommit,
    BlocksRevert,
    WithdrawalPending,
    BlockExecuted,
    ExodusMode,
    FactAuth,
    NewGovernor,
    NewToken,
    TokenPausedUpdate,
    ValidatorStatusUpdate,
    AddBridge,
    UpdateBridge,
    Accept,
    BrokerApprove
)

from contracts.utils.IVerifier import IVerifier

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
    alloc_locals
    if index == -1:
        return (_offset)
    end
    let (offset) = parse_onchain_operation_data(bytes, _offset, index - 1, onchain_operations)
    let (offset, public_data_offset) = read_felt(bytes, offset, 4)
    let (offset, eth_witness : Bytes) = parse_eth_witness(bytes, offset)
    assert onchain_operations[index] = OnchainOperationData(
        public_data_offset=public_data_offset,
        eth_witness=eth_witness
    )
    return (offset)
end

func parse_eth_witness{range_check_ptr}(bytes : Bytes, _offset : felt) -> (offset : felt, eth_witness : Bytes):
    alloc_locals
    let (offset, local eth_witness_size) = read_felt(bytes, _offset, 4)
    if eth_witness_size == 0:
        let (eth_witness : Bytes) = create_empty_bytes()
        return (offset, eth_witness)
    else:
        let (offset, eth_witness : Bytes) = read_bytes(bytes, offset, eth_witness_size)
        return (offset, eth_witness)
    end
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
    alloc_locals
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

func parse_commit_block_info{
    range_check_ptr
}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : CommitBlockInfo):
    alloc_locals
    let (offset, local new_state_hash : Uint256) = read_uint256(bytes, _offset)
    let (offset, local timestamp : Uint256) = read_uint256(bytes, offset)
    let (offset, local block_number) = read_felt(bytes, offset, 4)
    let (offset, local fee_account) = read_felt(bytes, offset, 4)
    let (offset, local pub_data_size) = read_felt(bytes, offset, 4)
    let (offset, local public_data : Bytes) = read_bytes(bytes, offset, pub_data_size)
    let (offset, local onchain_operations_size) = read_felt(bytes, offset, 4)
    let (offset, local onchain_operations : OnchainOperationData*) = parse_onchain_operations_data(bytes, offset, onchain_operations_size)

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

func CompressedBlockExtraInfo_new() -> (res : CompressedBlockExtraInfo):
    alloc_locals
    let (onchain_operation_pubdata_hashs : Uint256*) = alloc()
    return (
        CompressedBlockExtraInfo(
            public_data_hash=Uint256(0, 0),
            offset_commitment_hash=Uint256(0, 0),
            onchain_operation_pubdata_hash_len=0,
            onchain_operation_pubdata_hashs=onchain_operation_pubdata_hashs,
        )
    )
end

func parse_CompressedBlockExtraInfo{
    range_check_ptr
}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : CompressedBlockExtraInfo):
    alloc_locals
    let (offset, public_data_hash : Uint256) = read_uint256(bytes, _offset)
    let (offset, offset_commitment_hash : Uint256) = read_uint256(bytes, offset)
    let (offset, onchain_operation_pubdata_hash_len) = read_felt(bytes, offset, 4)
    let (offset, onchain_operation_pubdata_hashs : Uint256*) = read_uint256_array(bytes, offset, onchain_operation_pubdata_hash_len)

    return (offset, CompressedBlockExtraInfo(
        public_data_hash=public_data_hash,
        offset_commitment_hash=offset_commitment_hash,
        onchain_operation_pubdata_hash_len=onchain_operation_pubdata_hash_len,
        onchain_operation_pubdata_hashs=onchain_operation_pubdata_hashs
    ))
end

# Data needed to execute committed and verified block
struct ExecuteBlockInfo:
    member storedBlock : StoredBlockInfo
    member pendingOnchainOpsPubdata_len : felt
    member pendingOnchainOpsPubdata : Bytes*
end

func parse_ExecuteBlockInfo{
    range_check_ptr
}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : ExecuteBlockInfo):
    alloc_locals
    let (offset, storedBlock : StoredBlockInfo) = parse_stored_block_info(bytes, _offset)
    let (offset, local pendingOnchainOpsPubdata_len) = read_felt(bytes, offset, 4)
    let (local pendingOnchainOpsPubdata : Bytes*) = alloc()
    let (offset) = parse_pendingOnchainOpsPubdata(
        bytes, offset, pendingOnchainOpsPubdata, pendingOnchainOpsPubdata_len - 1)

    return (offset, ExecuteBlockInfo(
        storedBlock=storedBlock,
        pendingOnchainOpsPubdata_len=pendingOnchainOpsPubdata_len,
        pendingOnchainOpsPubdata=pendingOnchainOpsPubdata
    ))
end

func parse_pendingOnchainOpsPubdata{
    range_check_ptr
}(
    bytes : Bytes,
    _offset : felt,
    pendingOnchainOpsPubdata : Bytes*,
    i : felt
) -> (new_offset : felt):
    if i == -1:
        return (_offset)
    end

    let (before_offset) = parse_pendingOnchainOpsPubdata(bytes, _offset, pendingOnchainOpsPubdata, i - 1)
    let (offset, pendingOnchainOpsPubdata_size) = read_felt(bytes, before_offset, 4)
    let (offset, data) = read_bytes(bytes, offset, pendingOnchainOpsPubdata_size)
    assert pendingOnchainOpsPubdata[i] = data

    return (offset)
end

#
# Upgrade interface
#

@view
func getGovernor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address: felt):
    let (address) = Proxy.get_governor()
    return (address)
end

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
    let (exodus_mode_value) = get_exodusMode()
    if exodus_mode_value == 0:
        return (1)
    else:
        return (0)
    end
end

# ZkLink contract initialization.
# Can be external because Proxy contract intercepts illegal calls of this function.
@external
func initializer{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(

    _verifierAddress : felt,
    _networkGovernor : felt,
    _blockNumber : felt,
    _timestamp : Uint256,
    _stateHash : Uint256,
    _commitment : Uint256,
    _syncHash : Uint256
):
    # Must call proxy init function immediately
    Proxy.initializer(_networkGovernor)

    # Check if Zklink contract was already initialized
    let (initialized) = Initializable.initialized()
    assert initialized = 0

    only_delegate_call()

    with_attr error_message("i0"):
        assert_not_zero(_verifierAddress)
    end
    set_verifier_contract_address(_verifierAddress)

    # We need initial state hash because it is used in the commitment of the next block
    let storedBlockZero = StoredBlockInfo(
        block_number=_blockNumber,
        priority_operations=0,
        pending_onchain_operations_hash=Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH),
        timestamp=Uint256(0, 0),
        state_hash=_stateHash,
        commitment=_commitment,
        sync_hash=_syncHash
    )

    let (hash : Uint256) = hashStoredBlockInfo(storedBlockZero)
    set_storedBlockHashes(0, hash)

    set_totalBlocksExecuted(_blockNumber)
    set_totalBlocksSynchronized(_blockNumber)
    set_totalBlocksProven(_blockNumber)
    set_totalBlocksCommitted(_blockNumber)

    # Mark that Zklink contract was initialized
    Initializable.initialize()

    return ()
end

# ZkLink contract upgrade. Can be external because Proxy contract intercepts illegal calls of this function.
@external
func upgrade{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(newImplementation : felt):
    Proxy.assert_only_governor()
    Proxy._set_implementation_hash(newImplementation)
    return ()
end

#
# Delegate call
#

# Will run when no functions matches call data
@external
func fallback():
    return ()
end

# Same as fallback but called when calldata is empty
@external
func receive():
    return ()
end

#
# User interface
#

# Checks if Exodus mode must be entered. If true - enters exodus mode and emits ExodusMode event.
# Exodus mode must be entered in case of current ethereum block number is higher than the oldest
# of existed priority requests expiration block number.
@external
func activateExodusMode{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}():
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # check active
    active()
    let (local block_number) = get_block_number()
    let (firstPriorityRequestId) = get_firstPriorityRequestId()
    let (local priorityRequest : PriorityOperation) = get_priorityRequests(firstPriorityRequestId)
    let (trigger1) = is_le(0, block_number - priorityRequest.expirationBlock)
    let (trigger2) = is_not_zero(priorityRequest.expirationBlock)
    if trigger1 + trigger2 == 2:
        set_exodusMode(1)
        ExodusMode.emit()
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Withdraws token from ZkLink to root chain in case of exodus mode. User must provide proof that he owns funds
# _storedBlockInfo: Last verified block
# _owner: Owner of the account
# _accountId: Id of the account in the tree
# _subAccountId: Id of the subAccount in the tree
# _proof: Proof
# _tokenId: The token want to withdraw
# _srcTokenId: The token deducted at l2
# _amount: Amount for owner (must be total amount, not part of it)
@external
func performExodus{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _storedBlockInfo : StoredBlockInfo,
    _owner : felt,
    _accountId : felt,
    _subAccountId : felt,
    _tokenId : felt,
    _srcTokenId : felt,
    _amount : felt,
    proof_size : felt, proof_data_len : felt, proof_data : felt*
):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # not active
    not_active()

    # Checks
    # performed exodus MUST not be already exited
    with_attr error_message("y0"):
        let (valid) = get_performedExodus((_accountId, _subAccountId, _tokenId, _srcTokenId))
        assert valid = 0
    end
    # incorrect stored block info
    with_attr error_message("y1"):
        let (totalBlocksExecuted) = get_totalBlocksExecuted()
        let (hash1 : Uint256) = get_storedBlockHashes(totalBlocksExecuted)
        let (hash2 : Uint256) = hashStoredBlockInfo(_storedBlockInfo)
        let (eq) = uint256_eq(hash1, hash2)
        assert eq = 1
    end
    # exit proof MUST be correct
    with_attr error_message("y2"):
        let (address) = get_verifier_contract_address()
        let (proofCorrect) = IVerifier.verifyExitProof(
            contract_address=address,
            _rootHash=_storedBlockInfo.state_hash,
            _chainId=CHAIN_ID,
            _accountId=_accountId,
            _subAccountId=_subAccountId,
            _owner=_owner,
            _tokenId=_tokenId,
            _srcTokenId=_srcTokenId,
            _amount=_amount,
            size=proof_size,
            data_len=proof_data_len,
            data=proof_data
        )
        assert proofCorrect = 1
    end

    # Effects
    set_performedExodus((_accountId, _subAccountId, _tokenId, _srcTokenId), 1)
    increaseBalanceToWithdraw((_owner, _tokenId), _amount)
    WithdrawalPending.emit(_tokenId, _owner, _amount)
    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Accrues users balances from deposit priority requests in Exodus mode
# WARNING: Only for Exodus mode
# Canceling may take several separate transactions to be completed
@external
func cancelOutstandingDepositForExodusMode{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # not active
    not_active()

    # Checks
    let (totalOpenPriorityRequests) = get_totalOpenPriorityRequests()
    let (local toProcess) = min_felt(totalOpenPriorityRequests, 1)
    with_attr error_message("A0"):
        assert_lt(0, toProcess)
    end
    # Effects
    let (local id) = get_firstPriorityRequestId()
    let (pr : PriorityOperation) = get_priorityRequests(id)
    if pr.opType == OpType.Deposit:
        local bytes : Bytes = Bytes(
            _start=0,
            bytes_per_felt=FELT_MAX_BYTES,
            size=size,
            data_length=data_len,
            data=data
        )
        with_attr error_message("A1"):
            let (hash) = hashBytesToBytes20(bytes)
            assert hash = pr.hashedPubData
        end

        let (op : DepositOperation) = read_deposit_pubdata(bytes)
        let (owner) = address_to_felt(op.owner)
        increaseBalanceToWithdraw((owner, op.token_id), op.amount)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    delete_priorityRequests(id)
    increase_firstPriorityRequestId(toProcess)
    sub_totalOpenPriorityRequests(toProcess)
    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Set data for changing pubkey hash using onchain authorization.
# Transaction author (msg.sender) should be L2 account address
# New pubkey hash can be reset, to do that user should send two transactions:
# 1) First `setAuthPubkeyHash` transaction for already used `_nonce` will set timer.
# 2) After `AUTH_FACT_RESET_TIMELOCK` time is passed second `setAuthPubkeyHash` transaction will reset pubkey hash for `_nonce`.
# _pubkeyHash: New pubkey hash
# _nonce: Nonce of the change pubkey L2 transaction
@external
func setAuthPubkeyHash{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_pubkeyHash : felt, _nonce : felt):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # not active
    active()

    # PubKeyHash should be 20 bytes.
    # TODO: check _pubkeyHash valid
    let (local sender) = get_caller_address()
    let (hash) = get_authFacts((sender, _nonce))
    let (is_zero) = uint256_eq(hash, Uint256(0, 0))
    if is_zero == 1:
        # TODO: keccak
        let h = Uint256(0, 0)
        set_authFacts((sender, _nonce), h)
        FactAuth.emit(sender, _nonce, _pubkeyHash)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        let (local currentResetTimer : Uint256) = get_authFactsResetTimer((sender, _nonce))
        # TODO: on starknet, timestamp should use felt
        let (block_timestamp) = get_block_timestamp()
        let timestamp = Uint256(block_timestamp, 0)
        let (eq) = uint256_eq(currentResetTimer, Uint256(0, 0))
        if eq == 1:
            set_authFactsResetTimer((sender, _nonce), timestamp)
            tempvar syscall_ptr = syscall_ptr
            tempvar pedersen_ptr = pedersen_ptr
            tempvar range_check_ptr = range_check_ptr
        else:
            with_attr error_message("B1"):
                let (time : Uint256) = uint256_sub(timestamp, currentResetTimer)
                let (res) = uint256_le(Uint256(AUTH_FACT_RESET_TIMELOCK, 0), time)
                assert res = 1
            end
            set_authFactsResetTimer((sender, _nonce), Uint256(0, 0))
            # # TODO: keccak
            let h = Uint256(0, 0)
            set_authFacts((sender, _nonce), h)
            FactAuth.emit(sender, _nonce, _pubkeyHash)
            tempvar syscall_ptr = syscall_ptr
            tempvar pedersen_ptr = pedersen_ptr
            tempvar range_check_ptr = range_check_ptr
        end
    end
    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Deposit ETH to Layer 2 - transfer ether from user into contract, validate it, register deposit.
@external
func depositETH{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_zkLinkAddress : Uint256, _subAccountId : felt, _amount : felt):
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    
    let (eth_address) = get_eth_address()
    # deposit
    deposit(
        _tokenAddress=eth_address,
        _amount=_amount,
        _zkLinkAddress=_zkLinkAddress,
        _subAccountId=_subAccountId,
        _mapping=0
    )

    # Unlock
    ReentrancyGuard._end()
    return ()
end

# # Deposit ERC20 token to Layer 2 - transfer ERC20 tokens from user into contract, validate it, register deposit
# # it MUST be ok to call other external functions within from this function
# # when the token(eg. erc777,erc1155) is not a pure erc20 token
@external
func depositERC20{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_tokenAddress : felt, _amount : felt, _zkLinkAddress : Uint256, _subAccountId : felt, _mapping : felt):
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # support non-standard tokens
    let (current_contract_address) = get_contract_address()
    let (sender) = get_caller_address()
    let (balance_before : Uint256) = IERC20.balanceOf(
        contract_address=_tokenAddress,
        account=current_contract_address
    )

    # NOTE, if the token is not a pure erc20 token, it could do anything within the transferFrom
    let (amount_uint256 : Uint256) = felt_to_uint256(_amount)
    IERC20.transferFrom(
        contract_address=_tokenAddress,
        sender=sender,
        recipient=current_contract_address,
        amount=amount_uint256
    )

    let (balance_after : Uint256) = IERC20.balanceOf(
        contract_address=_tokenAddress,
        account=current_contract_address
    )
    let (deposit_amount_uint256 : Uint256) = uint256_sub(balance_after, balance_before)
    let (deposit_amount) = uint256_to_felt(deposit_amount_uint256)
    
    # deposit
    deposit(
        _tokenAddress=_tokenAddress,
        _amount=deposit_amount,
        _zkLinkAddress=_zkLinkAddress,
        _subAccountId=_subAccountId,
        _mapping=_mapping
    )

    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Register full exit request - pack pubdata, add priority request
@external
func requestFullExit{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_address : Uint256, _accountId : felt, _subAccountId : felt, _tokenId : felt, _mapping : felt):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    active()

    # Checks
    # account_id and sub_account_id MUST be valid
    with_attr error_message("a0"):
        assert_nn_le(_accountId, MAX_ACCOUNT_ID)
    end
    with_attr error_message("a1"):
        assert_nn_le(_subAccountId, MAX_SUB_ACCOUNT_ID)
    end
    # token MUST be registered to ZkLink
    let (local rt : RegisteredToken) = get_token(_tokenId)
    with_attr error_message("a2"):
        assert rt.registered = 1
    end

    if _mapping == 1:
        with_attr error_message("a3"):
            assert_lt(0, rt.mappingTokenId)
        end
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar range_check_ptr = range_check_ptr
    end

    # to prevent ddos
    let (requests) = get_totalOpenPriorityRequests()
    with_attr error_message("a4"):
        assert_nn_le(requests, MAX_PRIORITY_REQUESTS - 1)
    end

    # Effects
    # Priority Queue request
    let (chain_id) = get_chain_id()

    # sender should same with _address
    with_attr error_message("a5"):
        let (sender) = get_caller_address()
        let (address) = address_to_felt(_address)
        assert address = sender
    end
    
    if _mapping == 1:
        tempvar op = FullExit(
            chainId=chain_id,
            accountId=_accountId,
            subAccountId=_subAccountId,
            owner=_address,   # Only the owner of account can fullExit for them self
            tokenId=_tokenId,
            srcTokenId = rt.mappingTokenId,
            amount=0    # unknown at this point
        )
    else:
        tempvar op = FullExit(
            chainId=chain_id,
            accountId=_accountId,
            subAccountId=_subAccountId,
            owner=_address,   # Only the owner of account can fullExit for them self
            tokenId=_tokenId,
            srcTokenId=_tokenId,
            amount=0    # unknown at this point
        )
    end
    let (pubdata : Bytes) = writeFullExitPubdataForPriorityQueue(op)
    add_priority_request(OpType.FullExit, pubdata)
    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Withdraws tokens from zkLink contract to the owner
# NOTE: We will call ERC20.transfer(.., _amount), but if according to internal logic of ERC20 token zkLink contract
# balance will be decreased by value more then _amount we will try to subtract this value from user pending balance
@external
func withdrawPendingBalance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(owner : felt, token_id : felt, _amount : felt):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # Checks
    # token MUST be registered to ZkLink
    let (rt : RegisteredToken) = get_token(token_id)
    with_attr error_message("b0"):
        assert rt.registered = 1
    end

    # Set the available amount to withdraw
    let (local balance) = get_pendingBalances((owner, token_id))
    let (local amount) = min_felt(balance, _amount)
    with_attr error_message("b1"):
        assert_not_zero(amount)
    end

    # Effects
    set_pendingBalances((owner, token_id), balance - amount)    # amount <= balance

    # Interactions
    let (amount1) = transferERC20(rt.tokenAddress, owner, amount, balance, rt.standard)
    if  amount == amount1:
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        set_pendingBalances((owner, token_id), balance - amount1)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    Withdrawal.emit(token_id=token_id, amount=amount1)

    # Unlock
    ReentrancyGuard._end()
    return ()
end

# Sends tokens
# NOTE: will revert if transfer call fails or rollup balance difference (before and after transfer) is bigger than _maxAmount
# This function is used to allow tokens to spend zkLink contract balance up to amount that is requested
@external
func transferERC20{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(token_address : felt, to : felt, _amount : felt, max_amount : felt, is_standard : felt) -> (amount : felt):
    alloc_locals
    # can be called only from this contract as one "external" call 
    # (to revert all this function state changes if it is needed)
    let (sender) = get_caller_address()
    let (current_contract_address) = get_contract_address()
    with_attr error_message("n0"):
        assert sender = current_contract_address
    end

    # most tokens are standard, fewer query token balance can save gas
    if is_standard == 1:
        IERC20.transfer(contract_address=token_address, recipient=to, amount=Uint256(_amount, 0))
        return (_amount)
    else:
        let (balance_before : Uint256) = IERC20.balanceOf(contract_address=token_address, account=current_contract_address)
        IERC20.transfer(contract_address=token_address, recipient=to, amount=Uint256(_amount, 0))
        let (balance_after : Uint256) = IERC20.balanceOf(contract_address=token_address, account=current_contract_address)
        let (local balance_diff : Uint256) = uint256_sub(balance_before, balance_after)
        # transfer is considered successful only if the balance of the contract decreased after transfer
        with_attr error_message("n1"):
            let (lt) = uint256_lt(Uint256(0, 0), balance_diff)
            assert lt = 1
        end
        # rollup balance difference (before and after transfer) is bigger than `_maxAmount`
        with_attr error_message("n2"):
            let (le) = uint256_le(balance_diff, Uint256(max_amount, 0))
        end
        return (balance_diff.low)
    end
end

#
# Validator interface
#

# Commit block
# 1. Checks onchain operations of all chains, timestamp.
# 2. Store block commitments, sync hash
@external
func commitBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (offset, _lastCommittedBlockData : StoredBlockInfo) = parse_stored_block_info(bytes, 0)
    let (_, _newBlocksData : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
    let (_newBlockExtraData : CompressedBlockExtraInfo)= CompressedBlockExtraInfo_new()

    _commit_block(_lastCommittedBlockData, _newBlocksData, 0, _newBlockExtraData)
    return ()
end

# Commit compressed block
# 1. Checks onchain operations of current chain, timestamp.
# 2. Store block commitments, sync hash
@external
func commitCompressedBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (offset, _lastCommittedBlockData : StoredBlockInfo) = parse_stored_block_info(bytes, 0)
    let (offset, _newBlocksData : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
    let (_, _newBlockExtraData : CompressedBlockExtraInfo) = parse_CompressedBlockExtraInfo(bytes, offset)

    _commit_block(_lastCommittedBlockData, _newBlocksData, 1, _newBlockExtraData)
    return ()
end

# Recursive proof input data (individual commitments are constructed onchain)
# TODO: len as uint32 is ok?
struct ProofInput:
    member recursiveInput_len : felt
    member recursiveInput : Uint256*
    member proof_len : felt
    member proof : Uint256*
    member commitments_len : felt
    member commitments : Uint256*
    member vkIndexes_len : felt
    member vkIndexes : felt*
    member subproofsLimbs_len : felt
    member subproofsLimbs : Uint256*
end

func parse_ProofInput{
    range_check_ptr
}(bytes : Bytes, _offset : felt) -> (new_offset : felt, res : ProofInput):
    alloc_locals
    let (offset, local recursiveInput_len) = read_felt(bytes, _offset, 4)
    let (offset, recursiveInput : Uint256*) = read_uint256_array(bytes, offset, recursiveInput_len)
    let (offset, local proof_len) = read_felt(bytes, offset, 4)
    let (offset, proof : Uint256*) = read_uint256_array(bytes, offset, proof_len)
    let (offset, local commitments_len) = read_felt(bytes, offset, 4)
    let (offset, commitments : Uint256*) = read_uint256_array(bytes, offset, commitments_len)
    let (offset, local vkIndexes_len) = read_felt(bytes, offset, 4)
    let (offset, vkIndexes : felt*) = read_felt_array(bytes, offset, vkIndexes_len, 1)
    let (offset, local subproofsLimbs_len) = read_felt(bytes, offset, 4)
    let (offset, subproofsLimbs : Uint256*) = read_uint256_array(bytes, offset, subproofsLimbs_len)

    return (offset, ProofInput(
        recursiveInput_len=recursiveInput_len,
        recursiveInput=recursiveInput,
        proof_len=proof_len,
        proof=proof,
        commitments_len=commitments_len,
        commitments=commitments,
        vkIndexes_len=vkIndexes_len,
        vkIndexes=vkIndexes,
        subproofsLimbs_len=subproofsLimbs_len,
        subproofsLimbs=subproofsLimbs,
    ))
end

# Blocks commitment verification.
# Only verifies block commitments without any other processing
@external
func proveBlocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _committedBlocks_len : felt, _committedBlocks : StoredBlockInfo*,
    proof_size : felt, proof_data_len : felt, proof_data : felt*
):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()

    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=proof_size,
        data_length=proof_data_len,
        data=proof_data
    )
    let (_, local _proof : ProofInput) = parse_ProofInput(bytes, 0)
    # Checks
    let (local currentTotalBlocksProven) = _proveBlocks(_committedBlocks, _proof, _committedBlocks_len - 1)

    # Effects
    with_attr error_message("x2"):
        let (totalBlocksCommitted) = get_totalBlocksCommitted()
        assert_nn_le(currentTotalBlocksProven, totalBlocksCommitted)
    end
    set_totalBlocksProven(currentTotalBlocksProven)

    # Interactions
    let (address) = get_verifier_contract_address()
    let (success) = IVerifier.verifyAggregatedBlockProof(
        contract_address=address,
        size=proof_size,
        data_len=proof_data_len,
        data=proof_data
    )

    with_attr error_message("x3"):
        assert success = 1
    end
    # Unlock
    ReentrancyGuard._end()
    return ()
end

func _proveBlocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_committedBlocks : StoredBlockInfo*, _proof : ProofInput, i) -> (newTotalBlocksProven : felt):
    alloc_locals
    if i == -1:
        let (currentTotalBlocksProven) = get_totalBlocksProven()
        return (currentTotalBlocksProven)
    end
    let (old_TotalBlocksProven) = _proveBlocks(_committedBlocks, _proof, i - 1)
    with_attr error_message("x0"):
        let (hash1 : Uint256) = hashStoredBlockInfo(_committedBlocks[i])
        let (hash2 : Uint256) = get_storedBlockHashes(old_TotalBlocksProven + 1)
        let (eq) = uint256_eq(hash1, hash2)
        assert eq = 1
    end
    with_attr error_message("x1"):
        let (and1 : Uint256) = uint256_and(_proof.commitments[i], Uint256(INPUT_MASK_LOW, INPUT_MASK_HIGH))
        let (and2 : Uint256) = uint256_and(_committedBlocks[i].commitment, Uint256(INPUT_MASK_LOW, INPUT_MASK_HIGH))
        let (eq) = uint256_eq(and1, and2)
        assert eq = 1
    end
    return (old_TotalBlocksProven + 1)
end



# Reverts unExecuted blocks
@external
func revertBlocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_blocksToRevert_len : felt, _blocksToRevert : StoredBlockInfo*):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # onlyValidator
    only_validator()

    let (blocksCommitted) = get_totalBlocksCommitted()
    let (local totalBlocksExecuted) = get_totalBlocksExecuted()
    let (blocksToRevert) = min_felt(_blocksToRevert_len, blocksCommitted - totalBlocksExecuted)

    let (local blocksCommitted, local revertedPriorityRequests) = _revertBlocks(
        _blocksToRevert, _blocksToRevert_len - 1, blocksCommitted, 0)
    
    set_totalBlocksCommitted(blocksCommitted)
    sub_totalCommittedPriorityRequests(revertedPriorityRequests)

    let (local totalBlocksCommitted) = get_totalBlocksCommitted()
    let (totalBlocksProven) = get_totalBlocksProven()
    let (small) = is_le(totalBlocksCommitted, totalBlocksProven - 1)
    if small == 1:
        set_totalBlocksProven(totalBlocksCommitted)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    let (local totalBlocksProven) = get_totalBlocksProven()
    let (totalBlocksSynchronized) = get_totalBlocksSynchronized()
        let (small) = is_le(totalBlocksProven, totalBlocksSynchronized - 1)
    if small == 1:
        set_totalBlocksSynchronized(totalBlocksProven)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    BlocksRevert.emit(totalBlocksExecuted, blocksCommitted)

    # Unlock
    ReentrancyGuard._end()
    return ()
end

func _revertBlocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _blocksToRevert : StoredBlockInfo*,
    i : felt,
    _blocksCommitted : felt,
    _revertedPriorityRequests : felt
) -> (blocksCommitted : felt, revertedPriorityRequests : felt):
    alloc_locals
    if i == -1:
        return(_blocksCommitted, _revertedPriorityRequests)
    end

    let (local before_blocksCommitted, before_revertedPriorityRequests) = _revertBlocks(
        _blocksToRevert, i - 1, _blocksCommitted, _revertedPriorityRequests)
    
    with_attr error_message("c"):
        let (storedBlockHashes : Uint256) = get_storedBlockHashes(before_blocksCommitted)
        let (hashedStoredBlockInfo : Uint256) = hashStoredBlockInfo(_blocksToRevert[i])

        let (eq) = uint256_eq(storedBlockHashes, hashedStoredBlockInfo)
        assert eq = 1
    end

    set_storedBlockHashes(before_blocksCommitted, Uint256(0, 0))

    return (before_blocksCommitted - 1, before_revertedPriorityRequests + _blocksToRevert[i].priority_operations)
end

# Execute block, completing priority operations and processing withdrawals.
# 1. Processes all pending operations (Send Exits, Complete priority requests)
# 2. Finalizes block on Ethereum
@external
func executeBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()
    # active and onlyValidator
    active()
    only_validator()

    # parse calldata
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )

    let (_, _blockData : ExecuteBlockInfo) = parse_ExecuteBlockInfo(bytes, 0)
    let (local priorityRequestsExecuted) = executeOneBlock(_blockData, 0)

    increase_firstPriorityRequestId(priorityRequestsExecuted)
    sub_totalCommittedPriorityRequests(priorityRequestsExecuted)
    sub_totalOpenPriorityRequests(priorityRequestsExecuted)

    increase_totalBlocksExecuted(1)
    with_attr error_message("d1"):
        let (totalBlocksExecuted) = get_totalBlocksExecuted()
        let (totalBlocksSynchronized) = get_totalBlocksSynchronized()
        assert_nn_le(totalBlocksExecuted, totalBlocksSynchronized)
    end

    BlockExecuted.emit(_blockData.storedBlock.block_number)
    # Unlock
    ReentrancyGuard._end()
    return ()
end

#
# Governance interface
#

# Change current governor
@external
func changeGovernor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_newGovernor : felt):
    Proxy.assert_only_governor()

    with_attr error_message("H"):
        assert_not_equal(_newGovernor, 0)
    end
    let (networkGovernor) = Proxy.get_governor()
    if networkGovernor == _newGovernor:
        return ()
    else:
        Proxy._set_governor(_newGovernor)
    end
    return ()
end

# Add token to the list of networks tokens
# _tokenId: Token id
# _tokenAddress: Token address
# _standard: If token is a standard erc20
# _mappingTokenId: The mapping token id at l2
func addToken{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _tokenId : felt,
    _tokenAddress : felt,
    _standard : felt,
    _mappingTokenId : felt
):
    Proxy.assert_only_governor()
    # token id MUST be in a valid range
    with_attr error_message("I0"):
        assert_nn(_tokenId - 1)
        assert_nn_le(_tokenId - 1, MAX_AMOUNT_OF_REGISTERED_TOKENS)
    end

    # token MUST be not zero address
    with_attr error_message("I1"):
        assert_not_equal(_tokenAddress, 0)
    end

    # revert duplicate register
    let (rt : RegisteredToken) = get_token(_tokenId)
    with_attr error_message("I2"):
        assert rt.registered = 0
    end
    with_attr error_message("I2"):
        let (token_id) = get_token_id(_tokenAddress)
        assert token_id = 0
    end

    let new_rt = RegisteredToken(
        registered=1,
        paused=0,
        tokenAddress=_tokenAddress,
        standard=_standard,
        mappingTokenId=_mappingTokenId
    )

    set_token(_tokenId, new_rt)
    set_token_id(_tokenAddress, _tokenId)

    NewToken.emit(_tokenId, _tokenAddress)

    return ()
end

# Add tokens to the list of networks tokens
# _tokenIdList: Token id list
# _tokenAddressList: Token address list
# _standardList: Token standard list
# _mappingTokenList: Mapping token list
@external
func addTokens{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _tokenIdList_len : felt,
    _tokenIdList : felt*,
    _tokenAddressList_len : felt,
    _tokenAddressList : felt*,
    _standardList_len : felt,
    _standardList : felt*,
    _mappingTokenList_len : felt,
    _mappingTokenList : felt*
):
    # TODO: add new err message
    with_attr error_message("addTokens len"):
        assert _tokenIdList_len = _tokenAddressList_len
        assert _tokenAddressList_len = _standardList_len
        assert _standardList_len = _mappingTokenList_len
    end
    let len = _tokenIdList_len
    _addTokens(_tokenIdList, _tokenAddressList, _standardList, _mappingTokenList, len - 1)
    return ()
end

func _addTokens{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _tokenIdList : felt*,
    _tokenAddressList : felt*,
    _standardList : felt*,
    _mappingTokenList : felt*,
    i : felt
):
    if i == -1:
        return ()
    end
    _addTokens(_tokenIdList, _tokenAddressList, _standardList, _mappingTokenList, i - 1)
    addToken(_tokenIdList[i], _tokenAddressList[i], _standardList[i], _mappingTokenList[i])
    return ()
end

# Pause token deposits for the given token
# _tokenId: Token id
# _tokenPaused: Token paused status
@external
func setTokenPaused{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_tokenId : felt, _tokenPaused : felt):
    alloc_locals
    # only governor
    Proxy.assert_only_governor()

    let (local rt : RegisteredToken) = get_token(_tokenId)
    with_attr error_message("K"):
        assert rt.registered = 1
    end

    if rt.paused == _tokenPaused:
        return ()
    else:
        let new_rt = RegisteredToken(
            registered=rt.registered,
            paused=_tokenPaused,
            tokenAddress=rt.tokenAddress,
            standard=rt.standard,
            mappingTokenId=rt.mappingTokenId
        )
        set_token(_tokenId, new_rt)
        TokenPausedUpdate.emit(_tokenId, _tokenPaused)
        return ()
    end
end

# Change validator status (active or not active)
# _validator: Validator address
# _active: Active flag
@external
func setValidator{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_validator : felt, _active : felt):
    Proxy.assert_only_governor()

    let (valid) = get_validator(_validator)
    if valid == _active:
        return ()
    else:
        set_validator(_validator, _active)
        ValidatorStatusUpdate.emit(_validator, _active)
    end
    return ()
end

# Add a new bridge
# bridge: the bridge contract
@external
func addBridge{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(bridge : felt):
    Proxy.assert_only_governor()

    with_attr error_message("L0"):
        assert_not_zero(bridge)
    end
    # the index of non-exist bridge is zero
    with_attr error_message("L1"):
        let (index) = get_bridgeIndex(bridge)
        assert index = 0
    end

    let info = BridgeInfo(
        bridge=bridge,
        enableBridgeTo=1,
        enableBridgeFrom=1
    )
    add_bridge(info)
    set_bridgeIndex(bridge)
    AddBridge.emit(bridge)

    return ()
end

# Update bridge info
# If we want to remove a bridge(not compromised), we should firstly set `enableBridgeTo` to false
# and wait all messages received from this bridge and then set `enableBridgeFrom` to false.
# But when a bridge is compromised, we must set both `enableBridgeTo` and `enableBridgeFrom` to false immediately
# index: the bridge info index
# enableBridgeTo: if set to false, bridge to will be disabled
# enableBridgeFrom: if set to false, bridge from will be disabled
@external
func updateBridge{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(index : felt, enableBridgeTo : felt, enableBridgeFrom : felt):
    Proxy.assert_only_governor()

    with_attr error_message("M"):
        let (len) = get_bridge_length()
        assert_lt(index, len)
    end

    let (info : BridgeInfo) = get_bridge(index)
    let new_info = BridgeInfo(
        bridge=info.bridge,
        enableBridgeTo=enableBridgeTo,
        enableBridgeFrom=enableBridgeFrom
    )
    update_bridge(index, new_info)
    UpdateBridge.emit(index, enableBridgeTo, enableBridgeFrom)
    return ()
end

@view
func isBridgeToEnabled{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(bridge : felt) -> (enabled : felt):
    alloc_locals
    let (index) = get_bridgeIndex(bridge)
    let (info : BridgeInfo) = get_bridge(index)
    if info.bridge == bridge:
        if info.enableBridgeTo == 1:
            return (1)
        end
    end
    return (0)
end

@view
func isBridgeFromEnabled{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(bridge : felt) -> (enabled : felt):
    alloc_locals
    let (index) = get_bridgeIndex(bridge)
    let (info : BridgeInfo) = get_bridge(index)
    if info.bridge == bridge:
        if info.enableBridgeFrom == 1:
            return (1)
        end
    end
    return (0)
end

#
# Internal function
#

func deposit{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_tokenAddress : felt, _amount : felt, _zkLinkAddress : Uint256, _subAccountId : felt, _mapping : felt):
    alloc_locals
    active()

    # Checks
    # disable deposit to zero address or with zero amount
    with_attr error_message("e0"):
        assert_lt(0, _amount)
        assert_le(_amount, MAX_DEPOSIT_AMOUNT)
    end

    with_attr error_message("e1"):
        assert_not_zero(_zkLinkAddress.high)
        assert_not_zero(_zkLinkAddress.low)
    end

    # sub account id must be valid
    with_attr error_message("e2"):
        assert_nn_le(_subAccountId, MAX_SUB_ACCOUNT_ID)
    end

    let (token_id) = get_token_id(_tokenAddress)
    let (local rt : RegisteredToken) = get_token(token_id)

    # token MUST be registered to ZkLink and deposit MUST be enabled
    with_attr error_message("e3"):
        assert rt.registered = 1
    end
    with_attr error_message("e4"):
        assert rt.paused = 0
    end

    if _mapping == 1:
        with_attr error_message("e5"):
            assert_lt(0, rt.mappingTokenId)
        end
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar range_check_ptr = range_check_ptr
    end

    # To prevent DDOS atack
    let (requests) = get_totalOpenPriorityRequests()
    with_attr error_message("e6"):
        assert_lt(requests, MAX_PRIORITY_REQUESTS)
    end

    # Effects
    # Priority Queue request
    let (chain_id) = get_chain_id()
    if _mapping == 1:
        tempvar op = DepositOperation(
            chain_id=chain_id,
            account_id=0,
            sub_account_id=_subAccountId,
            token_id=token_id,
            target_token_id=rt.mappingTokenId,
            amount=_amount,
            owner=_zkLinkAddress
        )
    else:
        tempvar op = DepositOperation(
            chain_id=chain_id,
            account_id=0,
            sub_account_id=_subAccountId,
            token_id=token_id,
            target_token_id=token_id,
            amount=_amount,
            owner=_zkLinkAddress
        )
    end

    let (pubdata : Bytes) = writeDepositPubdataForPriorityQueue(op)
    add_priority_request(OpType.Deposit, pubdata)

    return ()
end

func add_priority_request{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(op_type : felt, pubData : Bytes):
    alloc_locals
    # Expiration block is: current block number + priority expiration delta, overflow is impossible
    let (block_number) = get_block_number()
    tempvar expirationBlock = block_number + PRIORITY_EXPIRATION

    # overflow is impossible
    let (first_priority_request_id) = get_firstPriorityRequestId()
    let (total_open_priority_requests) = get_totalOpenPriorityRequests()
    let next_priority_request_id = first_priority_request_id + total_open_priority_requests

    let (hashedPubData) = hashBytesToBytes20(pubData)

    let op = PriorityOperation(
        hashedPubData=hashedPubData,
        expirationBlock=expirationBlock,
        opType=op_type
    )
    set_priorityRequests(next_priority_request_id, op)

    let (sender) = get_caller_address()
    let (expiration_block : Uint256) = felt_to_uint256(expirationBlock)
    NewPriorityRequest.emit(
        sender=sender,
        serialId=next_priority_request_id,
        opType=op_type,
        pubData_len=pubData.data_length,
        pubData=pubData.data,
        expirationBlock=expiration_block
    )
    set_totalOpenPriorityRequests(total_open_priority_requests + 1)
    
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
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()

    # active and only validator
    active()
    only_validator()

    # Checks
    # Check that we commit blocks after last committed block
    with_attr error_message("f1"):
        let (total_blocks_committed) = get_total_blocks_committed()
        let (local old_stored_block_hash : Uint256) = get_storedBlockHashes(total_blocks_committed)

        let (n_elements : felt, elements : felt*) = convert_stored_block_info_to_array(_lastCommittedBlockData)
        let (last_committed_block_hash : Uint256) = hash_array_to_uint256(n_elements, elements)

        let (eq) =  uint256_eq(old_stored_block_hash, last_committed_block_hash)
        assert eq = 1
    end

    # Effects
    let (_lastCommittedBlockData) = commit_one_block(_lastCommittedBlockData, _newBlocksData, compressed, _newBlocksExtraData)
    increase_totalCommittedPriorityRequests(_lastCommittedBlockData.priority_operations)
    let (n_elements : felt, elements : felt*) = convert_stored_block_info_to_array(_lastCommittedBlockData)
    let (new_stored_block_hash : Uint256) = hash_array_to_uint256(n_elements, elements)
    set_storedBlockHashes(_lastCommittedBlockData.block_number, new_stored_block_hash)


    with_attr error_message("f2"):
        let (total_committed_priority_requests) = get_totalCommittedPriorityRequests()
        let (total_open_priority_requests) = get_totalOpenPriorityRequests()

        assert_nn_le(total_committed_priority_requests, total_open_priority_requests)
    end

    BlockCommit.emit(_lastCommittedBlockData.block_number)

    # Unlock
    ReentrancyGuard._end()
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
    alloc_locals
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
        let (le) = uint256_le(_previousBlock.timestamp, _newBlock.timestamp)
        assert le = 1
    end
    # MUST be in a range of [block.timestamp - COMMIT_TIMESTAMP_NOT_OLDER, block.timestamp + COMMIT_TIMESTAMP_APPROXIMATION_DELTA]
    let (local current_block_timestamp) = get_block_timestamp()
    with_attr error_message("g3"):
        let (le) = uint256_le(Uint256(current_block_timestamp - COMMIT_TIMESTAMP_NOT_OLDER, 0), _newBlock.timestamp)
        assert le = 1
        let (le) = uint256_le(_newBlock.timestamp, Uint256(current_block_timestamp + COMMIT_TIMESTAMP_APPROXIMATION_DELTA, 0))
        assert le = 1
        
    end

    # Check onchain operations
    let (
        pendingOnchainOpsHash : Uint256,
        priorityReqCommitted,
        onchainOpsOffsetCommitment,
        local onchainOperationPubdataHashs_low : DictAccess*,
        local onchainOperationPubdataHashs_high : DictAccess*
    ) = collect_onchain_ops(_newBlock)

    # Create synchronization hash for cross chain block verify
    let (commitment) = createBlockCommitment(_previousBlock, _newBlock, _compressed, _newBlockExtra, onchainOpsOffsetCommitment)

    # Create synchronization hash for cross chain block verify
    if _compressed == 1:
        create_sync_hashs(onchainOperationPubdataHashs_low, onchainOperationPubdataHashs_high,
            _newBlockExtra.onchain_operation_pubdata_hashs, MAX_CHAIN_ID)
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    let (syncHash : Uint256) = create_sync_hash(commitment, onchainOperationPubdataHashs_low, onchainOperationPubdataHashs_high)
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
}(low : DictAccess*, high : DictAccess*, onchainOperationPubdataHashs : Uint256*, i : felt):
    alloc_locals
    if i == MIN_CHAIN_ID - 1:
        return ()
    end

    create_sync_hashs(low, high, onchainOperationPubdataHashs, i - 1)
    if i - CHAIN_ID == 0:
        dict_write{dict_ptr=low}(key=i, new_value=onchainOperationPubdataHashs[i].low)
        dict_write{dict_ptr=high}(key=i, new_value=onchainOperationPubdataHashs[i].high)
    end
    return ()
end

# Create synchronization hash for cross chain block verify
func create_sync_hash{
    range_check_ptr, 
    bitwise_ptr : BitwiseBuiltin*
}(commitment : Uint256, low : DictAccess*, high :  DictAccess*) -> (syncHash : Uint256):
    let (syncHash : Uint256) = _create_sync_hash(commitment, low, high, MAX_CHAIN_ID)
    return (syncHash)
end

func _create_sync_hash{
    range_check_ptr, 
    bitwise_ptr : BitwiseBuiltin*
}(commitment : Uint256, low : DictAccess*, high : DictAccess*, i : felt) -> (syncHash : Uint256):
    alloc_locals
    if i == MIN_CHAIN_ID - 1:
        return (commitment)
    end

    let (before_commitment) = _create_sync_hash(commitment, low, high, i - 1)
    let (chainIndex_plus_1) = pow(2, i)
    tempvar chainIndex = chainIndex_plus_1 - 1
    let (chainIndex_and_ALL_CHAINS) = bitwise_and(chainIndex, ALL_CHAINS)
    if chainIndex_and_ALL_CHAINS == chainIndex:
        let (hash_low) = dict_read{dict_ptr=low}(key=i)
        let (hash_high) = dict_read{dict_ptr=high}(key=i)
        let (syncHash) = concat_two_hash(before_commitment, Uint256(hash_low, hash_high))
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
    onchain_operation_pubdata_hashs_low : DictAccess*,
    onchain_operation_pubdata_hashs_high : DictAccess*
):
    alloc_locals
    let pub_data = new_block_data.public_data

    let (offsets_commitmemt_size, rem) = unsigned_div_rem(pub_data.size, CHUNK_BYTES)
    with_attr error_message("h0"):
        assert rem = 0
    end

    # overflow is impossible
    let (first_priority_request_id) = get_firstPriorityRequestId()
    let (total_committed_priority_requests) = get_totalCommittedPriorityRequests()
    tempvar uncommitted_priority_requests_offset = first_priority_request_id + total_committed_priority_requests

    let (onchain_operation_pubdata_hashs_low : DictAccess*,
        onchain_operation_pubdata_hashs_high : DictAccess*) = init_onchain_operation_pubdata_hashs()

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
        onchain_operation_pubdata_hashs_low,
        onchain_operation_pubdata_hashs_high
    )
    return (processable_operations_hash, priority_operations_processed,
        offsets_commitmemt, onchain_operation_pubdata_hashs_low, onchain_operation_pubdata_hashs_high)
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
    onchain_operation_pubdata_hashs_low : DictAccess*,
    onchain_operation_pubdata_hashs_high : DictAccess*
) -> (
    offsets_commitmemt : felt,
    priority_operations_processed : felt,
    processable_operations_hash : Uint256
):
    alloc_locals
    if index == -1:
        return (_offsets_commitmemt, 0, Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH))
    end
    let (
        local before_offsets_commitmemt,
        before_priority_operations_processed,
        before_processable_operations_hash
    ) = _collect_onchain_ops(
        _pub_data,
        onchain_op_data=onchain_op_data,
        index = index - 1,
        _offsets_commitmemt=_offsets_commitmemt,
        _uncommitted_priority_requests_offset=_uncommitted_priority_requests_offset,
        onchain_operation_pubdata_hashs_low=onchain_operation_pubdata_hashs_low,
        onchain_operation_pubdata_hashs_high=onchain_operation_pubdata_hashs_high
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
        assert x_and_before_offsets_commitmemt = 0
    end
    let (offsets_commitmemt) = bitwise_or(x, before_offsets_commitmemt)

    let (_, local chain_id) = read_felt(_pub_data, pubdata_offset + 1, 1)
    check_chain_id(chain_id)

    let (_, op_type) = read_felt(_pub_data, pubdata_offset, 1)
    let next_priority_op_index = _uncommitted_priority_requests_offset + before_priority_operations_processed

    let (newPriorityProceeded, opPubData : Bytes, processablePubData : Bytes) = check_onchain_op(
        op_type, chain_id, _pub_data, pubdata_offset, next_priority_op_index, onchain_op_data[index].eth_witness
    )
    let priority_operations_processed = before_priority_operations_processed + newPriorityProceeded

    let (old_onchain_operation_pubdata_hash_low) = dict_read{dict_ptr=onchain_operation_pubdata_hashs_low}(key=chain_id)
    let (old_onchain_operation_pubdata_hash_high) = dict_read{dict_ptr=onchain_operation_pubdata_hashs_high}(key=chain_id)
    let (new_onchain_operation_pubdata_hash : Uint256) = concat_hash(
        Uint256(old_onchain_operation_pubdata_hash_low, old_onchain_operation_pubdata_hash_high), opPubData)
    
    dict_write{dict_ptr=onchain_operation_pubdata_hashs_low}(key=chain_id, new_value=new_onchain_operation_pubdata_hash.low)
    dict_write{dict_ptr=onchain_operation_pubdata_hashs_high}(key=chain_id, new_value=new_onchain_operation_pubdata_hash.high)

    let (has_processable_pubdata) = is_not_zero(processablePubData.size)
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
}() -> (low : DictAccess*, high :  DictAccess*):
    alloc_locals
    let (local low : DictAccess*) = default_dict_new(default_value=0)
    default_dict_finalize(
        dict_accesses_start=low,
        dict_accesses_end=low,
        default_value=0
    )
    let (local high : DictAccess*) = default_dict_new(default_value=0)
    default_dict_finalize(
        dict_accesses_start=high,
        dict_accesses_end=high,
        default_value=0
    )
    _init_onchain_operation_pubdata_hash(low, high, MAX_CHAIN_ID)
    return (low, high)
end

func _init_onchain_operation_pubdata_hash{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(low : DictAccess*, high : DictAccess*, i : felt) -> ():
    alloc_locals
    if i == MIN_CHAIN_ID - 1:
        return ()
    end

    _init_onchain_operation_pubdata_hash(low=low, high=high, i=i - 1)

    let (chain_index_plus_1) = pow(2, i)
    tempvar chain_index = chain_index_plus_1 - 1

    let (res) = bitwise_and(chain_index, ALL_CHAINS)
    if res == chain_index:
        dict_write{dict_ptr=low}(key=i, new_value=EMPTY_STRING_KECCAK_LOW)
        dict_write{dict_ptr=high}(key=i, new_value=EMPTY_STRING_KECCAK_HIGH)
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
    return ()
end

func check_onchain_op{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
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
        let (_, op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, DEPOSIT_BYTES)
        if chain_id == CHAIN_ID:
            let (deposit_op : DepositOperation) = read_deposit_pubdata(op_pubdata)
            let (pop : PriorityOperation) = get_priorityRequests(next_priority_op_index)
            check_deposit_with_priority_operation(deposit_op, pop)
            let (_, processable_pubdata : Bytes) = read_bytes(op_pubdata, 0, op_pubdata.size)
            return (priority_operations_processed=1, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
        end
    else:
        if op_type == OpType.ChangePubKey:
            let (_, op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, CHANGE_PUBKEY_BYTES)
            if chain_id == CHAIN_ID:
                let (cpk_op : ChangePubKey) = read_changepubkey_pubdata(op_pubdata)
                let (_, processable_pubdata : Bytes) = read_bytes(op_pubdata, 0, op_pubdata.size)
                if eth_witness.size == 0 :
                    let (af : Uint256) = get_authFacts((cpk_op.owner, cpk_op.nonce))
                    # TODO: keccak
                    return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
                else:
                    let (valid) = verify_changepubkey(eth_witness, cpk_op)
                    with_attr error_message("k0"):
                        assert valid = 1
                    end
                    return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
                end
            end
        else:
            if op_type == OpType.Withdraw:
                let (_, op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, WITHDRAW_BYTES)
                return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=empty_bytes)
            else:
                if op_type == OpType.ForcedExit:
                    let (_, op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, FORCED_EXIT_BYTES)
                    return (priority_operations_processed=0, op_pubdata=op_pubdata, processable_pubdata=empty_bytes)
                else:
                    if op_type == OpType.FullExit:
                        let (_, op_pubdata : Bytes) = read_bytes(pub_data, public_data_offset, FULL_EXIT_BYTES)
                        if chain_id == CHAIN_ID:
                            let (fullexit_op : FullExit) = read_fullexit_pubdata(op_pubdata)
                            let (pop : PriorityOperation) = get_priorityRequests(next_priority_op_index)
                            check_fullexit_with_priority_operation(fullexit_op, pop)
                            let (_, processable_pubdata : Bytes) = read_bytes(op_pubdata, 0, op_pubdata.size)
                            return (priority_operations_processed=1, op_pubdata=op_pubdata, processable_pubdata=processable_pubdata)
                        end
                    else:
                        # TODO:  revert("k2")
                        do_nothing:
                        return (0, empty_bytes, empty_bytes)
                    end
                end
            end
        end
    end

    jmp do_nothing
end

# Checks that change operation is correct
# True return 1, False return 0
func verify_changepubkey{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(eth_witness : Bytes, change_pk : ChangePubKey) -> (res : felt):
    let (_, changePkType) = read_felt(eth_witness, 0, 1)
    if changePkType == ChangePubkeyType.ECRECOVER:
        let (res_ECRECOVER) = verify_changepubkey_ECRECOVERP(eth_witness, change_pk)
        return (res_ECRECOVER)
    else:
        let (res_CREATE2) = verify_changepubkey_CREATE2(eth_witness, change_pk)
        return (res_CREATE2)
    end
end

func verify_changepubkey_ECRECOVERP{
    syscall_ptr : felt*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(eth_witness : Bytes,change_pk : ChangePubKey) -> (res : felt):
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

# Executes one block
# 1. Processes all pending operations (Send Exits, Complete priority requests)
# 2. Finalizes block on Ethereum
# _executedBlockIdx is index in the array of the blocks that we want to execute together
func executeOneBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_blockExecuteData : ExecuteBlockInfo, _executedBlockIdx : felt) -> (priorityRequestsExecuted : felt):
    alloc_locals
    # Ensure block was committed
    with_attr error_message("m0"):
        let (hash1) =  hashStoredBlockInfo(_blockExecuteData.storedBlock)
        let (hash2) = get_storedBlockHashes(_blockExecuteData.storedBlock.block_number)
        let (eq) = uint256_eq(hash1, hash2)
        assert eq = 1
    end

    with_attr error_message("m1"):
        let (totalBlocksExecuted) = get_totalBlocksExecuted()
        assert _blockExecuteData.storedBlock.block_number = totalBlocksExecuted + _executedBlockIdx + 1
    end

    let (pendingOnchainOpsHash : Uint256) = _executeOneBlock(
        _blockExecuteData.pendingOnchainOpsPubdata, _blockExecuteData.pendingOnchainOpsPubdata_len - 1)
    
    with_attr error_message("m3"):
        let (eq) = uint256_eq(pendingOnchainOpsHash, _blockExecuteData.storedBlock.pending_onchain_operations_hash)
        assert eq = 1
    end
    return (_blockExecuteData.storedBlock.priority_operations)
end

func _executeOneBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(pendingOnchainOpsPubdata : Bytes*, i : felt) -> (hash : Uint256):
    alloc_locals
    if i == -1:
        return (Uint256(EMPTY_STRING_KECCAK_LOW, EMPTY_STRING_KECCAK_HIGH))
    end
    let (before_hash : Uint256) = _executeOneBlock(pendingOnchainOpsPubdata, i - 1)

    local pubData : Bytes = pendingOnchainOpsPubdata[i]

    let (offset, op_type) = read_felt(pubData, 0, 1)

    # `pendingOnchainOpsPubdata` only contains ops of the current chain
    # no need to check chain id
    if op_type == OpType.Withdraw:
        let (withdraw : Withdraw) = read_withdraw_pubdata(pubData)
        executeWithdraw(withdraw)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        if op_type == OpType.ForcedExit:
            let (forcedexit : ForcedExit) = read_forcedexit_pubdata(pubData)
            withdrawOrStore(forcedexit.tokenId, forcedexit.target, forcedexit.amount)
            tempvar syscall_ptr = syscall_ptr
            tempvar pedersen_ptr = pedersen_ptr
            tempvar bitwise_ptr = bitwise_ptr
            tempvar range_check_ptr = range_check_ptr
        else:
            if op_type == OpType.FullExit:
                let (fullexit : FullExit) = read_fullexit_pubdata(pubData)
                let (owner) = address_to_felt(fullexit.owner)
                withdrawOrStore(fullexit.tokenId, owner, fullexit.amount)
                tempvar syscall_ptr = syscall_ptr
                tempvar pedersen_ptr = pedersen_ptr
                tempvar bitwise_ptr = bitwise_ptr
                tempvar range_check_ptr = range_check_ptr
            else:
                # TODO : revert?
                tempvar syscall_ptr = syscall_ptr
                tempvar pedersen_ptr = pedersen_ptr
                tempvar bitwise_ptr = bitwise_ptr
                tempvar range_check_ptr = range_check_ptr
            end
        end
    end

    let (hash : Uint256) = concat_hash(before_hash, pubData)
    return (hash)
end

# Execute withdraw operation
func executeWithdraw{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(op : Withdraw):
    alloc_locals
    assert_nn(op.nonce)
    # nonce > 0 means fast withdraw
    if op.nonce == 0:
        withdrawOrStore(op.tokenId, op.owner, op.amount)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        let (packed : felt*) = alloc()
        assert packed[0] = op.owner
        assert packed[1] = op.tokenId
        assert packed[2] = op.amount
        assert packed[3] = op.fastWithdrawFeeRate
        assert packed[4] = op.nonce
        let (fwHash : Uint256) = hash_array_to_uint256(5, packed)
        let (accepter) = get_accept((op.accountId, fwHash))
        if accepter == 0:
            # receiver act as a accepter
            set_accept((op.accountId, fwHash), op.owner)
            withdrawOrStore(op.tokenId, op.owner, op.amount)
            tempvar syscall_ptr = syscall_ptr
            tempvar pedersen_ptr = pedersen_ptr
            tempvar bitwise_ptr = bitwise_ptr
            tempvar range_check_ptr = range_check_ptr
        else:
            # just increase the pending balance of accepter
            increasePendingBalance(op.tokenId, accepter, op.amount)
            tempvar syscall_ptr = syscall_ptr
            tempvar pedersen_ptr = pedersen_ptr
            tempvar bitwise_ptr = bitwise_ptr
            tempvar range_check_ptr = range_check_ptr
        end
    end
    return ()
end

# Try to send token to _recipients
# On failure: Increment _recipients balance to withdraw.
func withdrawOrStore{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _tokenId : felt,
    _recipient : felt,
    _amount : felt
):
    alloc_locals
    if _amount == 0:
        return ()
    end

    let (rt : RegisteredToken) = get_token(_tokenId)
    if rt.registered == 0:
        increasePendingBalance(_tokenId, _recipient, _amount)
        return ()
    end

    tempvar tokenAddress = rt.tokenAddress
    # if tokenAddress == ETH_ADDRESS:
    #     IERC20.transfer(
    #         contract_address=ETH_ADDRESS,
    #         recipient=_recipient,
    #         amount=_amount
    #     )
    # else:

    # Need check: In starknet L2, Ether is a kind of ERC20?
    # We use `transferERC20` here to check that `ERC20` token indeed transferred `_amount`
    # and fail if token subtracted from zkLink balance more then `_amount` that was requested.
    # This can happen if token subtracts fee from sender while transferring `_amount` that was requested to transfer.
    
    transferERC20(tokenAddress, _recipient, _amount, _amount, rt.standard)
    # TODO: What about sent fail?
    increasePendingBalance(_tokenId, _recipient, _amount)
    # end
    return ()
end

# Increase `_recipient` balance to withdraw
func increasePendingBalance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(
    _tokenId : felt,
    _recipient : felt,
    _amount : felt
):
    increaseBalanceToWithdraw((_recipient, _tokenId), _amount)
    WithdrawalPending.emit(_tokenId, _recipient, _amount)
    return ()
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
    return (Uint256(0, 0))
end

#
# Cross chain block synchronization
#

# Combine the `progress` of the other chains of a `syncHash` with self
@external
func receiveSynchronizationProgress{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(syncHash : Uint256, progress : Uint256):
    with_attr error_message("C"):
        let (sender) = get_caller_address()
        let (enabled) = isBridgeFromEnabled(sender)
        assert enabled = 1
    end

    let (old_synchronizedChains) = get_synchronizedChains(syncHash)
    let (new_synchronizedChains) = uint256_or(old_synchronizedChains, progress)
    set_synchronizedChains(syncHash, new_synchronizedChains)
    return ()
end

# Get synchronized progress of current chain known
@view
func getSynchronizedProgress{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_block : StoredBlockInfo) -> (progress : Uint256):
    alloc_locals
    let (local progress : Uint256) = get_synchronizedChains(_block.sync_hash)
    # combine the current chain if it has proven this block
    let (totalBlocksProven) = get_totalBlocksProven()
    let (le) = is_le(_block.block_number, totalBlocksProven)
    if le == 1:
        let (hash1 : Uint256) = hashStoredBlockInfo(_block)
        let (hash2 : Uint256) = get_storedBlockHashes(_block.block_number)
        let (eq) = uint256_eq(hash1, hash2)
        if eq == 1:
            let (new_progress) = uint256_or(progress, Uint256(CHAIN_INDEX, 0))
            return (new_progress)
        end
    else:
        let (new_chain_index : Uint256) = uint256_not(Uint256(CHAIN_INDEX, 0))
        let (new_progress) = uint256_and(progress, new_chain_index)
        return (new_progress)
    end
    return (Uint256(0, 0))
end

# Check if received all syncHash from other chains at the block height
@external
func syncBlocks{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_block : StoredBlockInfo):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()

    with_attr error_message("D0"):
        let (progress : Uint256) = getSynchronizedProgress(_block)
        let (eq) = uint256_eq(progress, Uint256(ALL_CHAINS, 0))
        assert eq = 1
    end

    with_attr error_message("D1"):
        let (totalBlocksSynchronized) = get_totalBlocksSynchronized()
        assert_lt(totalBlocksSynchronized, _block.block_number)
    end

    set_totalBlocksSynchronized(_block.block_number)

    # Unlock
    ReentrancyGuard._end()
    return ()
end

#
# Fast withdraw and Accept
#

# # Accepter accept a eth fast withdraw, accepter will get a fee for profit
# # accepter: Accepter who accept a fast withdraw
# # accountId: Account that request fast withdraw
# # receiver: User receive token from accepter (the owner of withdraw operation)
# # amount: The amount of withdraw operation
# # withdrawFeeRate: Fast withdraw fee rate taken by accepter
# # nonce: Account nonce, used to produce unique accept info
# @external
# func acceptETH{
#     syscall_ptr : felt*,
#     pedersen_ptr : HashBuiltin*,
#     bitwise_ptr : BitwiseBuiltin*,
#     range_check_ptr
# }(
#     accountId : felt,
#     receiver : felt,
#     amount : felt,
#     withdrawFeeRate : felt,
#     nonce : felt
# ):
#     # Lock with reentrancy_guard
#     ReentrancyGuard._start()

#     # Checks
#     let (tokenId) = get_token_id(ETH_ADDRESS)
#     let (amountReceive, hash : Uint256, _) = _checkAccept(
#         accepter, accountId, receiver, tokenId, amount, withdrawFeeRate, nonce)
    
#     # Effects
#     set_accept((accountId, hash), accepter)

#     # Interactions
#     # make sure msg value >= amountReceive


#     # Unlock
#     ReentrancyGuard._end()
#     return ()
# end

# Accepter accept a erc20 token fast withdraw, accepter will get a fee for profit
# accepter Accepter who accept a fast withdraw
# accountId Account that request fast withdraw
# receiver User receive token from accepter (the owner of withdraw operation)
# tokenId Token id
# amount The amount of withdraw operation
# withdrawFeeRate Fast withdraw fee rate taken by accepter
# nonce Account nonce, used to produce unique accept info
# amountTransfer Amount that transfer from accepter to receiver
# may be a litter larger than the amount receiver received
@external
func acceptERC20{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    accepter : felt,
    accountId : felt,
    receiver : felt,
    tokenId : felt,
    amount : felt,
    withdrawFeeRate : felt,
    nonce : felt,
    amountTransfer : felt
):
    alloc_locals
    # Lock with reentrancy_guard
    ReentrancyGuard._start()

    # Checks
    let (amountReceive : felt, hash : Uint256, tokenAddress) = _checkAccept(
        accepter, accountId, receiver, tokenId, amount, withdrawFeeRate, nonce)

    # Effects
    set_accept((accountId, hash), accepter)

    # Interactions
    let (receiverBalanceBefore : Uint256) = IERC20.balanceOf(contract_address=tokenAddress, account=receiver)
    let (accepterBalanceBefore : Uint256) = IERC20.balanceOf(contract_address=tokenAddress, account=accepter)
    IERC20.transferFrom(
        contract_address=tokenAddress,
        sender=accepter,
        recipient=receiver,
        amount=Uint256(amountTransfer, 0)
    )
    let (receiverBalanceAfter : Uint256) = IERC20.balanceOf(contract_address=tokenAddress, account=receiver)
    let (accepterBalanceAfter : Uint256) = IERC20.balanceOf(contract_address=tokenAddress, account=accepter)
    let (receiverBalanceDiff : Uint256) = uint256_sub(receiverBalanceAfter, receiverBalanceBefore)
    let (receiverBalanceDiff_u128) = uint256_to_felt(receiverBalanceDiff)
    with_attr error_message("F0"):
        assert_le(amountReceive, receiverBalanceDiff_u128)
    end
    tempvar amountReceive = receiverBalanceDiff_u128
    let (accepterBalanceDiff) = uint256_sub(accepterBalanceAfter, accepterBalanceBefore)
    let (local amountSent) = uint256_to_felt(accepterBalanceDiff)

    let (local sender) = get_caller_address()
    if sender == accepter:
        # Do nothing
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        let (local old_allowance) = brokerAllowance(tokenId, accepter, sender)
        with_attr error_message("F1"):
            assert_le(amountSent, old_allowance)
        end
        set_brokerAllowances((tokenId, accepter, sender), old_allowance - amountSent)
        tempvar syscall_ptr = syscall_ptr
        tempvar pedersen_ptr = pedersen_ptr
        tempvar bitwise_ptr = bitwise_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    Accept.emit(accepter, accountId, receiver, tokenId, amountSent, amountReceive)

    # Unlock
    ReentrancyGuard._end()
    return ()
end

@view
func brokerAllowance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(tokenId : felt, owner : felt, spender : felt) -> (res : felt):
    let (allowance) = get_brokerAllowances((tokenId, owner, spender))
    return (allowance)
end

# Give allowance to spender to call accept
@external
func brokerApprove{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(tokenId : felt, spender : felt, amount : felt) -> (res : felt):
    with_attr error_message("G"):
        assert_not_zero(spender)
    end
    let (sender) = get_caller_address()
    set_brokerAllowances((tokenId, sender, spender), amount)
    BrokerApprove.emit(tokenId, sender, spender, amount)
    return (1)
end

@view
func _checkAccept{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    accepter : felt,
    accountId : felt,
    receiver : felt,
    tokenId : felt,
    amount : felt,
    withdrawFeeRate : felt,
    nonce : felt
) -> (amountReceive : felt, hash : Uint256, tokenAddress : felt):
    active()

    # accepter and receiver MUST be set and MUST not be the same
    with_attr error_message("H0"):
        assert_not_zero(accepter)
    end
    with_attr error_message("H1"):
        assert_not_zero(receiver)
    end
    with_attr error_message("H2"):
        assert_not_equal(accepter, receiver)
    end

    # token MUST be registered to ZkLink
    let (rt : RegisteredToken) = get_token(tokenId)
    with_attr error_message("H3"):
        assert rt.registered = 1
    end
    tempvar tokenAddress = rt.tokenAddress

    # feeRate MUST be valid
    with_attr error_message("H4"):
        assert_lt(withdrawFeeRate, MAX_ACCEPT_FEE_RATE)
    end
    tempvar amountReceive = amount * (MAX_ACCEPT_FEE_RATE - withdrawFeeRate) / MAX_ACCEPT_FEE_RATE

    # nonce MUST not be zero
    with_attr error_message("H5"):
        assert_not_zero(nonce)
    end

    # accept tx may be later than block exec tx(with user withdraw op)
    # TODO: keccak
    let hash = Uint256(0, 0)
    with_attr error_message("H6"):
        let (valid) = get_accept((accountId, hash))
        assert valid = 0
    end

    return (amountReceive, hash, tokenAddress)
end