%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.dict_access import DictAccess
from starkware.starknet.common.syscalls import get_block_number

from openzeppelin.upgrades.library import Proxy

from contracts.utils.Storage import (
    RegisteredToken,
    StoredBlockInfo,
    set_exodusMode,
    set_accept,
    get_accept,
    get_authFacts,
    get_priorityRequests,
    set_storedBlockHashes,
    get_storedBlockHashes,
    set_totalBlocksExecuted,
    get_totalBlocksExecuted,
    set_totalBlocksProven,
    set_totalOpenPriorityRequests,
    set_synchronizedChains,
    hashStoredBlockInfo,
    get_pendingBalances,
    get_token,
    get_token_id,
)
from contracts.utils.Operations import PriorityOperation, Withdraw
from contracts.Zklink import (
    CommitBlockInfo,
    CompressedBlockExtraInfo,
    parse_stored_block_info,
    parse_CompressedBlockExtraInfo,
    parse_commit_block_info,
    CompressedBlockExtraInfo_new,
    add_priority_request,
    commit_one_block,
    collect_onchain_ops,
    executeWithdraw
)
from contracts.utils.Bytes import (
    Bytes,
    read_felt,
    read_felt_array,
    read_uint256,
    read_uint256_array,
    read_bytes,
    FELT_MAX_BYTES,
)

from contracts.Zklink import (
    initializer,
    activateExodusMode,
    performExodus,
    cancelOutstandingDepositForExodusMode,
    requestFullExit,
    depositETH,
    depositERC20
)

@view
func getstoredBlockHashes{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(block : felt) -> (hash : Uint256):
    let (hash : Uint256) = get_storedBlockHashes(block)
    return (hash)
end

@view
func gettotalBlocksExecuted{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (block_number : felt):
    let (block_number) = get_totalBlocksExecuted()
    return (block_number)
end

@view
func getPendingBalance{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(owner : felt, tokenId : felt) -> (balance : felt):
    let (balance) = get_pendingBalances((owner, tokenId))
    return (balance)
end

@view
func getToken{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_id : felt) -> (token : RegisteredToken):
    let (token : RegisteredToken) = get_token(token_id)
    return (token)
end

@view
func getTokenId{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(token_address : felt) -> (token_id : felt):
    let (token_id) = get_token_id(token_address)
    return (token_id)
end

@view
func getPriorityHash{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(index : felt) -> (hash : felt):
    let (res : PriorityOperation) = get_priorityRequests(index)
    return (res.hashedPubData)
end

@external
func setExodus{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(_exodusMode : felt):
    set_exodusMode(_exodusMode)
    return ()
end

@external
func mockExecBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(storedBlockInfo : StoredBlockInfo):
    let (hash : Uint256) = hashStoredBlockInfo(storedBlockInfo)
    set_storedBlockHashes(storedBlockInfo.block_number, hash)
    set_totalBlocksExecuted(storedBlockInfo.block_number)
    return ()
end

@external
func testAddPriorityRequest{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_opType : felt, size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    add_priority_request(_opType, bytes)
    return ()
end

@external
func testCommitBlock{
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
    let (offset, local _previousBlock : StoredBlockInfo) = parse_stored_block_info(bytes, 0)
    let (offset, local _newBlock : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
    let (offset, local _compressed) = read_felt(bytes, offset, 1)
    
    assert _previousBlock.block_number = 0
    assert _previousBlock.priority_operations = 0
    assert _previousBlock.pending_onchain_operations_hash = Uint256(0xe500b653ca82273b7bfad8045d85a470, 0xc5d2460186f7233c927e7db2dcc703c0)
    assert _previousBlock.timestamp = Uint256(0, 0)
    assert _previousBlock.state_hash = Uint256(0x185240703635b5bbbb94759744d0cb07, 0x16b6dac29128fe56e3755b42f97a0ed4)
    assert _previousBlock.commitment = Uint256(0, 0)
    assert _previousBlock.sync_hash = Uint256(0xe500b653ca82273b7bfad8045d85a470, 0xc5d2460186f7233c927e7db2dcc703c0)

    assert _newBlock.new_state_hash = Uint256(0xdd9e948ab3c7bfd9a54fda813e739510, 0x06ef3a22c4ba6c03ed02b3baf5939355)
    assert _newBlock.timestamp = Uint256(0x00000000000000000000000062a94629, 0)
    assert _newBlock.block_number = 1
    assert _newBlock.fee_account = 0
    assert _newBlock.onchain_operations_size = 1
    assert _newBlock.onchain_operations[0].public_data_offset = 0


    return ()
end

@external
func testCommitOneBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*) -> (storedNewBlock : StoredBlockInfo):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (offset, local _previousBlock : StoredBlockInfo) = parse_stored_block_info(bytes, 0)
    let (offset, local _newBlock : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
    let (offset, local _compressed) = read_felt(bytes, offset, 1)
    if _compressed == 1:
        let (_, local _newBlockExtra : CompressedBlockExtraInfo) = parse_CompressedBlockExtraInfo(bytes, offset)
        let (stored_new_block : StoredBlockInfo) = commit_one_block(_previousBlock, _newBlock, _compressed, _newBlockExtra)
        return (stored_new_block)
    else:
        let (local _newBlockExtra : CompressedBlockExtraInfo)= CompressedBlockExtraInfo_new()
        let (stored_new_block : StoredBlockInfo) = commit_one_block(_previousBlock, _newBlock, _compressed, _newBlockExtra)
        return (stored_new_block)
    end
end

# @external
# func testCollectOnchainOps{
#     syscall_ptr : felt*,
#     pedersen_ptr : HashBuiltin*,
#     bitwise_ptr : BitwiseBuiltin*,
#     range_check_ptr
# }(size : felt, data_len : felt, data : felt*) -> (
#     processableOperationsHash : Uint256,
#     priorityOperationsProcessed : felt,
#     offsetsCommitment : felt,
#     onchainOperationPubdataHashs_len : felt,
#     onchainOperationPubdataHashs : Uint256*
# ):
#     alloc_locals
#     let (_, _newBlockData : CommitBlockInfo) = parse_commit_block_info(bytes, offset)
#     let (
#         processableOperationsHash : Uint256,
#         priorityOperationsProcessed,
#         offsetsCommitment,
#         local onchainOperationPubdataHashs_low : DictAccess*,
#         local onchainOperationPubdataHashs_high : DictAccess*
#     ) = collect_onchain_ops(_newBlockData)

# end

@external
func testExecuteWithdraw{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(op : Withdraw):
    executeWithdraw(op)
    return ()
end

@external
func setGovernor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(governor : felt):
    Proxy.assert_only_admin()
    Proxy._set_admin(governor)
    return ()
end

@external
func setAccepter{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(accountId : felt, hash : Uint256, accepter : felt):
    set_accept((accountId, hash), accepter)
    return ()
end

@external
func mockProveBlock{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(storedBlockInfo : StoredBlockInfo):
    let (hash : Uint256) = hashStoredBlockInfo(storedBlockInfo)
    set_storedBlockHashes(storedBlockInfo.block_number, hash)
    set_totalBlocksProven(storedBlockInfo.block_number)
    return ()
end

@external
func setTotalOpenPriorityRequests{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(_totalOpenPriorityRequests : felt):
    set_totalOpenPriorityRequests(_totalOpenPriorityRequests)
    return ()
end

@external
func setSyncProgress{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(syncHash : Uint256, progress : Uint256):
    set_synchronizedChains(syncHash, progress)
    return ()
end