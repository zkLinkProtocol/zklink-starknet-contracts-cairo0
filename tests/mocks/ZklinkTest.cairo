%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.dict_access import DictAccess
from contracts.utils.Storage import (
    StoredBlockInfo,
    set_exodusMode,
    get_priorityRequests,
    set_storedBlockHashes,
    set_totalBlocksExecuted,
    hashStoredBlockInfo
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
}(_opType : felt, _pubData_len : felt, _pubData : felt*):
    add_priority_request(_opType, _pubData, _pubData_len)
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