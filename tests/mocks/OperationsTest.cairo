%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256

from contracts.utils.Bytes import Bytes, FELT_MAX_BYTES
from contracts.utils.Operations import (
    DepositOperation,
    Withdraw,
    FullExit,
    ForcedExit,
    ChangePubKey,
    read_deposit_pubdata,
    read_withdraw_pubdata,
    read_fullexit_pubdata,
    read_forcedexit_pubdata,
    read_changepubkey_pubdata,
    writeDepositPubdataForPriorityQueue,
    writeFullExitPubdataForPriorityQueue
)

@external
func testDepositPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : DepositOperation, size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (local parsed : DepositOperation) = read_deposit_pubdata(bytes)

    with_attr error_message("cok"):
        assert _example.chain_id = parsed.chain_id
    end
    with_attr error_message("aok"):
        assert _example.account_id = parsed.account_id
    end
    with_attr error_message("sok"):
        assert _example.sub_account_id = parsed.sub_account_id
    end
    with_attr error_message("tok"):
        assert _example.token_id = parsed.token_id
    end
    with_attr error_message("t1ok"):
        assert _example.target_token_id = parsed.target_token_id
    end
    with_attr error_message("amn"):
        assert _example.amount = parsed.amount
    end
    with_attr error_message("own"):
        assert _example.owner = parsed.owner
    end
    return ()
end

@external
func testWriteDepositPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : DepositOperation):
    alloc_locals

    let (pubdata : Bytes) = writeDepositPubdataForPriorityQueue(_example)
    let (local parsed : DepositOperation) = read_deposit_pubdata(pubdata)

    with_attr error_message("cok"):
        assert _example.chain_id = parsed.chain_id
    end
    with_attr error_message("aok"):
        assert 0 = parsed.account_id
    end
    with_attr error_message("sok"):
        assert _example.sub_account_id = parsed.sub_account_id
    end
    with_attr error_message("tok"):
        assert _example.token_id = parsed.token_id
    end
    with_attr error_message("t1ok"):
        assert _example.target_token_id = parsed.target_token_id
    end
    with_attr error_message("amn"):
        assert _example.amount = parsed.amount
    end
    with_attr error_message("own"):
        assert _example.owner = parsed.owner
    end
    return ()
end

@external
func testWithdrawPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : Withdraw, size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (local parsed : Withdraw) = read_withdraw_pubdata(bytes)

    with_attr error_message("cok"):
        assert _example.chainId = parsed.chainId
    end
    with_attr error_message("aok"):
        assert _example.accountId = parsed.accountId
    end
    with_attr error_message("tok"):
        assert _example.tokenId = parsed.tokenId
    end
    with_attr error_message("amn"):
        assert _example.amount = parsed.amount
    end
    with_attr error_message("own"):
        assert _example.owner = parsed.owner
    end
    with_attr error_message("nonce"):
        assert _example.nonce = parsed.nonce
    end
    with_attr error_message("fr"):
        assert _example.fastWithdrawFeeRate = parsed.fastWithdrawFeeRate
    end
    return ()
end

@external
func testFullExitPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : FullExit, size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (local parsed : FullExit) = read_fullexit_pubdata(bytes)

    with_attr error_message("cok"):
        assert _example.chainId = parsed.chainId
    end
    with_attr error_message("aok"):
        assert _example.accountId = parsed.accountId
    end
    with_attr error_message("sok"):
        assert _example.subAccountId = parsed.subAccountId
    end
    with_attr error_message("own"):
        assert _example.owner = parsed.owner
    end
    with_attr error_message("tok"):
        assert _example.tokenId = parsed.tokenId
    end
    with_attr error_message("stok"):
        assert _example.srcTokenId = parsed.srcTokenId
    end
    with_attr error_message("amn"):
        assert _example.amount = parsed.amount
    end
    return ()
end

@external
func testWriteFullExitPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : FullExit):
    alloc_locals

    let (pubdata : Bytes) = writeFullExitPubdataForPriorityQueue(_example)
    let (local parsed : FullExit) = read_fullexit_pubdata(pubdata)

    with_attr error_message("cok"):
        assert _example.chainId = parsed.chainId
    end
    with_attr error_message("aok"):
        assert _example.accountId = parsed.accountId
    end
    with_attr error_message("sok"):
        assert _example.subAccountId = parsed.subAccountId
    end
    with_attr error_message("own"):
        assert _example.owner = parsed.owner
    end
    with_attr error_message("tok"):
        assert _example.tokenId = parsed.tokenId
    end
    with_attr error_message("stok"):
        assert _example.srcTokenId = parsed.srcTokenId
    end
    with_attr error_message("amn"):
        assert 0 = parsed.amount
    end
    return ()
end

@external
func testForcedExitPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : ForcedExit, size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (local parsed : ForcedExit) = read_forcedexit_pubdata(bytes)

    with_attr error_message("cok"):
        assert _example.chainId = parsed.chainId
    end
    with_attr error_message("tok"):
        assert _example.tokenId = parsed.tokenId
    end
    with_attr error_message("amm"):
        assert _example.amount = parsed.amount
    end
    with_attr error_message("tar"):
        assert _example.target = parsed.target
    end

    return ()
end

@external
func testChangePubkeyPubdata{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_example : ChangePubKey, size : felt, data_len : felt, data : felt*):
    alloc_locals
    local bytes : Bytes = Bytes(
        _start=0,
        bytes_per_felt=FELT_MAX_BYTES,
        size=size,
        data_length=data_len,
        data=data
    )
    let (local parsed : ChangePubKey) = read_changepubkey_pubdata(bytes)

    with_attr error_message("cok"):
        assert _example.chainId = parsed.chainId
    end
    with_attr error_message("acc"):
        assert _example.accountId = parsed.accountId
    end
    with_attr error_message("pkh"):
        assert _example.pubKeyHash = parsed.pubKeyHash
    end
    with_attr error_message("own"):
        assert _example.owner = parsed.owner
    end
    with_attr error_message("nnc"):
        assert _example.nonce = parsed.nonce
    end
    return ()
end