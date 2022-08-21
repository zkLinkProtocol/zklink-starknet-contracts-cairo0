# ZKLink operations tools
%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import unsigned_div_rem, split_felt
from starkware.cairo.common.pow import pow
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from contracts.utils.Utils import hashBytesToBytes20, deserialize_address
from contracts.utils.Bytes import Bytes, read_felt, read_uint256, join_bytes, BYTES_PER_FELT, read_address, split_felt_to_two

# ZKLink circuit operation type
struct OpType:
    member Noop : felt                       # 0
    member Deposit : felt                    # 1 L1 Op
    member TransferToNew : felt            # 2 L2 Op
    member Withdraw : felt                   # 3 L2 Op
    member Transfer : felt                   # 4 L2 Op
    member FullExit : felt                  # 5 L1 Op
    member ChangePubKey : felt              # 6 L2 Op
    member ForcedExit : felt                 # 7 L2 Op
    member L2CurveAddLiq : felt     # 8 L2 Op
    member L2CurveSwap : felt              # 9 L2 Op
    member L2CurveRemoveLiquidity : felt  # 10 Op
    member OrderMatching : felt             # 11 L2 Op
end

const OP_TYPE_BYTES = 1         # op is uint8
const CHAIN_BYTES = 1           # chainId is uint8
const TOKEN_BYTES = 2           # token is uint16
const NONCE_BYTES = 4           # nonce is uint32
const ADDRESS_BYTES = 32        # L2 address is 20 bytes length
const FEE_BYTES = 2             # fee is uint16
const ACCOUNT_ID_BYTES = 4      # accountId is uint32
const SUB_ACCOUNT_ID_BYTES = 1  # subAccountId is uint8
const AMOUNT_BYTES = 16         # amount is uint128

# Priority operations: Deposit, FullExit
struct PriorityOperation:
    member hashedPubData : felt    # hashed priority operation public data
    member expirationBlock : felt  # expiration block number (ETH block) for this request (must be satisfied before)
    member opType : felt           # priority operation type
end

# Deposit Operation
struct DepositOperation:
    member chain_id : felt          # deposit from which chain that identified by l2 chain id
    member account_id : felt        # the account id bound to the owner address, ignored at serialization and will be set when the block is submitted
    member sub_account_id : felt    # the sub account is bound to account, default value is 0(the global public sub account)
    member token_id : felt          # the token that registered to l2
    member target_token_id : felt   # the token that user increased in l2
    member amount : felt            # the token amount deposited to l2
    member owner : Uint256          # the address that receive deposited token at l2
end

# 59 bytes
const PACKED_DEPOSIT_PUBDATA_BYTES = OP_TYPE_BYTES + CHAIN_BYTES + ACCOUNT_ID_BYTES + SUB_ACCOUNT_ID_BYTES + TOKEN_BYTES * 2 + AMOUNT_BYTES + ADDRESS_BYTES

# Deserialize deposit pubdata
func read_deposit_pubdata{range_check_ptr}(op_pubdata : Bytes) -> (parsed : DepositOperation):
    alloc_locals
    let (offset, local chain_id) = read_felt(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, local account_id) = read_felt(op_pubdata, offset, ACCOUNT_ID_BYTES)
    let (offset, local sub_account_id) = read_felt(op_pubdata, offset, SUB_ACCOUNT_ID_BYTES)
    let (offset, local token_id) = read_felt(op_pubdata, offset, TOKEN_BYTES)
    let (offset, local target_token_id) = read_felt(op_pubdata, offset, TOKEN_BYTES)
    let (offset, local amount) = read_felt(op_pubdata, offset, AMOUNT_BYTES)
    let (offset, local owner) = read_uint256(op_pubdata, offset)

    let parsed = DepositOperation(
        chain_id=chain_id,
        account_id=account_id,
        sub_account_id=sub_account_id,
        token_id=token_id,
        target_token_id=target_token_id,
        amount=amount,
        owner=owner
    )
    return (parsed)
end

func writeDepositPubdataForPriorityQueue{range_check_ptr}(op : DepositOperation) -> (bytes : Bytes):
    alloc_locals
    let (local data : felt*) = alloc()

    let (amount_div) = pow(256, 11)
    let (local amount1, local amount2) = unsigned_div_rem(op.amount, amount_div)

    let (_, deowner : felt*) = deserialize_address(op.owner, 5, 16, 11)
    # bytes of DepositOperation member
    # op_type :         1
    # chain_id :        1
    # account_id :      4
    # sub_account_id :  1
    # token_id :        2
    # target_token_id : 2
    # amount :          16
    # owner :           32
    # data[0] = op_type + chain_id + account_id + sub_account_id + token_id + target_token_id + amount(5 bytes)
    let (value) = join_bytes(OpType.Deposit, op.chain_id, 1)
    let (value) = join_bytes(value, 0, 4)   # accountId (ignored during hash calculation)
    let (value) = join_bytes(value, op.sub_account_id, 1)
    let (value) = join_bytes(value, op.token_id, 2)
    let (value) = join_bytes(value, op.target_token_id, 2)
    let (value) = join_bytes(value, amount1, 5)
    assert data[0] = value
    # data[1] = amount(11 bytes) + owner(5 bytes)
    let (value) = join_bytes(amount2, deowner[0], 5)
    assert data[1] = value
    # data[2] = owner(16 bytes)
    assert data[2] = deowner[1]
    # data[3] = owner(11 bytes)
    assert data[3] = deowner[2]

    return (Bytes(
        size=PACKED_DEPOSIT_PUBDATA_BYTES,
        data_length=4,
        data=data
    ))
end

# Checks that deposit is same as operation in priority queue
func check_deposit_with_priority_operation{
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_deposit : DepositOperation, _priority_op : PriorityOperation):
    with_attr error_message("OP: not deposit"):
        assert _priority_op.opType = OpType.Deposit
    end
    with_attr error_message("OP: invalid deposit hash"):
        let (pubdata : Bytes) = writeDepositPubdataForPriorityQueue(_deposit)
        let (hashed_pub_data) = hashBytesToBytes20(pubdata)
        assert hashed_pub_data = _priority_op.hashedPubData
    end
    return ()
end

const PACKED_FULLEXIT_PUBDATA_BYTES = OP_TYPE_BYTES + CHAIN_BYTES + ACCOUNT_ID_BYTES + SUB_ACCOUNT_ID_BYTES + TOKEN_BYTES * 2 + AMOUNT_BYTES + ADDRESS_BYTES

# FullExit Operation
struct FullExit:
    member chainId : felt       # uint8, withdraw to which chain that identified by l2 chain id
    member accountId : felt     # uint32, the account id to withdraw from
    member subAccountId : felt  # uint8, the sub account is bound to account, default value is 0(the global public sub account)
    member owner : Uint256      # 32 bytes, the address that own the account at l2
    member tokenId : felt       # uint16, the token that registered to l2
    member srcTokenId : felt    # uint16, the token that decreased in l2
    member amount : felt        # uint128, the token amount that fully withdrawn to owner, ignored at serialization and will be set when the block is submitted
end

# Deserialize fullExit pubdata
func read_fullexit_pubdata{range_check_ptr}(op_pubdata : Bytes) -> (parsed : FullExit):
    alloc_locals
    let (offset, local chainId) = read_felt(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, local accountId) = read_felt(op_pubdata, offset, ACCOUNT_ID_BYTES)
    let (offset, local subAccountId) = read_felt(op_pubdata, offset, SUB_ACCOUNT_ID_BYTES)
    let (offset, local owner) = read_uint256(op_pubdata, offset)
    let (offset, local tokenId) = read_felt(op_pubdata, offset, TOKEN_BYTES)
    let (offset, local srcTokenId) = read_felt(op_pubdata, offset, TOKEN_BYTES)
    let (offset, local amount) = read_felt(op_pubdata, offset, AMOUNT_BYTES)

    let parsed = FullExit(
        chainId=chainId,
        accountId=accountId,
        subAccountId=subAccountId,
        owner=owner,
        tokenId=tokenId,
        srcTokenId=srcTokenId,
        amount=amount,
    )
    return (parsed)
end

# Checks that FullExit is same as operation in priority queue
func check_fullexit_with_priority_operation{
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(_fullexit : FullExit, _priority_op : PriorityOperation):
    with_attr error_message("OP: not fullExit"):
        assert _priority_op.opType = OpType.FullExit
    end
    with_attr error_message("OP: invalid deposit hash"):
        let (pubdata : Bytes) = writeFullExitPubdataForPriorityQueue(_fullexit)
        let (hashed_pub_data) = hashBytesToBytes20(pubdata)
        assert hashed_pub_data = _priority_op.hashedPubData
    end
    return ()
end

func writeFullExitPubdataForPriorityQueue{range_check_ptr}(op : FullExit) -> (bytes : Bytes):
    alloc_locals
    let (local data : felt*) = alloc()

    # amount(ignored during hash calculation)
    let (_, deowner) = deserialize_address(op.owner, 9, 16, 7)

    # bytes of DepositOperation member
    # op_type :         1
    # chainId :         1
    # accountId :       4
    # subAccountId :    1
    # owner :           32
    # tokenId :         2
    # srcTokenId :      2    
    # amount :          16
    # data[0] = op_type + chain_id + account_id + sub_account_id + owner(9 bytes)
    let (value) = join_bytes(OpType.FullExit, op.chainId, 1)
    let (value) = join_bytes(value, op.accountId, 4)
    let (value) = join_bytes(value, op.subAccountId, 1)
    let (value) = join_bytes(value, deowner[0], 9)
    assert data[0] = value
    # data[1] = owner(16 bytes)
    assert data[1] = deowner[1]
    # data[1] = owner(7 bytes) + tokenId + srcTokenId + amount(5 bytes)
    let (value) = join_bytes(deowner[2], op.tokenId, 2)
    let (value) = join_bytes(value, op.srcTokenId, 2)
    let (value) = join_bytes(value, 0, 5)
    assert data[2] = value
    # data[2] = amount(15 bytes)
    assert data[3] = 0

    return (Bytes(
        size=PACKED_FULLEXIT_PUBDATA_BYTES,
        data_length=4,
        data=data
    ))
end

# Withdraw operation, 49 bytes(50 bytes wiht op_type)
struct Withdraw:
    member chainId : felt               # uint8, which chain the withdraw happened
    member accountId : felt             # uint32, the account id to withdraw from
    member tokenId : felt               # uint16, the token that to withdraw
    member amount : felt                # uint128, the token amount to withdraw
    member owner : felt                 # 32 byte, the address to receive token
    member nonce : felt                 # uint32, zero means normal withdraw, not zero means fast withdraw and the value is the account nonce
    member fastWithdrawFeeRate : felt   # uint16, fast withdraw fee rate taken by accepter
end

# Serilize Withdraw: owner, tokenId, amount, fastWithdrawFeeRate, nonce
func writeWithdrawPubdataForHash{
    range_check_ptr
}(
    owner : felt,
    tokenId : felt,
    amount : felt,
    fastWithdrawFeeRate : felt,
    nonce : felt
) -> (bytes : Bytes):
    alloc_locals
    let (local data : felt*) = alloc()

    # bytes of Withdraw member (56 bytes)
    # owner :               32
    # tokenId :             2
    # amount :              16
    # fastWithdrawFeeRate : 2
    # nonce :               4
    
    # data[0] = owner.high
    # data[1] = owner.low
    let (owner_high, owner_low) = split_felt(owner)
    assert data[0] = owner_high
    assert data[1] = owner_low
    # data[2] = tokenId + amount(14 bytes)
    let (amount_left, local amount_right) = split_felt_to_two(16, amount, 14)
    let (value) = join_bytes(tokenId, amount_left, 14)
    assert data[2] = value
    # data[3] = amount(2 bytes) + fastWithdrawFeeRate + nonce
    let (value) = join_bytes(amount_right, fastWithdrawFeeRate, 2)
    let (value) = join_bytes(value, nonce, 4)
    assert data[3] = value
    return (Bytes(
        size=56,
        data_length=4,
        data=data
    ))
end

# Deserialize Withdraw pubdata
func read_withdraw_pubdata{range_check_ptr}(op_pubdata : Bytes) -> (parsed : Withdraw):
    alloc_locals
    let (offset, local chainId) = read_felt(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, local accountId) = read_felt(op_pubdata, offset, ACCOUNT_ID_BYTES)
    let (offset, local tokenId) = read_felt(op_pubdata, offset, TOKEN_BYTES)
    let (offset, local amount) = read_felt(op_pubdata, offset, AMOUNT_BYTES)
    let (offset, local owner) = read_address(op_pubdata, offset)
    let (offset, local nonce) = read_felt(op_pubdata, offset, NONCE_BYTES)
    let (_, local fastWithdrawFeeRate) = read_felt(op_pubdata, offset, 2)
    

    let parsed = Withdraw(
        chainId=chainId,
        accountId=accountId,
        tokenId=tokenId,
        amount=amount,
        owner=owner,
        nonce=nonce,
        fastWithdrawFeeRate=fastWithdrawFeeRate
    )
    return (parsed)
end

struct ForcedExit:
    member chainId : felt   # uint8, which chain the force exit happened
    member tokenId : felt   # uint16, the token that to withdraw
    member amount : felt    # uint128, the token amount to withdraw
    member target : felt    # 32 byte, the address to receive token
end

# Deserialize ForcedExit pubdata
func read_forcedexit_pubdata{range_check_ptr}(op_pubdata : Bytes) -> (parsed : ForcedExit):
    alloc_locals
    let (offset, local chainId) = read_felt(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, local tokenId) = read_felt(op_pubdata, offset, TOKEN_BYTES)
    let (offset, local amount) = read_felt(op_pubdata, offset, AMOUNT_BYTES)
    let (offset, local target) = read_address(op_pubdata, offset)
    

    let parsed = ForcedExit(
        chainId=chainId,
        tokenId=tokenId,
        amount=amount,
        target=target
    )
    return (parsed)
end


struct ChangePubKey:
    member chainId : felt    # 1 byte, which chain to verify(only one chain need to verify for gas saving)
    member accountId : felt  # 4 byte, the account that to change pubkey
    member pubKeyHash : felt # 20 byte, hash of the new rollup pubkey
    member owner : felt   # 32 byte, the owner that own this account
    member nonce : felt      # 4 byte, the account nonce
end

# Deserialize ChangePubKey pubdata
func read_changepubkey_pubdata{range_check_ptr}(op_pubdata : Bytes) -> (parsed : ChangePubKey):
    alloc_locals
    let (offset, local chainId) = read_felt(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, local accountId) = read_felt(op_pubdata, offset, ACCOUNT_ID_BYTES)
    let (offset, local pubKeyHash) = read_felt(op_pubdata, offset, 20)
    let (offset, local owner) = read_address(op_pubdata, offset)
    let (offset, local nonce) = read_felt(op_pubdata, offset, NONCE_BYTES)

    let parsed = ChangePubKey(
        chainId=chainId,
        accountId=accountId,
        pubKeyHash=pubKeyHash,
        owner=owner,
        nonce=nonce
    )
    return (parsed)
end

