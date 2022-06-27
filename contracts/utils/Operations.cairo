# ZKLink operations tools
%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from contracts.utils.Utils import hash_array_to_uint160, read_pubdata 
from Config import PUBLIC_DATA_ELEMENT_BYTES

# ZKLink circuit operation type
const OPERATIONS_OPTYPE_NOOP  = 0                       # 0
const OPERATIONS_OPTYPE_DEPOSIT = 1                     # 1 L1 Op
const OPERATIONS_OPTYPE_TRANSFER_TO_NEW = 2             # 2 L2 Op
const OPERATIONS_OPTYPE_WITHDRAW = 3                    # 3 L2 Op
const OPERATIONS_OPTYPE_TRANSFER = 4                    # 4 L2 Op
const OPERATIONS_OPTYPE_FULL_EXIT = 5                   # 5 L1 Op
const OPERATIONS_OPTYPE_CHANGE_PUBKEY = 6               # 6 L2 Op
const OPERATIONS_OPTYPE_FORCE_EXIT = 7                  # 7 L2 Op
const OPERATIONS_OPTYPE_L2_CURVE_ADD_LIQUIDITY = 8      # 8 L2 Op
const OPERATIONS_OPTYPE_L2_CURVE_SWAP = 9               # 9 L2 Op
const OPERATIONS_OPTYPE_L2_CURVE_REMOVE_LIQUIDITY = 10  # 10 Op
const OPERATIONS_OPTYPE_ORDER_MATCHING = 11             # 11 L2 Op

const OP_TYPE_BYTES = 1         # op is uint8
const CHAIN_BYTES = 1           # chainId is uint8
const TOKEN_BYTES = 2           # token is uint16
const NONCE_BYTES = 4           # nonce is uint32
const ADDRESS_BYTES = 20        # L2 address is 20 bytes length
const FEE_BYTES = 2             # fee is uint16
const ACCOUNT_ID_BYTES = 4      # accountId is uint32
const SUB_ACCOUNT_ID_BYTES = 1  # subAccountId is uint8
const AMOUNT_BYTES = 16         # amount is uint128

# Priority operations: Deposit, FullExit
struct PriorityOperation:
    member hashed_pub_data : felt    # hashed priority operation public data
    member expiration_block : felt      # expiration block number (ETH block) for this request (must be satisfied before)
    member op_type : felt               # priority operation type
end

# Deposit Operation
struct DepositOperation:
    member chain_id : felt      # deposit from which chain that identified by l2 chain id
    member account_id : felt    # the account id bound to the owner address, ignored at serialization and will be set when the block is submitted
    member sub_account_id : felt # the sub account is bound to account, default value is 0(the global public sub account)
    member token_id : felt      # the token that registered to l2
    member target_token_id : felt # the token that user increased in l2
    member amount : felt        # the token amount deposited to l2
    member owner : felt       # the address that receive deposited token at l2
end

# 47 bytes
const PACKED_DEPOSIT_PUBDATA_BYTES = OP_TYPE_BYTES + CHAIN_BYTES + ACCOUNT_ID_BYTES + SUB_ACCOUNT_ID_BYTES + TOKEN_BYTES * 2 + AMOUNT_BYTES + ADDRESS_BYTES

# Deserialize deposit pubdata
func read_deposit_pubdata{range_check_ptr}(op_pubdata : felt*) -> (parsed : DepositOperation):
    let (offset, chain_id) = read_pubdata(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, account_id) = read_pubdata(op_pubdata, offset, ACCOUNT_ID_BYTES)
    let (offset, sub_account_id) = read_pubdata(op_pubdata, offset, SUB_ACCOUNT_ID_BYTES)
    let (offset, token_id) = read_pubdata(op_pubdata, offset, TOKEN_BYTES)
    let (offset, target_token_id) = read_pubdata(op_pubdata, offset, TOKEN_BYTES)
    let (offset, amount) = read_pubdata(op_pubdata, offset, AMOUNT_BYTES)
    let (offset, owner) = read_pubdata(op_pubdata, offset, ADDRESS_BYTES)

    let parsed = DepositOperation(
        chain_id=chain_id,
        account_id=account_id,
        sub_account_id=sub_account_id,
        token_id=token_id,
        target_token_id=target_token_id,
        amount=amount,
        owner=owner
    )
    with_attr error_message("OP: invalid deposit"):
        assert offset = PACKED_DEPOSIT_PUBDATA_BYTES
    end
    return (parsed)
end

func convert_deposit_operation_to_array(op : DepositOperation) -> (n_elements : felt, elements : felt*):
    alloc_locals
    local op_array : felt*
    let (local op_array : felt*) = alloc()

    assert op_array[0] = op.chain_id
    assert op_array[1] = op.account_id
    assert op_array[2] = op.sub_account_id
    assert op_array[3] = op.token_id
    assert op_array[4] = op.amount
    assert op_array[5] = op.owner

    return (n_elements=6, elements=op_array)
end

# Checks that deposit is same as operation in priority queue
func check_priority_operation{range_check_ptr}(_deposit : DepositOperation, _priority_op : PriorityOperation):
    with_attr error_message("OP: not deposit"):
        assert _priority_op.op_type = OPERATIONS_OPTYPE_DEPOSIT
    end
    with_attr error_message("OP: invalid deposit hash"):
        let (num, pub_data) = convert_deposit_operation_to_array(op)
        let (hashed_pub_data) = hash_array_to_uint160(num, pub_data)
        assert hashed_pub_data = _priority_op.hashed_pub_data
    end
end

# FullExit Operation
struct FullExit:
    member chain_id : felt          # withdraw to which chain that identified by l2 chain id
    member account_id : felt        # the account id to withdraw from
    member sub_account_id : felt    # the sub account is bound to account, default value is 0(the global public sub account)
    member owner : felt             # the address that own the account at l2
    member token_id : felt          # the token that registered to l2
    member amount : felt            # the token amount that fully withdrawn to owner, ignored at serialization and will be set when the block is submitted
end

func convert_fullexit_operation_to_array(op : FullExit) -> (n_elements : felt, elements : felt*):
    alloc_locals
    local op_array : felt*
    let (local op_array : felt*) = alloc()

    assert op_array[0] = op.chain_id
    assert op_array[1] = op.account_id
    assert op_array[2] = op.sub_account_id
    assert op_array[3] = op.owner
    assert op_array[4] = op.token_id
    assert op_array[5] = op.amount

    return (n_elements=6, elements=op_array)
end



struct ChangePubKey:
    member chain_id : felt    # 1 byte, which chain to verify(only one chain need to verify for gas saving)
    member account_id : felt  # 4 byte, the account that to change pubkey
    member pubkey_hash : felt # 20 byte, hash of the new rollup pubkey
    member owner : felt       # 20 byte, the owner that own this account
    member nonce : felt       # 4 byte, the account nonce
end

# Deserialize ChangePubKey pubdata
func read_changepubkey_pubdata{range_check_ptr}(op_pubdata : felt*) -> (parsed : ChangePubKey):
    let (offset, chain_id) = read_pubdata(op_pubdata, OP_TYPE_BYTES, CHAIN_BYTES)
    let (offset, account_id) = read_pubdata(op_pubdata, offset, ACCOUNT_ID_BYTES)
    let (offset, pubkey_hash) = read_pubdata(op_pubdata, offset, 20)
    let (offset, owner) = read_pubdata(op_pubdata, offset, ADDRESS_BYTES)
    let (offset, nonce) = read_pubdata(op_pubdata, offset, NONCE_BYTES)

    let parsed = ChangePubKey(
        chain_id=chain_id,
        account_id=account_id,
        pubkey_hash=pubkey_hash,
        owner=owner,
        nonce=nonce
    )
    # with_attr error_message("OP: invalid deposit"):
    #     assert offset = PACKED_DEPOSIT_PUBDATA_BYTES
    # end
    return (parsed)
end