# ZKLink operations tools
%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256

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


# Priority operations: Deposit, FullExit
struct PriorityOperation:
    member hashed_pub_data : Uint256
    member expiration_block : felt
    member op_type : felt
end

# Deposit Operations
struct DepositOperation:
    member chain_id : felt      # deposit from which chain that identified by l2 chain id
    member account_id : felt    # the account id bound to the owner address, ignored at serialization and will be set when the block is submitted
    member sub_account_id : felt # the sub account is bound to account, default value is 0(the global public sub account)
    member token_id : felt      # the token that registered to l2
    member amount : felt        # the token amount deposited to l2
    member owner : felt       # the address that receive deposited token at l2
end

func convert_deposit_operation_to_array(deposit : DepositOperation) -> (n_elements : felt, elements : felt*):
    alloc_locals
    local deposit_array : felt*
    let (local deposit_array : felt*) = alloc()

    assert deposit_array[0] = deposit.chain_id
    assert deposit_array[1] = deposit.account_id
    assert deposit_array[2] = deposit.sub_account_id
    assert deposit_array[3] = deposit.token_id
    assert deposit_array[4] = deposit.amount
    assert deposit_array[5] = deposit.owner

    return (n_elements=6, elements=deposit_array)
end