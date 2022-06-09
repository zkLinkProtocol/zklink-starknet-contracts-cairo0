# ZKLink main contract: deposit, withdraw, add or remove liquidity, swap
%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.cairo_builtins import (
    HashBuiltin,
    BitwiseBuiltin
)
from starkware.cairo.common.math import assert_not_equal, assert_nn_le
from starkware.starknet.common.syscalls import (
    get_block_number,
    get_caller_address
)

from contracts.utils.Operations import (
    OPERATIONS_OPTYPE_DEPOSIT,
    OPERATIONS_OPTYPE_FULL_EXIT,
    PriorityOperation,
    DepositOperation,
    FullExit,
    convert_deposit_operation_to_array,
    convert_fullexit_operation_to_array
)

from contracts.utils.Utils import (
    hash_array_to_uint256
)

from contracts.utils.Config import (
    ETH_ADDRESS,
    EXODUS_MODE_ON,
    MAX_PRIORITY_REQUESTS,
    MAX_DEPOSIT_AMOUNT,
    MAX_ACCOUNT_ID,
    MAX_SUB_ACCOUNT_ID,
    PRIORITY_EXPIRATION
)

from contracts.utils.Storage import (
    get_total_open_priority_requests,
    get_chain_id,
    get_first_priority_request_id,
    set_priority_request
)

from contracts.utils.Events import new_priority_request
from contracts.utils.ReentrancyGuard import (
    reentrancy_guard_init,
    reentrancy_guard_lock,
    reentrancy_guard_unlock
)
from contracts.Governance import RegisteredToken
from contracts.IGovernance import IGovernance

#
# Storage section.
#

# Indicates that exodus (mass exit) mode is triggered.
@storage_var
func exodus_mode() -> (res : felt):
end

# Governance contract address
@storage_var
func governance_address_storage() -> (address : felt):
end

@view
func get_governance_address_storage{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (address : felt):
    let (address) = governance_address_storage.read()
    return (address)
end

@external
func set_governance_address_storage{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(governance_address : felt):
    governance_address_storage.write(governance_address)
    return ()
end

# Constructor
@constructor
func constructor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(governance_address : felt):
    reentrancy_guard_init()
    governance_address_storage.write(governance_address)
    return ()
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
# @external
# func deposit_ERC20{
#     syscall_ptr : felt*,
#     pedersen_ptr : HashBuiltin*,
#     bitwise_ptr : BitwiseBuiltin*,
#     range_check_ptr
# }(zklink_address : felt, sub_account_id : felt, amount : felt):
#     # Lock with reentrancy_guard
#     reentrancy_guard_lock()
    
#     # deposit
#     deposit(
#         token_address=ETH_ADDRESS,
#         amount=amount,
#         zklink_address=zklink_address,
#         sub_account_id=sub_account_id
#     )

#     # Unlock
#     reentrancy_guard_unlock()
#     return ()
# end

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
    let (governance_address) = get_governance_address_storage()
    let (rt : RegisteredToken) = IGovernance.get_token(
        contract_address=governance_address,
        token_id=token_id
    )
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
    let (exodus_mode_stat) = exodus_mode.read()
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

    let (governance_address) = get_governance_address_storage()
    let (token_id) = IGovernance.get_token_id(
        contract_address=governance_address,
        token_address=token_address
    )
    let (rt : RegisteredToken) = IGovernance.get_token(
        contract_address=governance_address,
        token_id=token_id
    )

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

    let (hashed_pub_data : Uint256) = hash_array_to_uint256(n_elements, pub_data)

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
