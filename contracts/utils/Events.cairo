%lang starknet

from starkware.cairo.common.uint256 import Uint256

@event
func new_priority_request(
    sender : felt,
    serial_id : felt,
    op_type : felt,
    pub_data_len : felt,
    pub_data : felt*,
    expiration_block : felt
):
end

@event
func with_draw(token_id : felt, amount : felt):
end

@event
func block_commit(block_number : felt):
end

@event
func BlocksRevert(totalBlocksVerified : felt, totalBlocksCommitted):
end

# Event emitted when user funds are withdrawn from the zkLink state but not from contract
@event
func WithdrawalPending(tokenId : felt, recepient : felt, amount : felt):
end

# Event emitted when a block is executed
@event
func BlockExecuted(blockNumber : felt):
end