%lang starknet

from starkware.cairo.common.uint256 import Uint256

@event
func NewPriorityRequest(
    sender : felt,
    serialId : felt,
    opType : felt,
    pubData_len : felt,
    pubData : felt*,
    expirationBlock : Uint256
):
end

@event
func Withdrawal(token_id : felt, amount : felt):
end

@event
func BlockCommit(block_number : felt):
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

# Exodus mode entered event
@event
func ExodusMode():
end

# Event emitted when user sends a authentication fact (e.g. pub-key hash)
@event
func FactAuth(sender : felt, nonce : felt, fact : felt):
end

# Governor changed
@event
func NewGovernor(newGovernor : felt):
end

# Token added to ZkLink net
@event
func NewToken(tokenId : felt, token : felt):
end

# pause status update
@event
func TokenPausedUpdate(tokenId : felt, paused : felt):
end

# Validator's status changed
@event
func ValidatorStatusUpdate(validatorAddress : felt, isActive : felt):
end

# New bridge added
@event
func AddBridge(bridge : felt):
end

# Bridge update
@event
func UpdateBridge(bridgeIndex : felt, enableBridgeTo : felt, enableBridgeFrom : felt):
end

# Event emitted when accepter accept a fast withdraw
@event
func Accept(accepter : felt, accountId : felt, receiver : felt, tokenId : felt, amountSent : felt, amountReceive : felt):
end

# Event emitted when set broker allowance
@event
func BrokerApprove(tokenId : felt, owner : felt, spender : felt, amount : felt):
end