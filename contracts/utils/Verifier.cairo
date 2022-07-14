# zklink Verifier contracts
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256

func verifyAggregatedBlockProof{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(size : felt, data_len : felt, data : felt*) -> (res : felt):
    # TODO: implement zk verifier system on starknet
    return (1)
end


func verifyExitProof{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    range_check_ptr
}(
    _rootHash : Uint256,
    _chainId : felt,
    _accountId : felt,
    _subAccountId : felt,
    _owner : felt,
    _tokenId : felt,
    _srcTokenId : felt,
    _amount : felt,
    size : felt, data_len : felt, data : felt*
) -> (res : felt):
    # TODO: implement zk verifier system on starknet
    return (1)
end