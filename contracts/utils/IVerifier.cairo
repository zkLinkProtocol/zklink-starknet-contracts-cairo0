%lang starknet

@contract_interface
namespace IVerifier:
    func verifyAggregatedBlockProof(size : felt, data_len : felt, data : felt*) -> (res : felt):
    end


    func verifyExitProof(
        _rootHash : Uint256,
        _chainId : felt,
        _accountId : felt,
        _subAccountId : felt,
        _owner : felt,
        _tokenId : felt,
        _srcTokenId : felt,
        _amount : felt,
        size : felt,
        data_len : felt,
        data : felt*
    ) -> (res : felt):
    end
end