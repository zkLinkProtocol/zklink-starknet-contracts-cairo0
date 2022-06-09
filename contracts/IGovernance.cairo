# Interface of Governance Contract
%lang starknet

from contracts.Governance import RegisteredToken

@contract_interface
namespace IGovernance:
    func get_governance_address() -> (address : felt):
    end

    func get_token_id(token_address : felt) -> (token_id : felt):
    end

    func get_token(token_id : felt) -> (token : RegisteredToken):
    end
end