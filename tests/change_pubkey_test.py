import pytest
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from eth_utils import to_wei
from web3 import Web3
from eth_abi.packed import encode_abi_packed
from signers import MockSigner
from utils import (
    assert_revert,
    assert_event_emitted,
    get_contract_class,
    cached_contract,
    str_to_felt,
    uint,
    to_uint,
    from_uint
)
from zklink_utils import getChangePubkeyPubdata, paddingChunk, splitPubData

signer = MockSigner(123456789987654321)
nonce = 0x1234

@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class('Account')
    implementation_cls = get_contract_class('ZklinkTest')
    proxy_cls = get_contract_class('Proxy')
    verifier_cls = get_contract_class('VerifierMock')

    return account_cls, implementation_cls, proxy_cls, verifier_cls

@pytest.fixture(scope='module')
async def deploy_init(contract_classes):
    account_cls, implementation_cls, proxy_cls, verifier_cls = contract_classes
    starknet = await Starknet.empty()
    starknet.state.state.block_info = BlockInfo.create_for_testing(100, 1)
    account1 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    account2 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    implementation_decl = await starknet.declare(
        contract_class=implementation_cls,
    )
    proxy = await starknet.deploy(
        contract_class=proxy_cls,
        constructor_calldata=[implementation_decl.class_hash]
    )
    verifier = await starknet.deploy(
        contract_class=verifier_cls
    )
    
    return (
        starknet.state,
        account1,
        account2,
        proxy,
        verifier,
    )
    
@pytest.fixture
def deploy_factory(contract_classes, deploy_init):
    account_cls, _, proxy_cls, verifier_cls = contract_classes
    state, account1, account2, proxy, verifier = deploy_init
    
    governor = cached_contract(state, account_cls, account1)
    alice = cached_contract(state, account_cls, account2)
    
    zklink = cached_contract(state, proxy_cls, proxy)
    verifier = cached_contract(state, verifier_cls, verifier)

    return (
        state,
        zklink,
        verifier,
        alice,
        governor
    )

@pytest.fixture
async def after_initialized(deploy_factory):
    state, zklink, verifier, alice, governor = deploy_factory 

    # initialize proxy
    await signer.send_transaction(
        governor, zklink.contract_address, 'initializer',
        [
            verifier.contract_address,                                                      # _verifierAddress
            governor.contract_address,                                                      # _networkGovernor
            0,                                                                              # _blockNumber
            *uint(0),                                                                       # _timestamp
            *to_uint(0x209d742ecb062db488d20e7f8968a40673d718b24900ede8035e05a78351d956),   # _stateHash
            *uint(0),                                                                       # _commitment
            *to_uint(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470),   # _syncHash
        ]
    )
    
    return state, zklink, alice, governor

#set auth pubkey should be success
@pytest.mark.asyncio
async def test_set_auth_pubkey_should_success(after_initialized):
    _, zklink, alice, _ = after_initialized

    # TODO: with invalid pubkey hash length
    # pubkeyHashInvalidLength = 0xfefefefefefefefefefefefefefefefefefefe
    # await assert_revert(
    #     signer.send_transaction(
    #         alice, zklink.contract_address, 'setAuthPubkeyHash', [pubkeyHashInvalidLength, nonce]
    #     ),
    #     reverted_with='B0'
    # )

    pubkeyHash = 0xfefefefefefefefefefefefefefefefefefefefe
    await signer.send_transaction(
        alice, zklink.contract_address, 'setAuthPubkeyHash', [pubkeyHash, nonce]
    )

    expectedAuthFact = Web3.keccak(pubkeyHash)
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getAuthFact', [alice.contract_address, nonce]
    )
    assert from_uint(tx_exec_info.result.response) == int.from_bytes(expectedAuthFact, 'big')

#reset auth pubkey should be success
@pytest.mark.asyncio
async def test_reset_auth_pubkey_should_success(after_initialized):
    state, zklink, alice, governor = after_initialized

    pubkeyHash = 0xfefefefefefefefefefefefefefefefefefefefe
    await signer.send_transaction(
        alice, zklink.contract_address, 'setAuthPubkeyHash', [pubkeyHash, nonce]
    )
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getAuthFact', [alice.contract_address, nonce]
    )
    oldHash = from_uint(tx_exec_info.result.response)
    newPubkeyHash = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

    # reset time count down begin
    await signer.send_transaction(
        alice, zklink.contract_address, 'setAuthPubkeyHash', [newPubkeyHash, nonce]
    )
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getAuthFact', [alice.contract_address, nonce]
    )
    assert from_uint(tx_exec_info.result.response) == oldHash

    # must wait 24 hours
    state.state.block_info = BlockInfo.create_for_testing(100, 1 + 23 * 60 * 60)
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'setAuthPubkeyHash', [newPubkeyHash, nonce]
        ),
        reverted_with='B1'
    )

    state.state.block_info = BlockInfo.create_for_testing(100, 1 + 24 * 60 * 60)
    await signer.send_transaction(
        alice, zklink.contract_address, 'setAuthPubkeyHash', [newPubkeyHash, nonce]
    )
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getAuthFact', [alice.contract_address, nonce]
    )
    assert from_uint(tx_exec_info.result.response) == int.from_bytes(Web3.keccak(newPubkeyHash), 'big')


#verify onchain pubkey should be success
@pytest.mark.asyncio
async def test_verify_onchain_pubkey_should_success(after_initialized):
    state, zklink, alice, governor = after_initialized

    pubKeyHash = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    example = [6, 1, 1, pubKeyHash, alice.contract_address, nonce]
    # changePubkey: opType + chainId + accountId + pubKeyHash + owner + nonce
    changepubkey = encode_abi_packed(["uint8","uint8","uint32","uint160","uint256","uint32"], example)
    changepubkey_len, changepubkey = paddingChunk(changepubkey)
    print(splitPubData(changepubkey))
    # OnchainOperationData: public_data_offset + eth_witness_size + eth_witness
    onchainOperation = encode_abi_packed(["uint32", "uint32", "bytes"], [0, 2, b'0x'])
    # CommitBlockInfo: new_state_hash + timestamp + block_number + fee_account + public_data_size + public_data + onchain_operations_size + onchain_operations
    commitBlockInfo = encode_abi_packed(
        ["uint256", "uint256", "uint32", "uint32", "uint32", "bytes", "uint32", "bytes[]"],
        [0x1, 0x1, 1, 0, changepubkey_len, changepubkey, 1, [onchainOperation]]
    )
    length = len(commitBlockInfo)
    commitBlockInfo = splitPubData(commitBlockInfo)
    print("commitBlockInfo len = ", length)
    print("commitBlockInfo = ", commitBlockInfo)

    tx_exce_info = await signer.send_transaction(
        alice, zklink.contract_address, 'testCollectOnchainOps',
        [length, len(commitBlockInfo), *commitBlockInfo]
    )
    assert from_uint(
        (
            tx_exce_info.result.response[0],
            tx_exce_info.result.response[1]
        )
    ) == int.from_bytes(Web3.keccak(text="0x"), "big")
    assert tx_exce_info.result.response[2] == 0
    assert tx_exce_info.result.response[3] == int.from_bytes(b'0x010000', 'big')