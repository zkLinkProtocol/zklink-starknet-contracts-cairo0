import pytest
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from eth_utils import to_wei
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
from zklink_utils import Token, getBytesArrayData, getDepositPubdata


signer = MockSigner(123456789987654321)


@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class('Account')
    implementation_cls = get_contract_class('ZklinkTest')
    proxy_cls = get_contract_class('Proxy')
    verifier_cls = get_contract_class('VerifierMock')
    st_cls = get_contract_class('StandardToken')
    nst_cls = get_contract_class('NonStandardToken')

    return account_cls, implementation_cls, proxy_cls, verifier_cls, st_cls, nst_cls

@pytest.fixture(scope='module')
async def deploy_init(contract_classes):
    account_cls, implementation_cls, proxy_cls, verifier_cls, st_cls, nst_cls = contract_classes
    starknet = await Starknet.empty()
    starknet.state.state.block_info = BlockInfo.create_for_testing(100, 0)
    account1 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    account2 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    account3 = await starknet.deploy(
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
    eth = await starknet.deploy(
        contract_class=st_cls,
        constructor_calldata=[str_to_felt('Ether'), str_to_felt('ETH')]
    )
    token2 = await starknet.deploy(
        contract_class=st_cls,
        constructor_calldata=[str_to_felt('Toekn2'), str_to_felt('T2')]
    )
    token3 = await starknet.deploy(
        contract_class=nst_cls,
        constructor_calldata=[str_to_felt('Toekn3'), str_to_felt('T3')]
    )
    token4 = await starknet.deploy(
        contract_class=st_cls,
        constructor_calldata=[str_to_felt('Toekn4'), str_to_felt('T4')]
    )
    
    return (
        starknet.state,
        account1,
        account2,
        account3,
        proxy,
        verifier,
        eth,
        token2,
        token3,
        token4
    )
    
@pytest.fixture
def deploy_factory(contract_classes, deploy_init):
    account_cls, _, proxy_cls, verifier_cls, st_cls, nst_cls = contract_classes
    state, account1, account2, account3, proxy, verifier, eth, token2, token3, token4 = deploy_init
    
    _state = state.copy()
    
    default_sender = cached_contract(_state, account_cls, account1)
    alice = cached_contract(_state, account_cls, account2)
    governor = cached_contract(_state, account_cls, account3)
    
    zklink = cached_contract(_state, proxy_cls, proxy)
    verifier = cached_contract(_state, verifier_cls, verifier)
    
    eth = cached_contract(_state, st_cls, eth)
    token2 = cached_contract(_state, st_cls, token2)
    token3 = cached_contract(_state, nst_cls, token3)
    token4 = cached_contract(_state, st_cls, token4)

    return (
        zklink,
        verifier,
        Token(1, eth.contract_address, 0),
        Token(2, token2.contract_address, 0),
        Token(3, token3.contract_address, 0),
        Token(4, token4.contract_address, 1000),
        default_sender,
        alice,
        governor
    )

@pytest.fixture
async def after_initialized(deploy_factory):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = deploy_factory 

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
    
    # add token
    await signer.send_transaction(
        governor, zklink.contract_address, 'addTokens',
        [
            4,
            *[eth.tokenId, token2.tokenId, token3.tokenId, token4.tokenId],
            4,
            *[eth.tokenAddress, token2.tokenAddress, token3.tokenAddress, token4.tokenAddress],
            4,
            *[1, 1, 0, 1],
            4,
            *[eth.mappingToken, token2.mappingToken, token3.mappingToken, token4.mappingToken]
        ]
    )
    
    # set eth address
    await signer.send_transaction(
        governor, zklink.contract_address, 'set_eth_address', [eth.tokenAddress]
    )

    return zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor

# invalid state or params should be failed when withdraw pending balance
@pytest.mark.asyncio
async def test_withdrawPendingBalance_should_failed(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = after_initialized
    
    # token not registered
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'withdrawPendingBalance',
            [default_sender.contract_address, 100, 1]
        ),
        reverted_with='b0'
    )
    
    # zero amount
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'withdrawPendingBalance',
            [default_sender.contract_address, eth.tokenId, 0]
        ),
        reverted_with='b1'
    )
    
    # no pending balance
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'withdrawPendingBalance',
            [default_sender.contract_address, eth.tokenId, 0]
        ),
        reverted_with='b1'
    )

# withdraw pending balance should success
@pytest.mark.asyncio
async def test_withdrawPendingBalance_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = after_initialized
    
    depositAmount = to_wei(1.0, 'ether')
    
    # mint
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'mint', [*uint(to_wei(10, 'ether'))]
    )
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'approve', [zklink.contract_address, *uint(to_wei(10, 'ether'))]
    )
    
    # increase pending balance
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositETH',
        [
            *to_uint(alice.contract_address),
            0,
            depositAmount
        ]
    )
    
    pubdata_size, pubdata = getDepositPubdata([1, 0, 0, eth.tokenId, eth.tokenId, depositAmount, alice.contract_address])
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'cancelOutstandingDepositForExodusMode',
        [pubdata_size, pubdata_size // 16 + 1, *pubdata]
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [0]
    )
    
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getPendingBalance',
        [alice.contract_address, eth.tokenId]
    )
    assert tx_exec_info.result.response == [depositAmount]
    
    tx_exec_info = await signer.send_transaction(
        alice, eth.tokenAddress, 'balanceOf',
        [alice.contract_address]
    )
    b0 = from_uint(tx_exec_info.result.response)
    
    amount0 = to_wei(0.5, 'ether')
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'withdrawPendingBalance',
        [alice.contract_address, eth.tokenId, amount0]
    )
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='Withdrawal',
        data=[eth.tokenId, amount0]
    )
    
    tx_exec_info = await signer.send_transaction(
        alice, eth.tokenAddress, 'balanceOf',
        [alice.contract_address]
    )
    b1 = from_uint(tx_exec_info.result.response)
    assert b1 == b0 + amount0
    
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getPendingBalance',
        [alice.contract_address, eth.tokenId]
    )
    assert tx_exec_info.result.response == [depositAmount - amount0]
    
    leftAmount = depositAmount - amount0
    amount1 = to_wei(0.6, 'ether')
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'withdrawPendingBalance',
        [alice.contract_address, eth.tokenId, amount1]
    )
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='Withdrawal',
        data=[eth.tokenId, leftAmount]
    )
    tx_exec_info = await signer.send_transaction(
        alice, eth.tokenAddress, 'balanceOf',
        [alice.contract_address]
    )
    b2 = from_uint(tx_exec_info.result.response)
    assert b2 == b0 + depositAmount
    
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'getPendingBalance',
        [alice.contract_address, eth.tokenId]
    )
    assert tx_exec_info.result.response == [0]
    