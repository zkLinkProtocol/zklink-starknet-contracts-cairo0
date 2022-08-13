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
from zklink_utils import Token, calAcceptHash


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
    account4 = await starknet.deploy(
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

    token2 = await starknet.deploy(
        contract_class=st_cls,
        constructor_calldata=[str_to_felt('Toekn2'), str_to_felt('T2')]
    )
    
    return (
        starknet.state,
        account1,
        account2,
        account3,
        account4,
        proxy,
        verifier,
        token2,
    )
    
@pytest.fixture
def deploy_factory(contract_classes, deploy_init):
    account_cls, _, proxy_cls, verifier_cls, st_cls, nst_cls = contract_classes
    state, account1, account2, account3, account4, proxy, verifier, token2 = deploy_init
    
    _state = state.copy()
    
    default_sender = cached_contract(_state, account_cls, account1)
    alice = cached_contract(_state, account_cls, account2)
    bob = cached_contract(_state, account_cls, account3)
    governor = cached_contract(_state, account_cls, account4)
    
    zklink = cached_contract(_state, proxy_cls, proxy)
    verifier = cached_contract(_state, verifier_cls, verifier)
    
    token2 = cached_contract(_state, st_cls, token2)

    return (
        zklink,
        verifier,
        Token(2, token2.contract_address, 0),
        default_sender,
        alice,
        bob,
        governor
    )

@pytest.fixture
async def after_initialized(deploy_factory):
    zklink, verifier, token2, default_sender, alice, bob, governor = deploy_factory 

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
            1,
            *[token2.tokenId],
            1,
            *[token2.tokenAddress],
            1,
            *[1],
            1,
            *[token2.mappingToken]
        ]
    )

    return zklink, token2, default_sender, alice, bob

# normal withdraw erc20 token should success
@pytest.mark.asyncio
async def test_normal_withdraw_erc20_should_success(after_initialized):
    zklink, token2, default_sender, alice, bob = after_initialized
    
    chainId = 1
    accountId = 1
    tokenId = token2.tokenId
    amount = to_wei(10, 'ether')
    owner = bob.contract_address
    nonce = 0
    fastWithdrawFeeRate = 50
    
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mintTo',
        [zklink.contract_address, *to_uint(amount)]
    )
    
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [owner]
    )
    b0 = from_uint(tx_exce_info.result.response)
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'testExecuteWithdraw',
        [chainId, accountId, tokenId, amount, owner, nonce, fastWithdrawFeeRate]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [owner]
    )
    b1 = from_uint(tx_exce_info.result.response)
    assert b1 - b0 == amount


# fast withdraw and accept finish, token should be sent to accepter
@pytest.mark.asyncio
async def test_fast_withdraw_and_accept_finish(after_initialized):
    zklink, token2, default_sender, alice, bob = after_initialized
    
    chainId = 1
    accountId = 1
    tokenId = token2.tokenId
    amount = to_wei(10, 'ether')
    owner = alice.contract_address
    nonce = 1
    fastWithdrawFeeRate = 50
    MAX_WITHDRAW_FEE_RATE = 10000
    
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [bob.contract_address]
    )
    bobBalance0 = from_uint(tx_exce_info.result.response)
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPendingBalance',
        [bob.contract_address, tokenId]
    )
    bobPendingBalance0 = tx_exec_info.result.response[0]
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [alice.contract_address]
    )
    aliceBalance0 = from_uint(tx_exce_info.result.response)
    
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mintTo',
        [bob.contract_address, *to_uint(amount)]
    )
    amountTransfer = int(amount * (MAX_WITHDRAW_FEE_RATE - fastWithdrawFeeRate) / MAX_WITHDRAW_FEE_RATE)
    await signer.send_transaction(
        bob, token2.tokenAddress, 'approve',
        [zklink.contract_address, *to_uint(amountTransfer)]
    )
    await signer.send_transaction(
        bob, zklink.contract_address, 'acceptERC20',
        [bob.contract_address, accountId, owner, tokenId, amount, fastWithdrawFeeRate, nonce, amountTransfer]
    )
    
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mintTo',
        [zklink.contract_address, *to_uint(amount)]
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'testExecuteWithdraw',
        [chainId, accountId, tokenId, amount, owner, nonce, fastWithdrawFeeRate]
    )
    
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [alice.contract_address]
    )
    aliceBalance1 = from_uint(tx_exce_info.result.response)
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [bob.contract_address]
    )
    bobBalance1 = from_uint(tx_exce_info.result.response)
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPendingBalance',
        [bob.contract_address, tokenId]
    )
    bobPendingBalance1 = tx_exec_info.result.response[0]
    
    assert aliceBalance1 - aliceBalance0 == amountTransfer
    assert bobBalance1 - bobBalance0 == amount - amountTransfer # amount - amountTransfer is the profit of accept
    assert bobPendingBalance1 - bobPendingBalance0 == amount    # accepter pending balance increase
    
    
# fast withdraw but accept not finish, token should be sent to owner as normal
@pytest.mark.asyncio
async def test_fast_withdraw_and_accept_not_finish(after_initialized):
    zklink, token2, default_sender, alice, bob = after_initialized
    
    chainId = 1
    accountId = 1
    tokenId = token2.tokenId
    amount = to_wei(10, 'ether')
    owner = alice.contract_address
    nonce = 2
    fastWithdrawFeeRate = 50
    
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [alice.contract_address]
    )
    aliceBalance0 = from_uint(tx_exce_info.result.response)
    
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mintTo',
        [zklink.contract_address, *to_uint(amount)]
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'testExecuteWithdraw',
        [chainId, accountId, tokenId, amount, owner, nonce, fastWithdrawFeeRate]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [alice.contract_address]
    )
    aliceBalance1 = from_uint(tx_exce_info.result.response)
    assert aliceBalance1 - aliceBalance0 == amount
    # TODO
    # hash = calAcceptHash([owner, tokenId, amount, fastWithdrawFeeRate, nonce])
    # tx_exce_info = await signer.send_transaction(
    #     default_sender, zklink.contract_address, 'getAccepter',
    #     [accountId, *to_uint(hash)]
    # )
    # assert tx_exce_info.result.response == [owner]