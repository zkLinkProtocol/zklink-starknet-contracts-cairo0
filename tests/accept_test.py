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
fwAid = 1


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
        account4,
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
    state, account1, account2, account3, account4, proxy, verifier, eth, token2, token3, token4 = deploy_init
    
    _state = state.copy()
    
    default_sender = cached_contract(_state, account_cls, account1)
    alice = cached_contract(_state, account_cls, account2)
    bob = cached_contract(_state, account_cls, account3)
    governor = cached_contract(_state, account_cls, account4)
    
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
        bob,
        governor
    )

@pytest.fixture
async def after_initialized(deploy_factory):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, bob, governor = deploy_factory 

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

    return zklink, verifier, eth, token2, token3, token4, default_sender, alice, bob, governor

# broker approve should success
@pytest.mark.asyncio
async def test_broker_approve_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, bob, governor = after_initialized
    
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'brokerApprove',
        [token2.tokenId, bob.contract_address, 100]
    )
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='BrokerApprove',
        data=[token2.tokenId, alice.contract_address, bob.contract_address, 100]
    )
    tx_exec_info = await signer.send_transaction(
        alice, zklink.contract_address, 'brokerAllowance',
        [token2.tokenId, alice.contract_address, bob.contract_address]
    )
    assert tx_exec_info.result.response == [100]


# invalid state or params should failed when accept
@pytest.mark.asyncio
async def test_accept_token_should_failed(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, bob, governor = after_initialized
    
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [0, fwAid, bob.contract_address, eth.tokenId, 100, 20, 1, 100]
        ),
        reverted_with='H0'
    )
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, 0, eth.tokenId, 100, 20, 1, 100]
        ),
        reverted_with='H1'
    )
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, alice.contract_address, eth.tokenId, 100, 20, 1, 100]
        ),
        reverted_with='H2'
    )
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, bob.contract_address, 10000, 100, 20, 1, 100]
        ),
        reverted_with='H3'
    )
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, bob.contract_address, eth.tokenId, 100, 10000, 1, 100]
        ),
        reverted_with='H4'
    )
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, bob.contract_address, eth.tokenId, 100, 20, 0, 100]
        ),
        reverted_with='H5'
    )
    
    hash = calAcceptHash([bob.contract_address, eth.tokenId, 100, 100, 1])
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setAccepter',
        [fwAid, *to_uint(hash), alice.contract_address]
    )
    
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, bob.contract_address, eth.tokenId, 100, 100, 1, 100]
        ),
        reverted_with='H6'
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    await assert_revert(
        signer.send_transaction(
            alice, zklink.contract_address, 'acceptERC20',
            [alice.contract_address, fwAid, bob.contract_address, eth.tokenId, 100, 20, 1, 100]
        ),
        reverted_with='0'
    )
    

# accept standard erc20 should success
@pytest.mark.asyncio
async def test_accept_standard_erc20_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, bob, governor = after_initialized
    
    amount = to_wei(1, 'ether')
    feeRate = 100 # 1%
    nonce = 1
    amountReceive = to_wei(0.99, 'ether')
    
    # mint
    await signer.send_transaction(
        bob, token2.tokenAddress, 'mint', [*uint(to_wei(100, 'ether'))]
    )
    await signer.send_transaction(
        bob, token2.tokenAddress, 'approve', [zklink.contract_address, *uint(amount)]
    )
    
    tx_exce_info = await signer.send_transaction(
        bob, zklink.contract_address, 'acceptERC20',
        [bob.contract_address, fwAid, alice.contract_address, token2.tokenId, amount, feeRate, nonce, amountReceive]
    )
    assert_event_emitted(
        tx_exce_info,
        from_address=zklink.contract_address,
        name='Accept',
        data=[bob.contract_address, fwAid, alice.contract_address, token2.tokenId, amountReceive, amountReceive]
    )
    
    hash = calAcceptHash([alice.contract_address, token2.tokenId, amount, feeRate, nonce])
    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getAccepter',
        [fwAid, *to_uint(hash)]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf',
        [alice.contract_address]
    )
    assert tx_exce_info.result.response == [*to_uint(amountReceive)]
    
    # approve value not enough
    await signer.send_transaction(
        bob, token2.tokenAddress, 'approve', [zklink.contract_address, *uint(to_wei(0.98, 'ether'))]
    )
    nonce = 2
    await assert_revert(
        signer.send_transaction(
            bob, zklink.contract_address, 'acceptERC20',
            [bob.contract_address, fwAid, alice.contract_address, token2.tokenId, amount, feeRate, nonce, to_wei(0.98, 'ether')]
        )
    )
    
    # msg sender is not the accepter
    nonce = 3
    await signer.send_transaction(
        bob, token2.tokenAddress, 'approve', [zklink.contract_address, *uint(to_wei(2, 'ether'))]
    )
    await signer.send_transaction(
        bob, zklink.contract_address, 'brokerApprove',
        [token2.tokenId, default_sender.contract_address, to_wei(1.5, 'ether')]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'acceptERC20',
        [bob.contract_address, fwAid, alice.contract_address, token2.tokenId, amount, feeRate, nonce, amountReceive]
    )
    assert_event_emitted(
        tx_exce_info,
        from_address=zklink.contract_address,
        name='Accept',
        data=[bob.contract_address, fwAid, alice.contract_address, token2.tokenId, amountReceive, amountReceive]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'brokerAllowance',
        [token2.tokenId, bob.contract_address, default_sender.contract_address]
    )
    assert tx_exce_info.result.response == [to_wei(0.51, 'ether')]
    
    # broker allowance not enough
    nonce = 4
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'acceptERC20',
            [bob.contract_address, fwAid, alice.contract_address, token2.tokenId, amount, feeRate, nonce, amountReceive]
        ),
        reverted_with='F1'
    )
    

# accept non-standard erc20 should success
@pytest.mark.asyncio
async def test_accept_nonstandard_erc20_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, bob, governor = after_initialized
    
    amount = to_wei(1, 'ether')
    feeRate = 100 # 1%
    nonce = 1
    amountReceive = to_wei(0.99, 'ether')
    amountTransfer = to_wei(1.2375, 'ether') # to address will be taken 20% fee within transfer
    amountSent = to_wei(1.36125, 'ether') # from address will be taken 10% fee within transfer
    await signer.send_transaction(
        bob, token3.tokenAddress, 'mint', [*uint(to_wei(100, 'ether'))]
    )
    await signer.send_transaction(
        bob, token3.tokenAddress, 'approve', [zklink.contract_address, *uint(amountTransfer)]
    )
    tx_exce_info = await signer.send_transaction(
        bob, zklink.contract_address, 'acceptERC20',
        [bob.contract_address, fwAid, alice.contract_address, token3.tokenId, amount, feeRate, nonce, amountTransfer]
    )
    assert_event_emitted(
        tx_exce_info,
        from_address=zklink.contract_address,
        name='Accept',
        data=[bob.contract_address, fwAid, alice.contract_address, token3.tokenId, amountSent, amountReceive]
    )