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
from zklink_utils import Token, getDepositPubdataHash, getFullExitPubdataHash


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
    governor = cached_contract(_state, account_cls, account2)
    to = cached_contract(_state, account_cls, account3)
    
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
        Token(2, token2.contract_address, 1000),
        Token(3, token3.contract_address, 0),
        Token(4, token4.contract_address, 0),
        default_sender,
        governor,
        to
    )

@pytest.fixture
async def after_initialized(deploy_factory):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = deploy_factory 

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
            3,
            *[eth.tokenId, token2.tokenId, token3.tokenId],
            3,
            *[eth.tokenAddress, token2.tokenAddress, token3.tokenAddress],
            3,
            *[1, 1, 0],
            3,
            *[eth.mappingToken, token2.mappingToken, token3.mappingToken]
        ]
    )
    
    # set eth address
    await signer.send_transaction(
        governor, zklink.contract_address, 'set_eth_address', [eth.tokenAddress]
    )

    return zklink, verifier, eth, token2, token3, token4, default_sender, governor, to


# invalid state or params should be failed when deposit
@pytest.mark.asyncio
async def test_deposit_should_failed(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized

    # exodus
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    # mint
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'mint', [*uint(to_wei(10, 'ether'))]
    )
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'approve', [zklink.contract_address, *uint(to_wei(10, 'ether'))]
    )

    to = to.contract_address
    subAccountId = 0
    amount = to_wei(1, 'ether')
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositETH',
            [*to_uint(to), subAccountId, amount]
        ),
        reverted_with='0'
    )

    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mint', [*uint(10000)]
    )
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'approve', [zklink.contract_address, *uint(100)]
    )
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositERC20',
            [token2.tokenAddress, 30, *to_uint(to), 0, 0]
        ),
        reverted_with='0'
    )

    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [0]
    )

    # ddos
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setTotalOpenPriorityRequests', [4096]
    )
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositETH',
            [*to_uint(to), subAccountId, amount]
        ),
        reverted_with='e6'
    )
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setTotalOpenPriorityRequests', [0]
    )

    # token not registered
    await signer.send_transaction(
        default_sender, token4.tokenAddress, 'mint', [*uint(10000)]
    )
    await signer.send_transaction(
        default_sender, token4.tokenAddress, 'approve', [zklink.contract_address, *uint(100)]
    )
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositERC20',
            [token4.tokenAddress, 30, *to_uint(to), 0, 0]
        ),
        reverted_with='e3'
    )

    # token deposit paused
    await signer.send_transaction(
        governor, zklink.contract_address, 'setTokenPaused',
        [token2.tokenId, 1]
    )
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositERC20',
            [token2.tokenAddress, 30, *to_uint(to), 0, 0]
        ),
        reverted_with='e4'
    )
    await signer.send_transaction(
        governor, zklink.contract_address, 'setTokenPaused',
        [token2.tokenId, 0]
    )

    # token mapping not supported
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositERC20',
            [eth.tokenAddress, 30, *to_uint(to), 0, 1]
        ),
        reverted_with='e5'
    )

    # zero amount
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositETH',
            [*to_uint(to), subAccountId, 0]
        ),
        reverted_with='e0'
    )

    # zero to address
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositETH',
            [*to_uint(0), subAccountId, amount]
        ),
        reverted_with='e1'
    )

    # subAccountId too large
    tooLargeSubId = 8
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'depositETH',
            [*to_uint(to), tooLargeSubId, amount]
        ),
        reverted_with='e2'
    )


# deposit standard erc20 should success
@pytest.mark.asyncio
async def test_deposit_standard_erc20_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized
    
    tx_exce_info = await signer.send_transaction(
        default_sender, eth.tokenAddress, 'balanceOf', [zklink.contract_address]
    )
    balance0 = from_uint(tx_exce_info.result.response)
    to = to.contract_address
    subAccountId = 0
    amount = to_wei(1, 'ether')

    # mint
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'mint', [*uint(to_wei(10, 'ether'))]
    )
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'approve', [zklink.contract_address, *uint(to_wei(10, 'ether'))]
    )

    await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositERC20',
        [eth.tokenAddress, amount, *to_uint(to), subAccountId, 0]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, eth.tokenAddress, 'balanceOf', [zklink.contract_address]
    )
    balance1 = from_uint(tx_exce_info.result.response)
    assert balance1 - balance0 == amount

    
    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPriorityHash', [0]
    )

    # TODO
    # hashedPubdata = tx_exce_info.result.response[0]
    # encodePubdata = getDepositPubdataHash([1, 0, subAccountId, eth.tokenId, eth.tokenId, amount, to])
    # assert hashedPubdata == encodePubdata


# deposit standard erc20 with mapping should success
@pytest.mark.asyncio
async def test_deposit_standard_erc20_with_mapping_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized
    
    to = to.contract_address
    subAccountId = 0
    amount = 30

    # mint
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mint', [*uint(10000)]
    )

    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [default_sender.contract_address]
    )
    senderBalance = from_uint(tx_exce_info.result.response)
    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [zklink.contract_address]
    )
    contractBalance = from_uint(tx_exce_info.result.response)

    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'approve', [zklink.contract_address, *uint(100)]
    )

    await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositERC20',
        [token2.tokenAddress, amount, *to_uint(to), subAccountId, 1]
    )

    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [zklink.contract_address]
    )
    assert from_uint(tx_exce_info.result.response) == contractBalance + amount

    tx_exce_info = await signer.send_transaction(
        default_sender, token2.tokenAddress, 'balanceOf', [default_sender.contract_address]
    )
    assert from_uint(tx_exce_info.result.response) == senderBalance - amount
    

    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPriorityHash', [0]
    )
    # TODO
    # hashedPubdata = tx_exce_info.result.response[0]
    # encodePubdata = getDepositPubdataHash([1, 0, subAccountId, token2.tokenId, token2.tokenId, amount, to])
    # assert hashedPubdata == encodePubdata


# deposit non-standard erc20 should success
@pytest.mark.asyncio
async def test_deposit_nonstandard_erc20_should_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized
    
    to = to.contract_address
    subAccountId = 0
    amount = 30
    senderFee = 3   # 30 * 0.1
    receiverFee = 6 # 30 * 0.2

    # mint
    await signer.send_transaction(
        default_sender, token3.tokenAddress, 'mint', [*uint(10000)]
    )
    tx_exce_info = await signer.send_transaction(
        default_sender, token3.tokenAddress, 'balanceOf', [default_sender.contract_address]
    )
    senderBalance = from_uint(tx_exce_info.result.response)
    tx_exce_info = await signer.send_transaction(
        default_sender, token3.tokenAddress, 'balanceOf', [zklink.contract_address]
    )
    contractBalance = from_uint(tx_exce_info.result.response)
    await signer.send_transaction(
        default_sender, token3.tokenAddress, 'approve', [zklink.contract_address, *uint(100)]
    )
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositERC20',
        [token3.tokenAddress, amount, *to_uint(to), subAccountId, 0]
    )

    tx_exce_info = await signer.send_transaction(
        default_sender, token3.tokenAddress, 'balanceOf', [zklink.contract_address]
    )
    assert from_uint(tx_exce_info.result.response) == contractBalance + (amount - receiverFee)

    tx_exce_info = await signer.send_transaction(
        default_sender, token3.tokenAddress, 'balanceOf', [default_sender.contract_address]
    )
    assert from_uint(tx_exce_info.result.response) == senderBalance - (amount + senderFee)

    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPriorityHash', [0]
    )
    # TODO
    # hashedPubdata = tx_exce_info.result.response[0]
    # encodePubdata = getDepositPubdataHash([1, 0, subAccountId, token3.tokenId, token3.tokenId, amount - receiverFee, to])
    # assert hashedPubdata == encodePubdata


# invalid state or params should be failed when full exit
@pytest.mark.asyncio
async def test_fullexit_shuold_failed(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized
    
    # exodus
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    accountId = 13
    subAccountId = 0
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'requestFullExit',
            [*to_uint(default_sender.contract_address), accountId, subAccountId, eth.tokenId, 0]
        ),
        reverted_with='0'
    )
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [0]
    )
    # ddos
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setTotalOpenPriorityRequests', [4096]
    )
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'requestFullExit',
            [*to_uint(default_sender.contract_address), accountId, subAccountId, eth.tokenId, 0]
        ),
        reverted_with='a4'
    )
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setTotalOpenPriorityRequests', [0]
    )
    # accountId too large
    tooLargeAccountId = 16777216 # 2**24
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'requestFullExit',
            [*to_uint(default_sender.contract_address), tooLargeAccountId, subAccountId, eth.tokenId, 0]
        ),
        reverted_with='a0'
    )
    # subAccountId too large
    tooLargeSubId = 8 # 2**3
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'requestFullExit',
            [*to_uint(default_sender.contract_address), accountId, tooLargeSubId, eth.tokenId, 0]
        ),
        reverted_with='a1'
    )
    # tokenId not registered
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'requestFullExit',
            [*to_uint(default_sender.contract_address), accountId, subAccountId, token4.tokenId, 0]
        ),
        reverted_with='a2'
    )
    # token mapping not supported
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'requestFullExit',
            [*to_uint(default_sender.contract_address), accountId, subAccountId, eth.tokenId, 1]
        ),
        reverted_with='a3'
    )


# requestFullExit should success 
@pytest.mark.asyncio
async def test_fullexit_shuold_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized
    
    accountId = 13
    subAccountId = 0

    await signer.send_transaction(
        default_sender, zklink.contract_address, 'requestFullExit',
        [*to_uint(default_sender.contract_address), accountId, subAccountId, eth.tokenId, 0]
    )

    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPriorityHash', [0]
    )
    # TODO
    # hashedPubdata = tx_exce_info.result.response[0]
    # encodePubdata = getFullExitPubdataHash([1, accountId, subAccountId, default_sender.contract_address, eth.tokenId, eth.tokenId, 0])
    # assert hashedPubdata == encodePubdata


# requestFullExit with mapping should success 
@pytest.mark.asyncio
async def test_fullexit_with_mapping_shuold_success(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, governor, to = after_initialized
    
    accountId = 13
    subAccountId = 0

    await signer.send_transaction(
        default_sender, zklink.contract_address, 'requestFullExit',
        [*to_uint(default_sender.contract_address), accountId, subAccountId, token2.tokenId, 1]
    )

    tx_exce_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPriorityHash', [0]
    )
    # TODO
    # hashedPubdata = tx_exce_info.result.response[0]
    # encodePubdata = getFullExitPubdataHash([1, accountId, subAccountId, default_sender.contract_address, token4.tokenId, token4.mappingToken, 0])
    # assert hashedPubdata == encodePubdata