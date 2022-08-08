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
)
from zklink_utils import Token, getBytesArrayData, getDepositPubdata, getFullExitPubdata

signer = MockSigner(123456789987654321)
storedBlockTemplate = (
    5,
    7,
    *to_uint(0xcf2ef9f8da5935a514cc25835ea39be68777a2674197105ca904600f26547ad2),
    *to_uint(1652422395),
    *to_uint(0xbb66ffc06a476f05a218f6789ca8946e4f0cf29f1efc2e4d0f9a8e70f0326313),
    *to_uint(0x6104d07f7c285404dc58dd0b37894b20c4193a231499a20e4056d119fc2c1184),
    *to_uint(0xab04d07f7c285404dc58dd0b37894b20c4193a231499a20e4056d119fc2c1184)
)

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
    # In pytest, Starknet default set block number is -1,
    # and cause math library fault because of out of range.
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
#
# initializer
#

@pytest.mark.asyncio
async def test_initializer(deploy_factory):
    zklink, verifier, eth, token2, token3, token4, _, _, governor = deploy_factory 

    # initialize zklink
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

    # check governor is set
    execution_info = await signer.send_transaction(
        governor, zklink.contract_address, 'getGovernor', []
    )
    assert execution_info.result.response == [governor.contract_address]
    
    # add token
    tx_exec_info = await signer.send_transaction(
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

    # check NewToken emit
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='NewToken',
        data=[
            eth.tokenId,
            eth.tokenAddress
        ]
    )
    
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='NewToken',
        data=[
            token2.tokenId,
            token2.tokenAddress
        ]
    )
    
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='NewToken',
        data=[
            token3.tokenId,
            token3.tokenAddress
        ]
    )
    
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='NewToken',
        data=[
            token4.tokenId,
            token4.tokenAddress
        ]
    )
    
    # get token
    exec_info = await signer.send_transaction(
        governor, zklink.contract_address, 'getToken', [eth.tokenId]
    )
    assert exec_info.result.response == [1, 0, eth.tokenAddress, 1, 0]
    
    exec_info = await signer.send_transaction(
        governor, zklink.contract_address, 'getTokenId', [eth.tokenAddress]
    )
    assert exec_info.result.response == [eth.tokenId]

# performExodus and cancelOutstandingDepositsForExodusMode should be failed when active
@pytest.mark.asyncio
async def test_should_failed_when_active(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = after_initialized

    owner = default_sender.contract_address
    accountId = 245
    subAccountId = 2
    tokenId = 58
    amount = to_wei(1.56, 'ether')
    proof_len, proof = getBytesArrayData([3, 0, 9, 5])
    
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'performExodus',
            [
                *storedBlockTemplate,
                owner,
                accountId,
                subAccountId,
                tokenId,
                tokenId,
                amount,
                proof_len,
                proof_len // 16 + 1,
                *proof
            ]
        ),
        reverted_with='1'
    )
    
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'cancelOutstandingDepositsForExodusMode',
            [
                3,
                0,
                *[]
            ]
        ),
        reverted_with='1'
    )

# active exodus should success
@pytest.mark.asyncio
async def test_should_success_when_active(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = after_initialized

    # mint
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'mint', [*uint(1000)]
    )
    await signer.send_transaction(
        default_sender, eth.tokenAddress, 'approve', [zklink.contract_address, *uint(1000)]
    )
    
    # deposit
    to = 0x5c5c4090980bd30e42aefeb07e2802921459aad13ee665c9274ec67871dad57
    subAccountId = 0
    amount = 1
    
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositETH',
        [
            *to_uint(to),
            subAccountId,
            amount
        ]
    )
    
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'activateExodusMode', []
    )
    
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='ExodusMode',
        data=[]
    )
    
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'activateExodusMode', []
        ),
        reverted_with='0'
    )
    
@pytest.mark.asyncio
async def test_performExodus(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = after_initialized
    
    block5 = storedBlockTemplate
    block6 = (
        6,
        7,
        *to_uint(0xcf2ef9f8da5935a514cc25835ea39be68777a2674197105ca904600f26547ad2),
        *to_uint(1652422395),
        *to_uint(0xbb66ffc06a476f05a218f6789ca8946e4f0cf29f1efc2e4d0f9a8e70f0326313),
        *to_uint(0x6104d07f7c285404dc58dd0b37894b20c4193a231499a20e4056d119fc2c1184),
        *to_uint(0xab04d07f7c285404dc58dd0b37894b20c4193a231499a20e4056d119fc2c1184)
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'mockExecBlock', [*block5]
    )

    await signer.send_transaction(
        default_sender, zklink.contract_address, 'mockExecBlock', [*block6]
    )
    
    owner = default_sender.contract_address
    accountId = 245
    subAccountId = 2
    tokenId = 58
    amount = to_wei(1.56, 'ether')
    proof_size, proof = getBytesArrayData([3, 0, 9, 5])
    
    # set not active
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    
    # not the last executed block
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'performExodus',
            [
                *block5, owner, accountId, subAccountId, tokenId, tokenId, amount,
                proof_size, proof_size // 16 + 1, *proof
            ]
        ),
        reverted_with='y1'
    )
    
    # verify failed
    await verifier.setVerifyResult(0).invoke()
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'performExodus',
            [
                *block6, owner, accountId, subAccountId, tokenId, tokenId, amount,
                proof_size, proof_size // 16 + 1, *proof
            ]
        ),
        reverted_with='y2'
    )
    
    # pending balance should increase if success
    await verifier.setVerifyResult(1).invoke()
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'performExodus',
        [
            *block6, owner, accountId, subAccountId, tokenId, tokenId, amount,
            proof_size, proof_size // 16 + 1, *proof
        ]
    )
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='WithdrawalPending',
        data=[tokenId, owner, amount]
    )

    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPendingBalance',
        [owner, tokenId]
    )
    assert tx_exec_info.result.response == [amount]
    
    # duplicate perform should be failed
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'performExodus',
            [
                *block6, owner, accountId, subAccountId, tokenId, tokenId, amount,
                proof_size, proof_size // 16 + 1, *proof
            ]
        ),
        reverted_with='y0'
    )
    
    # diff subAccount should success
    subAccountId1 = 3
    amount1 = to_wei(0.5, 'ether')
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'performExodus',
        [
            *block6, owner, accountId, subAccountId1, tokenId, tokenId, amount1,
            proof_size, proof_size // 16 + 1, *proof
        ]
    )
    assert_event_emitted(
        tx_exec_info,
        from_address=zklink.contract_address,
        name='WithdrawalPending',
        data=[tokenId, owner, amount1]
    )
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPendingBalance',
        [owner, tokenId]
    )
    assert tx_exec_info.result.response == [amount + amount1]


# cancelOutstandingDepositsForExodusMode should success
@pytest.mark.asyncio
async def test_cancelOutstandingDepositsForExodusMode(after_initialized):
    zklink, verifier, eth, token2, token3, token4, default_sender, alice, governor = after_initialized
    
    # there should be priority requests exist
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setTotalOpenPriorityRequests', [0]
    )
    
    # set not active
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    
    await assert_revert(
        signer.send_transaction(
            default_sender, zklink.contract_address, 'cancelOutstandingDepositForExodusMode',
            [
                3,
                0,
                *[]
            ]
        ),
        reverted_with='A0'
    )
    
    # set active
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [0]
    )
    
    # mint
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'mint', [*uint(to_wei(1000, 'ether'))]
    )
    await signer.send_transaction(
        default_sender, token2.tokenAddress, 'approve', [zklink.contract_address, *uint(to_wei(1000, 'ether'))]
    )
    
    amount0 = to_wei(4, 'ether')
    amount1 = to_wei(10, 'ether')
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositERC20', 
        [
            token2.tokenAddress,
            amount0,
            *to_uint(default_sender.contract_address),
            0,
            0
        ]
    )
    
    await signer.send_transaction(
        alice, zklink.contract_address, 'requestFullExit', 
        [
            *to_uint(alice.contract_address),
            14,
            2,
            token3.tokenId,
            0
        ]
    )
    
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'depositERC20', 
        [
            token2.tokenAddress,
            amount1,
            *to_uint(alice.contract_address),
            1,
            0
        ]
    )
    
    # set not active
    await signer.send_transaction(
        default_sender, zklink.contract_address, 'setExodus', [1]
    )
    
    pubdata0_len, pubdata0 = getDepositPubdata([1, 0, 0, token2.tokenId, token2.tokenId, amount0, default_sender.contract_address])
    pubdata1_len, pubdata1 = getDepositPubdata([1, 0, 1, token2.tokenId, token2.tokenId, amount1, alice.contract_address])
    
    await signer.send_transactions(
        default_sender, [
            (zklink.contract_address, 'cancelOutstandingDepositForExodusMode', [pubdata0_len, pubdata0_len // 16 + 1, *pubdata0]),
            (zklink.contract_address, 'cancelOutstandingDepositForExodusMode', [0, 0, *[]]),
            (zklink.contract_address, 'cancelOutstandingDepositForExodusMode', [pubdata1_len, pubdata1_len // 16 + 1, *pubdata1])
        ]
    )
    
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPendingBalance',
        [default_sender.contract_address, token2.tokenId]
    )
    assert tx_exec_info.result.response == [amount0]
    
    tx_exec_info = await signer.send_transaction(
        default_sender, zklink.contract_address, 'getPendingBalance',
        [alice.contract_address, token2.tokenId]
    )
    assert tx_exec_info.result.response == [amount1]