import os
import pytest
from web3 import Web3

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from signers import MockSigner
from utils import get_contract_class, cached_contract, assert_revert

signer = MockSigner(123456789987654321)

CONTRACT_FILE = os.path.join("BytesTest")
ACCOUNT_CONTRACT_FILE = os.path.join("Account")
DATA1 = [0x0102030405060708]
DATA2 = [0x01020304050607080102030405060708, 0x0102030405060708]
DATA3 = [0x01020304050607080102030405060708, 0x01020304050607080102030405060708, 0x01020304050607080102030405060708]

@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class(ACCOUNT_CONTRACT_FILE)
    contract_cls = get_contract_class(CONTRACT_FILE)

    return account_cls, contract_cls

# Reusable to save testing time.
@pytest.fixture(scope='module')
async def contract_factory(contract_classes):
    account_cls, contract_cls = contract_classes
    
    starknet = await Starknet.empty()
    account = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    contract = await starknet.deploy(contract_class=contract_cls)
    return starknet, account, contract

@pytest.mark.asyncio
async def test_readBytes(contract_factory):
    starknet, account, contract = contract_factory
    
    # test data length = 1, first felt not full
    info = await contract.readBytes(4, 2, 8, DATA1).call()
    assert info.result == (6, [0x0506])
    
    # test data length = 2, and read bytes from first full felt
    info = await contract.readBytes(4, 2, 24, DATA2).call()
    assert info.result == (6, [0x0506])
    
    # test data length = 2, and read bytes between 2 felt, last felt not full
    info = await contract.readBytes(8, 16, 24, DATA2).call()
    assert info.result == (24, DATA1 * 2)
    
    # read bytes between 3 felt, last felt full
    info = await contract.readBytes(8, 32, 48, DATA3).call()
    assert info.result == (40, DATA1 + DATA2)
    
    # test overflow
    await assert_revert(contract.readBytes(4, 5, 8, DATA1).call())
    
@pytest.mark.asyncio
async def test_readFelt(contract_factory):
    starknet, account, contract = contract_factory
    
    # test data length = 1, first felt not full
    info = await contract.readFelt(4, 2, 8, DATA1).call()
    assert info.result == (6, 0x0506)
    
    # test data length = 2, and read felt from first full felt
    info = await contract.readFelt(4, 2, 24, DATA2).call()
    assert info.result == (6, 0x0506)
    
    # test data length = 2, and read felt between 2 felt, last felt not full
    info = await contract.readFelt(15, 2, 24, DATA2).call()
    assert info.result == (17, 0x0801)
    
    # last felt full
    info = await contract.readFelt(36, 2, 48, DATA3).call()
    assert info.result == (38, 0x0506)
    
    # test overflow
    await assert_revert(contract.readFelt(4, 5, 8, DATA1).call())
    await assert_revert(contract.readFelt(4, 32, 48, DATA3).call())
    
@pytest.mark.asyncio
async def test_readUint256(contract_factory):
    starknet, account, contract = contract_factory
    
    info = await contract.readUint256(0, 48, DATA3).call()
    assert info.result == (32, (0x01020304050607080102030405060708, 0x01020304050607080102030405060708))
    
    info = await contract.readUint256(10, 48, DATA3).call()
    assert info.result == (42, (0x03040506070801020304050607080102, 0x03040506070801020304050607080102))
    
    await assert_revert(contract.readUint256(32, 48, DATA3).call())

@pytest.mark.asyncio
async def test_readFeltArray(contract_factory):
    starknet, account, contract = contract_factory
    
    info = await contract.readFeltArray(0, 2, 1, 8, DATA1).call()
    assert info.result == (2, [0x01, 0x02])
    
    info = await contract.readFeltArray(15, 2, 1, 24, DATA2).call()
    assert info.result == (17, [0x08, 0x01])
    
    info = await contract.readFeltArray(16, 4, 8, 48, DATA3).call()
    assert info.result == (48, [0x0102030405060708, 0x0102030405060708, 0x0102030405060708, 0x0102030405060708])
    
    # test overflow
    await assert_revert(contract.readFeltArray(16, 5, 8, 48, DATA3).call())
    
@pytest.mark.asyncio
async def test_readUint256Array(contract_factory):
    starknet, account, contract = contract_factory
    
    info = await contract.readUint256Array(0, 2, 96, DATA3 * 2).call()
    assert info.result == (64, [
        (0x01020304050607080102030405060708, 0x01020304050607080102030405060708),
        (0x01020304050607080102030405060708, 0x01020304050607080102030405060708)
    ])
    
    info = await contract.readUint256Array(10, 2, 96, DATA3 * 2).call()
    assert info.result == (74, [
        (0x03040506070801020304050607080102, 0x03040506070801020304050607080102),
        (0x03040506070801020304050607080102, 0x03040506070801020304050607080102)
    ])
    
    await assert_revert(contract.readUint256Array(80, 2, 96, DATA3 * 2).call())