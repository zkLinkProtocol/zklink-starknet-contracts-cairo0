import os
import pytest
from web3 import Web3
from eth_abi.packed import encode_abi_packed

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from signers import MockSigner
from utils import get_contract_class, from_uint

CONTRACT_FILE = os.path.join("HashTest")
ACCOUNT_CONTRACT_FILE = os.path.join("Account")

signer = MockSigner(123456789987654321)

def splitPubData(data):
    return [int.from_bytes(x, 'big') for x in [data[i:i+16] for i in range(0, len(data), 16)]]

def getAlignedPubData(example):
    data = encode_abi_packed(["uint256", "uint256"], example)
    return len(data), splitPubData(data)

def getAlignedHash(example):
    hexbytes = Web3.solidityKeccak(["uint256", "uint256"], example)
    return int.from_bytes(hexbytes, 'big')

def getUnAlignedPubData1(example):
    data = encode_abi_packed(["uint256", "uint256", "uint128", "uint32"], example)
    return len(data), splitPubData(data)

def getUnAlignedHash1(example):
    hexbytes = Web3.solidityKeccak(["uint256", "uint256", "uint128", "uint32"], example)
    return int.from_bytes(hexbytes, 'big')

def getUnAlignedPubData2(example):
    data = encode_abi_packed(["uint256", "uint256", "uint32"], example)
    return len(data), splitPubData(data)

def getUnAlignedHash2(example):
    hexbytes = Web3.solidityKeccak(["uint256", "uint256", "uint32"], example)
    return int.from_bytes(hexbytes, 'big')

def getBytesData(example):
    data = encode_abi_packed(
        ["bytes[]"],
        [[example]]
    )
    return len(data), splitPubData(data)

def getBytesHash(example):
    hexbytes = Web3.solidityKeccak(
        ["bytes[]"],
        [[example]]
    )
    return int.from_bytes(hexbytes, 'big')

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
    account1 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    account2 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    contract = await starknet.deploy(contract_class=contract_cls)
    return contract, account1, account2

@pytest.mark.asyncio
async def test_Reverse(contract_factory):
    contract, account1, account2 = contract_factory
    
    example = int.from_bytes(b'Hello world!', 'big')
    tx_info = await contract.testReverse(example, 12).call()
    assert tx_info.result == (int.from_bytes(b'Hello world!', 'little'), )
    
    

@pytest.mark.asyncio
async def test_AddBytes(contract_factory):
    contract, account1, account2 = contract_factory
    
    # pow(2, n) align test
    example = b'Hello world!'
    pubdata_len, pubdata = getBytesData(example)
    print('pubdata_len = ', pubdata_len)
    print('pubdata = ', pubdata)
    tx_info = await contract.testAddBytes(pubdata_len, pubdata).call()
    assert tx_info.result == ([8031924123371070792, 560229490], )

@pytest.mark.asyncio
async def test_computeAlignedBytesHash(contract_factory):
    contract, account1, account2 = contract_factory
    
    # pow(2, n) align test
    example = [account1.contract_address, account2.contract_address]
    pubdata_len, pubdata = getAlignedPubData(example)
    hash = getAlignedHash(example)
    
    tx_info = await contract.computeBytesHash(pubdata_len, pubdata).call()
    assert from_uint(tx_info.result[0]) == hash
    
@pytest.mark.asyncio
async def test_computeUnAlignedBytesHash(contract_factory):
    contract, account1, account2 = contract_factory
    
    # pow(2, n) align test
    example = [account1.contract_address, account2.contract_address, 12, 1]
    pubdata_len, pubdata = getUnAlignedPubData1(example)
    hash = getUnAlignedHash1(example)
    
    tx_info = await contract.computeBytesHash(pubdata_len, pubdata).call()
    assert from_uint(tx_info.result[0]) == hash
    
    
    example = [account1.contract_address, account2.contract_address, 12]
    pubdata_len, pubdata = getUnAlignedPubData2(example)
    hash = getUnAlignedHash2(example)
    
    tx_info = await contract.computeBytesHash(pubdata_len, pubdata).call()
    assert from_uint(tx_info.result[0]) == hash
    
@pytest.mark.asyncio
async def test_computeBytesHash(contract_factory):
    contract, account1, account2 = contract_factory
    
    # pow(2, n) align test
    example = b'Hello world!'
    pubdata_len, pubdata = getBytesData(example)
    print('pubdata_len = ', pubdata_len)
    print('pubdata = ', pubdata)
    hash = getBytesHash(example)
    print('hash = ', hash)
    
    tx_info = await contract.computeBytesHash(pubdata_len, pubdata).call()
    result = from_uint(tx_info.result[0])
    print("result = ", result)
    assert from_uint(tx_info.result[0]) == hash