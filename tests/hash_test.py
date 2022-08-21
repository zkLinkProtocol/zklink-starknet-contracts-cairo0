import os
import pytest
from web3 import Web3
from eth_abi.packed import encode_abi_packed
from eth_utils import to_wei

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from signers import MockSigner
from utils import get_contract_class, from_uint, to_uint
from zklink_utils import (
    getDepositPubdata, getDepositPubdataHash32, getDepositPubdataHash20,
    getFullExitPubdata, getFullExitPubdataHash32
)

CONTRACT_FILE = os.path.join("HashTest")
ACCOUNT_CONTRACT_FILE = os.path.join("Account")

signer = MockSigner(123456789987654321)

def splitPubData(data):
    return [int.from_bytes(x, 'big') for x in [data[i:i+16] for i in range(0, len(data), 16)]]

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
async def test_keccakBytes(contract_factory):
    contract, account1, account2 = contract_factory
    
    ethId = 1
    to = account2.contract_address
    subAccountId = 0
    amount = to_wei(1, 'ether')
    example = [1, 0, subAccountId, ethId, ethId, amount, to]
    
    pubdata_len, pubdata = getDepositPubdata(example)
    hash = getDepositPubdataHash32(example)

    tx_info = await contract.testKeccakBytes(pubdata_len, pubdata).call()
    assert from_uint(tx_info.result[0]) == hash

    token4Id = 4
    accountId = 13
    example = [1, accountId, subAccountId, account1.contract_address, token4Id, 0, 0]

    pubdata_len, pubdata = getFullExitPubdata(example)
    hash = getFullExitPubdataHash32(example)
    tx_info = await contract.testKeccakBytes(pubdata_len, pubdata).call()
    assert from_uint(tx_info.result[0]) == hash

@pytest.mark.asyncio
async def test_keccakUint256s(contract_factory):
    contract, account1, account2 = contract_factory

    data = [account1.contract_address, account2.contract_address] * 10
    hash = int.from_bytes(
        Web3.solidityKeccak(
            [
                "uint256", "uint256", "uint256", "uint256",
                "uint256", "uint256", "uint256", "uint256",
                "uint256", "uint256", "uint256", "uint256",
                "uint256", "uint256", "uint256", "uint256",
                "uint256", "uint256", "uint256", "uint256",
            ],
            data),
        'big'
    )
    tx_info = await contract.testKeccakUint256s([to_uint(x) for x in data]).call()
    assert from_uint(tx_info.result[0]) == hash

@pytest.mark.asyncio
async def test_concatTwoHash(contract_factory):
    contract, account1, account2 = contract_factory

    hash = int.from_bytes(
        Web3.solidityKeccak(
            ["uint256", "uint256"],
            [account1.contract_address, account2.contract_address]
        ),
        'big'
    )

    tx_info = await contract.testconcatTwoHash(
        to_uint(account1.contract_address),
        to_uint(account2.contract_address)
    ).call()
    assert from_uint(tx_info.result[0]) == hash

@pytest.mark.asyncio
async def test_concatHash(contract_factory):
    contract, account1, account2 = contract_factory

    ethId = 1
    to = account2.contract_address
    subAccountId = 0
    amount = to_wei(1, 'ether')
    example1 = [1, 0, subAccountId, ethId, ethId, amount, to]
    pubdata_len, pubdata = getDepositPubdata(example1)

    test_bytes =  encode_abi_packed(
        ["uint8","uint8","uint32","uint8","uint16","uint16","uint128","uint256"],
        [1] + example1
    )
    token4Id = 4
    accountId = 13
    example2 = [1, accountId, subAccountId, account1.contract_address, token4Id, 0, 0]
    test_hash = getFullExitPubdataHash32(example2)

    hash = int.from_bytes(
        Web3.solidityKeccak(
            ["uint256", "bytes[]"],
            [test_hash, [test_bytes]]
        ),
        'big'
    )

    tx_info = await contract.testconcatHash(to_uint(test_hash), pubdata_len, pubdata).call()
    assert from_uint(tx_info.result[0]) == hash

@pytest.mark.asyncio
async def test_hashBytesToBytes20(contract_factory):
    contract, account1, account2 = contract_factory

    ethId = 1
    to = account2.contract_address
    subAccountId = 0
    amount = to_wei(1, 'ether')
    example = [1, 0, subAccountId, ethId, ethId, amount, to]
    
    pubdata_len, pubdata = getDepositPubdata(example)
    hash = getDepositPubdataHash20(example)

    tx_info = await contract.testhashBytesToBytes20(pubdata_len, pubdata).call()
    assert tx_info.result[0] == hash