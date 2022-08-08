import os
import pytest
from web3 import Web3

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from signers import MockSigner
from utils import get_contract_class, to_uint
from zklink_utils import (
    getDepositPubdata, getWithdrawPubdata, getFullExitPubdata,
    getForcedExitPubdata, getChangePubkeyPubdata
)

CONTRACT_FILE = os.path.join("OperationsTest")
ACCOUNT_CONTRACT_FILE = os.path.join("Account")

signer = MockSigner(123456789987654321)

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

def str_to_felt(owner):
    return int(bytes(owner, 'ascii'),16)

@pytest.mark.asyncio
async def test_testDepositPubdata(contract_factory):
    _, account, contract = contract_factory
    
    example = [1, 13, 0, 25, 23, 100, account.contract_address]
    pubdata_len, pubdata = getDepositPubdata(example)
    
    contract_example = (1, 13, 0, 25, 23, 100, to_uint(account.contract_address))
    await contract.testDepositPubdata(contract_example, pubdata_len, pubdata).invoke()
    
@pytest.mark.asyncio
async def test_testWriteDepositPubdata(contract_factory):
    _, account, contract = contract_factory
    
    # ignore accountId
    contract_example = (1, 13, 0, 25, 23, 100, to_uint(account.contract_address))
    await contract.testWriteDepositPubdata(contract_example).invoke()
    
@pytest.mark.asyncio
async def test_testWithdrawPubdata(contract_factory):
    _, account, contract = contract_factory
    
    example = [1, 32, 34, 32, account.contract_address, 45, 45]
    pubdata_len, pubdata = getWithdrawPubdata(example)
    
    contract_example = (1, 32, 34, 32, account.contract_address, 45, 45)
    await contract.testWithdrawPubdata(contract_example, pubdata_len, pubdata).invoke()
    
@pytest.mark.asyncio
async def test_testFullExitPubdata(contract_factory):
    _, account, contract = contract_factory
    
    example = [1, 34, 23, account.contract_address, 2, 1, 15]
    pubdata_len, pubdata = getFullExitPubdata(example)
    
    contract_example = (1, 34, 23, to_uint(account.contract_address), 2, 1, 15)
    await contract.testFullExitPubdata(contract_example, pubdata_len, pubdata).invoke()
    
@pytest.mark.asyncio
async def test_testWriteFullExitPubdata(contract_factory):
    _, account, contract = contract_factory
    
    contract_example = (1, 34, 23, to_uint(account.contract_address), 2, 1, 15)
    await contract.testWriteFullExitPubdata(contract_example).invoke()
    
@pytest.mark.asyncio
async def test_testForcedExitPubdata(contract_factory):
    _, account, contract = contract_factory
    
    example = [1, 5, 6, account.contract_address]
    pubdata_len, pubdata = getForcedExitPubdata(example)
    
    contract_example = (1, 5, 6, account.contract_address)
    await contract.testForcedExitPubdata(contract_example, pubdata_len, pubdata).invoke()
    
@pytest.mark.asyncio
async def test_testChangePubkeyPubdata(contract_factory):
    _, account, contract = contract_factory
    
    pubKeyHash = '0x823B747710C5bC9b8A47243f2c3d1805F1aA00c5'
    
    example = [1, 2, pubKeyHash, account.contract_address, 3]
    pubdata_len, pubdata = getChangePubkeyPubdata(example)
    
    contract_example = (1, 2, str_to_felt(pubKeyHash), account.contract_address, 3)
    await contract.testChangePubkeyPubdata(contract_example, pubdata_len, pubdata).invoke()