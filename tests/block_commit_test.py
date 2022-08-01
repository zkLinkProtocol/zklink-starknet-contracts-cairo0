import os
import pytest

from starkware.starknet.testing.starknet import Starknet

from signers import MockSigner
from utils import get_contract_class

CONTRACT_FILE = os.path.join("ZklinkTest")
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

@pytest.mark.asyncio
async def test_testCommitBlock(contract_factory):
    starknet, account, contract = contract_factory
    
    data = [
        0x000000000000000000000000c5d24601,
        0x86f7233c927e7db2dcc703c0e500b653,
        0xca82273b7bfad8045d85a47000000000,
        0x00000000000000000000000000000000,
        0x00000000000000000000000016b6dac2,
        0x9128fe56e3755b42f97a0ed418524070,
        0x3635b5bbbb94759744d0cb0700000000,
        0x00000000000000000000000000000000,
        0x000000000000000000000000c5d24601,
        0x86f7233c927e7db2dcc703c0e500b653,
        0xca82273b7bfad8045d85a47006ef3a22,
        0xc4ba6c03ed02b3baf5939355dd9e948a,
        0xb3c7bfd9a54fda813e73951000000000,
        0x00000000000000000000000000000000,
        0x000000000000000062a9462900000001,
        0x000000000000008c0101000000020000,
        0x11001100000000000000056bc75e2d63,
        0x10000030cf409acb299b1d9badaa5873,
        0x19a105b7fb05a8000000000000000000,
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x00000000000000010000000000000000,
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
    ]
    
    await contract.testCommitBlock(0x1ac, data).invoke()