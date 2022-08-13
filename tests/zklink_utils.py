from eth_abi.packed import encode_abi_packed
from web3 import Web3

OP_NOOP = 0
OP_DEPOSIT = 1
OP_TRANSFER_TO_NEW = 2
OP_WITHDRAW = 3
OP_TRANSFER = 4
OP_FULL_EXIT = 5
OP_CHANGE_PUBKEY = 6
OP_FORCE_EXIT = 7
OP_ORDER_MATCHING = 11
CHUNK_BYTES = 14
BYTES_PER_FELT = 16

class Token():
    def __init__(self, tokenId, tokenAddress, mappingToken):
        self.tokenId = tokenId
        self.tokenAddress = tokenAddress
        self.mappingToken = mappingToken

def splitPubData(data):
    return [int.from_bytes(x, 'big') for x in [data[i:i+BYTES_PER_FELT] for i in range(0, len(data), BYTES_PER_FELT)]]

def getDepositPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","uint8","uint16","uint16","uint128","uint256"],
        [OP_DEPOSIT] + example)
    return len(data), splitPubData(data)

def getWithdrawPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","uint16","uint128","uint256","uint32","uint16"],
        [OP_WITHDRAW] + example)
    return len(data), splitPubData(data)

def getFullExitPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","uint8","uint256","uint16","uint16","uint128"],
        [OP_FULL_EXIT] + example)
    return len(data), splitPubData(data)

def getForcedExitPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint16","uint128","uint256"],
        [OP_FORCE_EXIT] + example)
    return len(data), splitPubData(data)

def getChangePubkeyPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","address","uint256","uint32"],
        [OP_CHANGE_PUBKEY] + example)
    return len(data), splitPubData(data)

def getBytesArrayData(example):
    data = encode_abi_packed(
        ["bytes[]"],
        [[ x.to_bytes(1, 'big') for x in example]]
    )
    return len(data), splitPubData(data)

def calAcceptHash(example):
    hexbytes = Web3.solidityKeccak(
        ["uint256","uint16","uint128","uint16","uint32"],
        example
    )
    return int.from_bytes(hexbytes, 'big')
    