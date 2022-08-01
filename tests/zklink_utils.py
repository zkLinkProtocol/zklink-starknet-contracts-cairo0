from eth_abi.packed import encode_abi_packed

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


def splitPubData(data):
    return [int.from_bytes(x, 'big') for x in [data[i:i+BYTES_PER_FELT] for i in range(0, len(data), BYTES_PER_FELT)]]

def getDepositPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","uint8","uint16","uint16","uint128","address"],
        [OP_DEPOSIT] + example)
    return splitPubData(data)

def getWithdrawPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","uint16","uint128","address","uint32","uint16"],
        [OP_WITHDRAW] + example)
    return splitPubData(data)

def getFullExitPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","uint8","address","uint16","uint16","uint128"],
        [OP_FULL_EXIT] + example)
    return splitPubData(data)

def getForcedExitPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint16","uint128","address"],
        [OP_FORCE_EXIT] + example)
    return splitPubData(data)

def getChangePubkeyPubdata(example):
    data = encode_abi_packed(
        ["uint8","uint8","uint32","address","address","uint32"],
        [OP_CHANGE_PUBKEY] + example)
    return splitPubData(data)