# zkSync configuration constants


# Empty string keccak low part
const EMPTY_STRING_KECCAK_LOW = 0xe500b653ca82273b7bfad8045d85a470

# Empty string keccak high part
const EMPTY_STRING_KECCAK_HIGH = 0xc5d2460186f7233c927e7db2dcc703c0

# Exodus mode status, 0 is off, 1 is on
const EXODUS_MODE_ON = 1

# Max deposit of ERC20 token that is possible to deposit
const MAX_DEPOSIT_AMOUNT = 2 ** 104 - 1

# Max amount of tokens registered in the network
const MAX_AMOUNT_OF_REGISTERED_TOKENS = 4096

# Max account id that could be registered in the network
const MAX_ACCOUNT_ID = 2 ** 24 - 1

# Max sub account id that could be bound to account id
const MAX_SUB_ACCOUNT_ID = 2 ** 3 - 1

# Expected average period of block creation
# TODO: It should be a storage_var instead of constant
const BLOCK_PERIOD = 15 # 15 seconds

# Bytes in one chunk
const CHUNK_BYTES = 14

# Operation chunks
const OPERATION_CHUNK_SIZE = 4
const DEPOSIT_BYTES = OPERATION_CHUNK_SIZE * CHUNK_BYTES
const FULL_EXIT_BYTES = OPERATION_CHUNK_SIZE * CHUNK_BYTES
const WITHDRAW_BYTES = OPERATION_CHUNK_SIZE * CHUNK_BYTES
const FORCED_EXIT_BYTES = OPERATION_CHUNK_SIZE * CHUNK_BYTES
const CHANGE_PUBKEY_BYTES = OPERATION_CHUNK_SIZE * CHUNK_BYTES

# Expiration delta for priority request to be satisfied (in seconds)
# NOTE: Priority expiration should be > (EXPECT_VERIFICATION_IN * BLOCK_PERIOD)
# otherwise incorrect block with priority op could not be reverted.
const PRIORITY_EXPIRATION_PERIOD = 1209600  # 14 days

# Expiration delta for priority request to be satisfied (in ETH blocks)
# TODO: It should be a storage_var instead of constant
const PRIORITY_EXPIRATION = 80640   # PRIORITY_EXPIRATION_PERIOD / BLOCK_PERIOD

# Reserved time for users to send full exit priority operation in case of an upgrade (in seconds)
const MASS_FULL_EXIT_PERIOD = 432000 # 5 days

# Reserved time for users to withdraw funds from full exit priority operation in case of an upgrade (in seconds)
const TIME_TO_WITHDRAW_FUNDS_FROM_FULL_EXIT = 172800 # 2 days

# Notice period before activation preparation status of upgrade mode (in seconds)
# MASS_FULL_EXIT_PERIOD + PRIORITY_EXPIRATION_PERIOD + TIME_TO_WITHDRAW_FUNDS_FROM_FULL_EXIT = 21 days
const UPGRADE_NOTICE_PERIOD = 1814400 # 21 days

# Timestamp - seconds since unix epoch
const COMMIT_TIMESTAMP_NOT_OLDER = 86400 # 24h

# Maximum available error between real commit block timestamp and analog used in the verifier (in seconds)
# Must be used cause miner's `block.timestamp` value can differ on some small value (as we know - 15 seconds)
const COMMIT_TIMESTAMP_APPROXIMATION_DELTA = 900 # 15min

# Bit mask to apply for verifier public input before verifying.
# TODO: $$(~uint256(0) >> 3)
const INPUT_MASK_LOW = 1
const INPUT_MASK_HIGH = 1

# Auth fact reset timelock
const AUTH_FACT_RESET_TIMELOCK = 86400 # 1 days

# Maximum number of priority request that wait to be proceed
# to prevent an attacker submit a large number of priority requests
# that exceeding the processing power of the l2 server
# and force the contract to enter exodus mode
# this attack may occur on some blockchains with high tps but low gas prices
# TODO: It should be a storage_var instead of constant
const MAX_PRIORITY_REQUESTS = 4096

# Enable commit a compressed block
const ENABLE_COMMIT_COMPRESSED_BLOCK = 1

# Min chain id defined by ZkLink
const MIN_CHAIN_ID = 1

# Max chain id defined by ZkLink
const MAX_CHAIN_ID = 4

# All chain index, for example [1, 2, 3, 4] => 1 << 0 | 1 << 1 | 1 << 2 | 1 << 3 = 15
const ALL_CHAINS = 15

# Address represent eth when deposit or withdraw
# TODO: It should be a storage_var instead of constant
# Because of ETH address is different between testnet and mainnet
const ETH_ADDRESS = 0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7

# When set fee = 100, it means 1%
const MAX_ACCEPT_FEE_RATE = 10000

# see EIP-712
# keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
const CHANGE_PUBKEY_DOMAIN_SEPARATOR_LOW = 0x239f7b179b0ffacaa9a75d522b39400f
const CHANGE_PUBKEY_DOMAIN_SEPARATOR_HIGH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79

# keccak256("ZkLink");
const CHANGE_PUBKEY_HASHED_NAME_LOW = 0x3e725ebc4ed8a2d9cea6e29b98608795
const CHANGE_PUBKEY_HASHED_NAME_HIGH = 0x98dcb1a1c610092f8ddbd78467f948b9

#  keccak256("1");
const CHANGE_PUBKEY_HASHED_VERSION_LOW = 0xf5a951637e0307cdcb4c672f298b8bc6
const CHANGE_PUBKEY_HASHED_VERSION_HIGH = 0xc89efdaa54c0f20c7adf612882df0950

# keccak256("ChangePubKey(bytes20 pubKeyHash,uint32 nonce,uint32 accountId)");
const CHANGE_PUBKEY_TYPE_HASH_LOW = 0x0621f39392101b34fba2ecd141432580b
const CHANGE_PUBKEY_TYPE_HASH_HIGH = 0x8012078cc90c4c82e493f1a538159fd8