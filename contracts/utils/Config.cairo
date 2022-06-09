# zkSync configuration constants



# Exodus mode status, 0 is off, 1 is on
const EXODUS_MODE_ON = 1

# Max deposit of ERC20 token that is possible to deposit
const MAX_DEPOSIT_AMOUNT = 2 ** 104 - 1

# Max sub account id that could be bound to account id
const MAX_SUB_ACCOUNT_ID = 2 ** 3 - 1

# Expected average period of block creation
# TODO: It should be a storage_var instead of constant
const BLOCK_PERIOD = 15 # 15 seconds

# Expiration delta for priority request to be satisfied (in seconds)
# NOTE: Priority expiration should be > (EXPECT_VERIFICATION_IN * BLOCK_PERIOD)
# otherwise incorrect block with priority op could not be reverted.
const PRIORITY_EXPIRATION_PERIOD = 1209600  # 14 days

# Expiration delta for priority request to be satisfied (in ETH blocks)
# TODO: It should be a storage_var instead of constant
const PRIORITY_EXPIRATION = 80640   # PRIORITY_EXPIRATION_PERIOD / BLOCK_PERIOD

# Maximum number of priority request that wait to be proceed
# to prevent an attacker submit a large number of priority requests
# that exceeding the processing power of the l2 server
# and force the contract to enter exodus mode
# this attack may occur on some blockchains with high tps but low gas prices
# TODO: It should be a storage_var instead of constant
const MAX_PRIORITY_REQUESTS = 4096

# Address represent eth when deposit or withdraw
# TODO: It should be a storage_var instead of constant
const ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE