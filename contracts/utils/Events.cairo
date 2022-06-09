%lang starknet

from starkware.cairo.common.uint256 import Uint256

@event
func new_priority_request(
    sender : felt,
    serial_id : felt,
    op_type : felt,
    pub_data_len : felt,
    pub_data : felt*,
    expiration_block : felt
):
end