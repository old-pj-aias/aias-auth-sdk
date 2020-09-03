use std::os::raw::{c_char, c_int};
use aias_auth_sdk::{utils, JsonData};

pub extern fn verify_fbs(data: *const c_char, signer_pubkey: *const c_char, judge_pubkey: *const c_char) -> c_int {
    let data_str = utils::from_c_str(data);
    let json_data = match JsonData::from_str(&data_str) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to parse json: {}", e);
            return 0;
        }
    };

    let signer_pubkey_str = utils::from_c_str(signer_pubkey);
    let judge_pubkey_str = utils::from_c_str(judge_pubkey);

    if json_data.verify_fbs(&signer_pubkey_str, &judge_pubkey_str) {
        1
    } else {
        0
    }
}