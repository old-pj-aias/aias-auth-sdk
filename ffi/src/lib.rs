use std::os::raw::{c_char, c_int};
use aias_auth_sdk::{utils, JsonData};

#[no_mangle]
pub extern fn verify(data: *const c_char, signer_pubkey: *const c_char, judge_pubkey: *const c_char) -> c_int {
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

    let fbs_valid = json_data.verify_fbs(&signer_pubkey_str, &judge_pubkey_str);
    let signature_valid = json_data.verify_signature();

    (fbs_valid || signature_valid) as c_int
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_verify_fbs() {
        let json_data_str = read_or_panic("../sdk/test_data/json_data.json");
        let json_data_c = utils::to_c_str(json_data_str);

        let signer_pubkey_str = read_or_panic("../sdk/test_data/public_key.pem");
        let judge_pubkey_str = read_or_panic("../sdk/test_data/public_key.pem");

        let signer_pubkey_c = utils::to_c_str(signer_pubkey_str);
        let judge_pubkey_c = utils::to_c_str(judge_pubkey_str);

        assert_ne!(verify(json_data_c, signer_pubkey_c, judge_pubkey_c), 0)
    }

    fn read_or_panic(file: &str) -> String {
        std::fs::read_to_string(file)
            .map_err(|e| format!("failed to read file {}: {}", file, e))
            .unwrap()
    }
}