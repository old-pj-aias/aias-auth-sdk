use rsa::{RSAPublicKey};

use serde::{Serialize, Deserialize};

use fair_blind_signature::{BlindSignature};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct JsonData {
    pub fair_blind_signature: String,
    pub pubkey: String,
    pub signature: String,
    pub signed: SignedData,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignedData {
    pub data: String,
    pub random: u32,
}

impl JsonData {
    pub fn from_str(data: &str) -> serde_json::Result<JsonData> {
        serde_json::from_str(data)
    }
}

pub fn parse_fbs(data: &str) -> serde_json::Result<BlindSignature> {
    serde_json::from_str(data)
}

pub fn parse_pubkey(data: &str) -> Result<RSAPublicKey, rsa::errors::Error> {
    let judge_pubkey = pem::parse(data).expect("failed to parse judge public keypem");
    RSAPublicKey::from_pkcs8(&judge_pubkey.contents)
}


#[cfg(test)]
mod tests {
    use super::*;

    static PUBLIC_KEY: &str = "test_data/public_key.pem";
    static SIGNATURE: &str = "test_data/signature.txt";

    #[test]
    fn should_parse_json() {
        let json_data = JsonData {
            fair_blind_signature: "fair blind signature".to_string(),
            pubkey: "public key".to_string(),
            signature: "signature".to_string(),
            signed: SignedData {
                data: "data".to_string(),
                random: 10
            }
        };

        let data = serde_json::to_string(&json_data)
            .expect("failed to convert to string");

        let parsed = JsonData::from_str(&data)
            .expect("failed to parse");
        
        assert_eq!(json_data, parsed);
    }

    #[test]
    fn should_parse_pubkey() {
        let public_key = read_or_panic(PUBLIC_KEY);
        parse_pubkey(&public_key)
            .expect("failed to parse pubkey pkcs8");
    }

    #[test]
    fn should_parse_fbs() {
        let signature = read_or_panic(&SIGNATURE);
        parse_fbs(&signature)
            .expect("failed to parse fair-blind-signature");
    }

    fn read_or_panic(file: &str) -> String {
        std::fs::read_to_string(file)
            .map_err(|e| format!("failed to read file {}: {}", file, e))
            .unwrap()
    }
}
