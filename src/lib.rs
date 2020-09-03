use rsa::{RSAPublicKey};

use serde::{Serialize, Deserialize};

use aias_core::verifyer;
use fair_blind_signature::{Signature};

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

    pub fn verify_signature(&self, signer_pubkey: &str, judge_pubkey: &str) -> bool {
        verifyer::verify(
            self.fair_blind_signature.clone(),
            self.pubkey.to_string(),
            signer_pubkey.to_string(),
            judge_pubkey.to_string()
        )
    }
}

pub fn parse_fbs(data: &str) -> serde_json::Result<Signature> {
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
    static FAIR_BLIND_SIGNATURE: &str = "test_data/fair_blind_signature.txt";

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
        let signature = read_or_panic(FAIR_BLIND_SIGNATURE);
        parse_fbs(&signature)
            .expect("failed to parse fair-blind-signature");
    }

    #[test]
    fn should_verify_signature() {
        let fair_blind_signature = read_or_panic(FAIR_BLIND_SIGNATURE);
        let signature = "hogehoge".to_string();

        let signer_pubkey = read_or_panic(PUBLIC_KEY);
        let judge_pubkey = read_or_panic(PUBLIC_KEY);

        let pubkey = read_or_panic(PUBLIC_KEY);

        let json_data = JsonData {
            fair_blind_signature,
            pubkey,
            signature,
            signed: SignedData {
                data: "data".to_string(),
                random: 10
            }
        };

        assert!(json_data.verify_signature(&signer_pubkey, &judge_pubkey));
    }

    fn read_or_panic(file: &str) -> String {
        std::fs::read_to_string(file)
            .map_err(|e| format!("failed to read file {}: {}", file, e))
            .unwrap()
    }
}
