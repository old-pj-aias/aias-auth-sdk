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
    RSAPublicKey::from_pkcs8(data.as_bytes())
}


#[cfg(test)]
mod tests {
    use super::*;

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

        let parsed = parse_json(&data)
            .expect("failed to parse");
        
        assert_eq!(json_data, parsed);
    }
}
