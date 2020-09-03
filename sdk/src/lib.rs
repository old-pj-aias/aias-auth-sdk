pub mod utils;


use rsa::{PublicKey, RSAPublicKey, PaddingScheme, hash::Hash::SHA2_256};

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

    pub fn verify_fbs(&self, signer_pubkey: &str, judge_pubkey: &str) -> bool {
        verifyer::verify(
            self.fair_blind_signature.clone(),
            self.pubkey.to_string(),
            signer_pubkey.to_string(),
            judge_pubkey.to_string()
        )
    }

    pub fn verify_signature(&self) -> bool {
        let pubkey = match self.public_key() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("failed to parse pubkey: {}", e);
                return false;
            }
        };

        let hashed = self.hashed_data();

        let signature = match base64::decode(&self.signature) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to decode base64: {}", e);
                return false;
            }
        };

        pubkey.verify(
            PaddingScheme::PKCS1v15Sign{hash: Some(SHA2_256)},
            &hashed,
            &signature
        )
        .map(|_| true)
        .unwrap_or(false)
    }

    pub fn hashed_data(&self) -> Vec<u8> {
        let raw = format!("{}.{}",
            base64::encode(&self.signed.data),
            self.signed.random.to_string()
        );

        hash_sha256(&raw)
    }

    pub fn public_key(&self) -> Result<RSAPublicKey, rsa::errors::Error> {
        parse_pubkey(&self.pubkey)
    }
}

pub fn parse_fbs(data: &str) -> serde_json::Result<Signature> {
    serde_json::from_str(data)
}

pub fn parse_pubkey(data: &str) -> Result<RSAPublicKey, rsa::errors::Error> {
    let judge_pubkey = pem::parse(data).expect("failed to parse judge public keypem");
    RSAPublicKey::from_pkcs8(&judge_pubkey.contents)
}

pub fn hash_sha256(m: &str) -> Vec<u8> {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(m.as_bytes());
    hasher.finalize().to_vec()
}


#[cfg(test)]
mod tests {
    use super::*;

    static JSON_DATA: &str = "test_data/json_data.json";
    static PUBLIC_KEY: &str = "test_data/public_key.pem";
    static SECRET_KEY: &str = "test_data/secret_key.pem";
    static FAIR_BLIND_SIGNATURE: &str = "test_data/fair_blind_signature.txt";

    #[test]
    fn all() {
        let json_data_str = read_or_panic(JSON_DATA);

        let json_data = JsonData::from_str(&json_data_str)
            .expect("failed to parse");

        let signer_pubkey = read_or_panic(PUBLIC_KEY);
        let judge_pubkey = read_or_panic(PUBLIC_KEY);

        //assert_eq!(json_data.fair_blind_signature, read_or_panic(FAIR_BLIND_SIGNATURE));
        assert!(json_data.verify_fbs(&signer_pubkey, &judge_pubkey));

        assert!(json_data.verify_signature());
    }

    #[test]
    fn should_parse_json() {
        let json_data = read_or_panic(JSON_DATA);

        JsonData::from_str(&json_data)
            .expect("failed to parse");
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
    fn should_verify_fbs() {
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

        assert!(json_data.verify_fbs(&signer_pubkey, &judge_pubkey));
    }

    #[test]
    fn should_verify_signature() {
        let fair_blind_signature = read_or_panic(FAIR_BLIND_SIGNATURE);

        let pubkey = read_or_panic(PUBLIC_KEY);

        let signature = vec![37,125,221,141,20,105,26,106,137,219,14,107,218,225,223,144,228,135,127,46,28,89,112,191,187,9,148,105,250,135,241,80,231,83,147,59,94,221,74,79,187,227,7,181,162,102,14,219,251,110,110,199,220,55,36,163,64,246,74,169,228,111,65,95,223,37,209,92,105,87,21,57,201,197,192,61,141,106,19,178,227,233,232,146,42,70,29,203,127,152,147,130,144,71,21,71,109,176,192,19,25,178,150,238,170,117,38,50,226,32,226,174,167,193,224,3,186,155,252,88,3,126,109,91,210,39,206,72,253,88,103,209,230,38,198,92,176,179,153,186,88,233,220,238,227,203,7,198,205,114,98,135,91,240,254,145,8,27,35,221,180,126,120,72,152,190,15,146,24,208,144,178,214,213,184,69,4,116,59,28,181,12,186,105,3,130,98,195,137,7,240,197,154,109,160,141,183,177,145,210,50,90,103,19,97,41,81,195,188,7,57,126,196,251,84,150,241,226,141,224,36,143,29,174,163,25,116,34,231,104,205,193,147,107,174,64,48,92,163,49,94,195,221,196,49,225,189,137,26,121,158,124,34,150,174,193];
        let signature = base64::encode(&signature);

        let json_data = JsonData {
            fair_blind_signature,
            pubkey,
            signature,
            signed: SignedData {
                data: "data".to_string(),
                random: 10
            }
        };

        assert!(json_data.verify_signature());
    }

    fn read_or_panic(file: &str) -> String {
        std::fs::read_to_string(file)
            .map_err(|e| format!("failed to read file {}: {}", file, e))
            .unwrap()
    }

    #[allow(dead_code)]
    fn generate_signature(json_data: &JsonData) -> String {
        let secret_key = read_or_panic(SECRET_KEY);

        let privkey = pem::parse(&secret_key).unwrap();
        let privkey = rsa::RSAPrivateKey::from_pkcs1(&privkey.contents).unwrap();

        let digest = json_data.hashed_data();

        let signature = privkey
            .sign(PaddingScheme::new_pkcs1v15_sign(Some(SHA2_256)), &digest)
            .unwrap();

        println!("signature\n{:?}", serde_json::to_string(&signature).unwrap());
        String::new()
    }
}
