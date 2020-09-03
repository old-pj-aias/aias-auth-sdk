use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct JsonData {
    pub fair_blind_signature: String,
    pub pubkey: String,
    pub signature: String,
    pub signed: SignedData,
}

#[derive(Serialize, Deserialize)]
pub struct SignedData {
    pub data: String,
    pub random: u32,
}

pub fn parse_json(data: &str) -> serde_json::Result<JsonData> {
    serde_json::from_str(data)
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
