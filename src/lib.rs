extern crate ring;
extern crate serde;
extern crate hex;

use ring::{digest, hmac};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RequestData {
    pub auth_date: u64,
    pub first_name: String,
    pub hash: String,
    pub id: i32,
    pub photo_url: String,
    pub username: String
}

pub struct LoginVerifier {
    key: hmac::SigningKey
}

impl LoginVerifier {
    pub fn new(token: &str) -> LoginVerifier {
        let key_value = digest::digest(&digest::SHA256, token.as_bytes());


        LoginVerifier {
            key: hmac::SigningKey::new(&digest::SHA256, key_value.as_ref())
        }
    }
    fn generate_data_check_string(data: &RequestData) -> String {
        format!("auth_date={}\nfirst_name={}\nid={}\nphoto_url={}\nusername={}",
        data.auth_date,
        data.first_name,
        data.id,
        data.photo_url,
        data.username
        )
    }

    pub fn verify(&self, data: &RequestData, check_time_stamp: bool) -> Result<bool, &'static str> {
        if check_time_stamp {
            let system_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("UNIX_EPOCH can not be earlier than systemtime");
            if (system_time.as_secs() - data.auth_date) > 86400 {
                return Err("The login request expired")
            }
        }

        let data_check_string = LoginVerifier::generate_data_check_string(&data);
        let signature = hmac::sign(&self.key, data_check_string.as_bytes());
        let signature_string = hex::encode(signature.as_ref());

        if data.hash == signature_string {
            return Ok(true);
        } else {
            return Err("Invalid login data");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LoginVerifier;

    #[test]
    fn it_works() {
        true
    }
}
