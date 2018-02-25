extern crate ring;
extern crate serde;
extern crate hex;

use ring::{digest, hmac};
use std::time::{SystemTime, UNIX_EPOCH};

/// This struct stores the data provided by the user in format compatible with the telegram_login_verifier::LoginVerifier
pub struct RequestData {
    pub auth_date: u64,
    pub first_name: String,
    pub hash: String,
    pub id: i32,
    pub photo_url: String,
    pub username: String
}
/// This struct allows you to verify the provided user data with your bot token
pub struct LoginVerifier {
    key: hmac::SigningKey
}

impl LoginVerifier {
    /**
    Returns a new LoginVerifier using the provided bot token as key

    # Arguments
    * `token` - A &str  containing the bot token provided by Telegram's Botfather
    # Examples
    ```
    use telegram_login_verifier::{LoginVerifier, RequestData}

    let verifier = LoginVerifier::new("123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    ```

    */
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
    /**
        Verifies if the provided login data is valid

        # Arguments
        * `data` - A reference to a telegram_login_verifier::RequestData struct.
        * `check_time_stamp` - If true the function will check if the auth_date is older than a day, in that case the function will return an Err("The login request expired")

        # Remarks
        The funcion will return Ok(true) if the verification success, if it fails will provide an Err with an error message.

        # Examples
        ```
        use telegram_login_verifier::{LoginVerifier, RequestData}

        let verifier = LoginVerifier::new("123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        let data = telegram_login_verifier::RequestData {
            auth_date: 1234567890,
            first_name: "First name".to_string(),
            hash: "d029f87e3d80f8fd9b1be67c7426b4cc1ff47b4a9d0a8461c826a59d8c5eb6cd".to_string(),
            id: 1234567,
            photo_url: "https://t.me/i/userpic/320/username.jpg".to_string(),
            username: "username".to_string()
        };

        let result = verifier.verify(&data, true);

        match result {
            Ok(_) => println!("Ok!"),
            Err(e) => println!("{}", e)
        }
        ```
    */
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
