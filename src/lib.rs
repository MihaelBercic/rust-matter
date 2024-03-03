mod crypto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_hash_test_sha_256() {
        let sample = b"mihael";
        let hash = crypto::hash_message(sample);
        let hex = hash.map(|x| format!("{:02x}", x)).join("");
        assert_eq!(hex, "a1ec7aff7a3ce85b3784176861b4995fe092eea0f417443d4ba77ae96a9f812e");
    }

    #[test]
    fn crypto_hmac_test() {
        let sample_key = b"my secret and secure key";
        let sample_input_message = b"input message";
        let hmac = crypto::hmac(sample_key, sample_input_message);
        let hex = hmac.map(|x| format!("{:02x}", x)).join("");
        assert_eq!(hex, "97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9")
    }

    #[test]
    fn crypto_hmac_verify() {
        let hmac = crypto::verify_hmac(b"my secret and secure key", b"input message", b"97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9");
        hmac.expect("Verification was not successful.")
    }
}
