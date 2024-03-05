pub mod symmetric {

    use ccm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
    use ccm::{
        consts::{U10, U13},
        Ccm,
    };

    const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: u8 = 128;
    const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: u8 = 16;
    const CRYPTO_AEAD_MIC_LENGTH_BITS: u8 = 128;
    const CRYPTO_AEAD_MIC_LENGTH_BYTES: u8 = 16;
    const CRYPTO_AEAD_NONCE_LENGTH_BYTES: u8 = 13;
    const Q: u8 = 2;
    const N: u8 = CRYPTO_AEAD_NONCE_LENGTH_BYTES;

    fn generate_and_encrypt() {
        let key = hex::decode("D7828D13B2B0BDC325A76236DF93CC6B").expect("Issue decoding HEX!");
        let nonce = hex::decode("2F1DBD38CE3EDA7C23F04DD650").expect("Issue decoding HEX!");

        type Cipher = Ccm<aes::Aes128, U10, U13>;
        let key = GenericArray::from_slice(&key);
        let nonce = GenericArray::from_slice(&nonce);
        let c = Cipher::new(key);

        let mut buf1 = [1; core::u16::MAX as usize];
        let res = c.encrypt_in_place_detached(nonce, &[], &mut buf1);
        assert!(res.is_ok());

        let mut buf2 = [1; core::u16::MAX as usize + 1];
        let res = c.encrypt_in_place_detached(nonce, &[], &mut buf2);
        assert!(res.is_err());
    }
}
