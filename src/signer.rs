use taps::protocol::taps::{KeyPair};
use secp256k1::{PublicKey, SecretKey, Scalar};
use taps::protocol::taps::{sign, create_commitment}; // Assuming these are exposed

pub struct Signer {
    pub id: usize,
    // Secrets
    key_pr: KeyPair,          // Identity Secret
    // State for Current Session
    current_nonce: Option<KeyPair>, // (r, R)
}

impl Signer {
    pub fn new(id: usize, keys: &KeyPair) -> Self {
        Signer {
            id,
            key_pr: keys.clone(),
            current_nonce: None,
        }
    }

    // Step 1: Generate Commitment (R)
    pub fn commit(&mut self) -> PublicKey {
        let nonce =taps::protocol::taps::create_commitment(); // Function from TAPS lib
        let R = nonce.pk;
        self.current_nonce = Some(nonce);
        R
    }

    // Step 2: Sign (z_i)
    pub fn sign_message(&self, c: &Scalar) -> Scalar {
        let nonce = self.current_nonce.as_ref().expect("No commitment made!");
        
        // Call the TAPS library function
        taps::sign(&nonce.sk, &self.sk, c)
    }
}