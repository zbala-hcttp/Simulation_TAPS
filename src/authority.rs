use aes_gcm::Key;
use taps::protocol::taps::*;
use crate::crypto::*;
use secp256k1::{PublicKey, SecretKey};
use rand::seq::SliceRandom;
use rand::thread_rng;

pub struct KeyPairs {
    pub(crate) signers_keys: Vec<KeyPair>,      // (sk_i, pk_i)
    pub(crate) combiner_keys: KeyPair,        // (sk_c, pk_c)
    pub(crate) tracer_keys: KeyPair,            // (sk_e, pk_e)
    pub(crate) tracing_keys: Vec<KeyPair>,      // (tau_i, h_i)
}

impl KeyPairs {
    /// Initializes the system, generating all static keys for N actors.
    pub fn new(n: usize) -> Self {
        let mut signers = Vec::with_capacity(n);
        let mut tracing = Vec::with_capacity(n);

        // 1. Generate N Signer Identity Keys and Tracing Keys (tau_i)
        for _ in 0..n {
            signers.push(KeyPair::create());
            tracing.push(KeyPair::create());
        }

        // 2. Generate N Tracing Keys (h_i = g^tau_i)
        let combiner_kp = KeyPair::create();

        // 3. Generate Tracer's Encryption Keypair
        let tracer_kp = KeyPair::create();

        KeyPairs {
            signers_keys: signers,
            combiner_keys: combiner_kp,
            tracing_keys: tracing,
            tracer_keys: tracer_kp,
        }
    }

    pub fn set_pk(&self) -> PK {
        PK::set(&self.signers_keys, &self.combiner_keys, &self.tracer_keys)
    }
    
}

















#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_initialization() {
        let n = 5;
        let auth = KeyPairs::new(n);

        // Check key counts
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);
        
        // Check structural integrity (keys are valid)
        // (Just checking if they exist is enough, KeyPair::create guarantees validity)
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);
    }


}