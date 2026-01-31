use taps::protocol::taps::KeyPair;
use secp256k1::{PublicKey, SecretKey};
use rand::seq::SliceRandom;
use rand::thread_rng;

pub struct TrustedAuthority {
    pub(crate) n: usize,
    pub(crate) signers_keys: Vec<KeyPair>,      // (sk_i, pk_i)
    pub(crate) combiner_keys: KeyPair,        // (sk_c, pk_c)
    pub(crate) tracer_keys: KeyPair,            // (sk_e, pk_e)
    pub(crate) tracing_keys: Vec<KeyPair>,      // (tau_i, h_i)
}

impl TrustedAuthority {
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

        TrustedAuthority {
            n,
            signers_keys: signers,
            combiner_keys: combiner_kp,
            tracing_keys: tracing,
            tracer_keys: tracer_kp,
        }
    }

    /// Starts a signing session by choosing 't' participants.
    /// Returns the attendance bits (b_i) to be sent ONLY to the Combiner.
    pub fn select_session_quorum(&self, t: usize) -> Vec<u8> {
        if t > self.n {
            panic!("Threshold t cannot be greater than total signers n");
        }

        let mut rng = thread_rng();
        let mut indices: Vec<usize> = (0..self.n).collect();
        
        // Randomly shuffle indices to pick 't' winners
        indices.shuffle(&mut rng);
        
        // Create the bit vector (initialized to 0)
        let mut bits = vec![0u8; self.n];
        
        // Set the first 't' shuffled indices to 1
        for &idx in indices.iter().take(t) {
            bits[idx] = 1;
        }

        println!("[Authority] Selected quorum indices: {:?}", &indices[0..t]);
        // In a real logger, you might hide this, but for simulation it's useful:
        // println!("[Authority] Generated private bits: {:?}", bits);

        bits
    }
}

















#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_initialization() {
        let n = 5;
        let auth = TrustedAuthority::new(n);

        // Check key counts
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);
        
        // Check structural integrity (keys are valid)
        // (Just checking if they exist is enough, KeyPair::create guarantees validity)
        assert_eq!(auth.n, n);
    }

    #[test]
    fn test_quorum_selection_counts() {
        let n = 10;
        let t = 4;
        let auth = TrustedAuthority::new(n);

        let bits = auth.select_session_quorum(t);

        // 1. Check length
        assert_eq!(bits.len(), n, "Bit vector length must match n");

        // 2. Check total count of 1s
        let count_ones = bits.iter().filter(|&&b| b == 1).count();
        assert_eq!(count_ones, t, "Bit vector must have exactly t ones");
    }

    #[test]
    #[should_panic(expected = "Threshold t cannot be greater than total signers n")]
    fn test_invalid_threshold() {
        let n = 3;
        let auth = TrustedAuthority::new(n);
        auth.select_session_quorum(4); // Should panic
    }
}