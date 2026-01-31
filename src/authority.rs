use taps::KeyPair;
use secp256k1::{PublicKey, SecretKey, Secp256k1};

pub struct TrustedAuthority {
    pub n: usize,
    pub signers_keys: Vec<KeyPair>,      // (sk_i, pk_i)
    pub tracing_keys: Vec<KeyPair>,      // (tau_i, h_i)
    pub tracer_pk: PublicKey,            // pk_e (Encryption key for Tracer)
    pub tracer_sk: SecretKey,            // sk_e (Decryption key for Tracer)
}

impl TrustedAuthority {
    pub fn new(n: usize) -> Self {
        let mut signers = Vec::new();
        let mut tracing = Vec::new();

        // 1. Generate N Signer Identity Keys
        for _ in 0..n {
            signers.push(KeyPair::create());
        }

        // 2. Generate N Tracing Keys (h_i = g^tau_i)
        for _ in 0..n {
            tracing.push(KeyPair::create());
        }

        // 3. Generate Tracer's Encryption Keypair
        let tracer_kp = KeyPair::create();

        TrustedAuthority {
            n,
            signers_keys: signers,
            tracing_keys: tracing,
            tracer_pk: tracer_kp.pk,
            tracer_sk: tracer_kp.sk,
        }
    }
}