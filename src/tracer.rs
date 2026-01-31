use taps::{SecretKey, PublicKey, Scalar};

pub struct Tracer {
    encryption_sk: SecretKey,       // sk_e
    tracing_secrets: Vec<SecretKey>, // tau_i list
}

impl Tracer {
    pub fn new(sk_e: SecretKey, taus: Vec<SecretKey>) -> Self {
        Tracer {
            encryption_sk: sk_e,
            tracing_secrets: taus,
        }
    }

    pub fn trace_session(
        &self, 
        c0: &PublicKey, 
        v_list: &[PublicKey], // Encrypted bits
        decrypted_z_point: &PublicKey, // Recovered g^z
        R_agg: &PublicKey,
        signer_pks: &[PublicKey],
        challenge: &Scalar
    ) -> bool {
        // 1. Decrypt Bits
        let bits = taps::decrypt_bits(c0, v_list, &self.tracing_secrets);
        println!("Tracer found bits: {:?}", bits);

        // 2. Verify Quorum Trace
        taps::verify_quorum_trace(
            decrypted_z_point,
            &bits,
            R_agg,
            signer_pks,
            challenge
        )
    }
}