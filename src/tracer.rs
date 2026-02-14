use taps::protocol::taps::*;
use crate::{authority::TracerPackage, crypto::*, combiner};
use secp256k1::{PublicKey, Scalar, Error};
use serde::{Serialize, Deserialize};
use bincode;

pub struct Tracer {
    // 1. Networking Keys
    pub identity_kp: IdentityKeyPair,   // Long-term Identity (Signing)
    pub transport_kp: TransportKeyPair, // Ephemeral Transport (Encryption)

    // 2. TAPS Protocol Keys
    pub taps_kp: Option<KeyPair>,
    pub tracing_kps: Option<Vec<KeyPair>>,

    // 3. TAPS Protocol State
    pub T: Option<ElGamalCiphertext>,
    pub pk: Option<PK>,
    pub n: Option<usize>,
    pub proof: Option<Proofs>,
    pub sigma: Option<Sigma>,
    pub c: Option<Scalar>,
    pub alpha: Option<Scalar>,
}

impl Tracer {
    pub fn new() -> Self {
        Tracer {
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            taps_kp: None,
            tracing_kps: None,
            pk: None,
            n: None,
            T: None,
            proof: None,
            sigma: None,
            c: None,
            alpha: None,
        }
    }

    pub fn load_from_authority(
        &mut self,
        secure_pkg: &SecurePackage,
        authority_pk: &PublicKey,
        identity_pk: &PublicKey
    ) -> Result<(), Error> {

        // 1. VERIFY Signature & Timestamp
        // Use the wrapper method in IdentityKeyPair
        let is_valid = IdentityKeyPair::verify_data(identity_pk, secure_pkg);

        if !is_valid {
            eprintln!("[Combiner] Error: SecurePackage verification failed (Invalid Signature or Expired).");
            return Err(Error::InvalidSignature);
        }

        // 2. DECRYPT Payload
        // Use the wrapper method in TransportKeyPair
        // This handles deriving the AES key and decrypting with the nonce
        let plaintext_bytes = self.transport_kp.decrypt_from(
            authority_pk,          // Sender PK (Authority)
            &secure_pkg.ciphertext,
            &secure_pkg.nonce
        );

        let config: TracerPackage = bincode::deserialize(&plaintext_bytes)
            .map_err(|_| Error::InvalidMessage)?;

        self.taps_kp = Some(config.kp_t);
        self.pk = Some(config.pk);
        self.n = Some(config.tracing_keys.len());
        self.tracing_kps = Some(config.tracing_keys);

        Ok(())
    }

    pub fn load_from_combiner(
        &mut self,
        broadcast_pkg: &BroadcastPackage,
        identity_pk: &PublicKey
    ) -> Result<(), Error> {

        // 1. VERIFY Signature & Timestamp
        // Use the wrapper method in IdentityKeyPair
        let is_valid = IdentityKeyPair::verify_broadcast_data(identity_pk, broadcast_pkg);

        if !is_valid {
            eprintln!("[Tracer] Error: BroadcastPackage verification failed (Invalid Signature or Expired).");
            return Err(Error::InvalidSignature);
        }

        let config: combiner::TracerPackage = bincode::deserialize(&broadcast_pkg.text)
            .map_err(|_| Error::InvalidMessage)?;

        self.T = Some(config.T);
        self.proof = Some(config.proof);
        self.sigma = Some(config.sigma);
        self.c = Some(config.c);
        self.alpha = Some(config.alpha);

        Ok(())
    }

    pub fn verify_sigma(&self, sigma: &Sigma, m: &[u8]) -> Result<bool, String> {
        let pk = self.pk.as_ref().unwrap();
        Sigma::verify(pk, m, sigma)
            .map_err(|e| format!("Sigma verification failed: {:?}", e))
    }

}
