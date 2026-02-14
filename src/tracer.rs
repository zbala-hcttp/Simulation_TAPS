use taps::protocol::taps::*;
use crate::{authority::TracerPackage, crypto::*, combiner};
use secp256k1::{Error, PublicKey, Scalar, schnorr};
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
    pub v0: Option<PublicKey>,
    pub v_vec: Option<Vec<PublicKey>>,
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
            v0: None,
            v_vec: None,
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

    pub fn verify_proof(&self, proof: &Proofs) -> Result<bool, String> {
        let sigma = self.sigma.as_ref().unwrap();
        let t = self.T.as_ref().unwrap();
        let v0 = self.v0.as_ref().unwrap();
        let v = self.v_vec.as_ref().unwrap();
        let pk = self.pk.as_ref().unwrap();
        let tracing_kps = self.tracing_kps.as_ref().unwrap();
        let kp_t = self.taps_kp.as_ref().unwrap();
        let c = self.c.as_ref().unwrap();
        let alpha = self.alpha.as_ref().unwrap();
        Proofs::verify(&proof, &sigma, &t, &v0, &v, &pk, &tracing_kps, &kp_t, &c, &alpha)
            .map_err(|e| format!("Proof verification failed: {:?}", e))
    }

    pub fn verify_sign(&self) {
        let sigma = self.sigma.as_ref().unwrap();
        let kp = self.taps_kp.as_ref().unwrap();
        let ct = sigma.ct.clone();
        let g_z_prime = ElGamalCiphertext::decrypt(&ct, &kp);

        let R = sigma.R.clone();
        let c = self.c.as_ref().unwrap();
        let v0 = self.v0.as_ref().unwrap();
        let v = self.v_vec.as_ref().unwrap();
        let tr_keys = self.tracing_kps.as_ref().unwrap();
        let b_i = decrypt_bits(&v0, &v, &tr_keys);
        let pk = self.pk.as_ref().unwrap();
        //let g_z : schnorr_signature(R, quo, c);      
    }

}
