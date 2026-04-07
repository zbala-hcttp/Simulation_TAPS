use crate::authority::SignerPackage;
use crate::combiner;
use crate::crypto::*;
use bincode;
use secp256k1::{Error, PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use taps::protocol::taps::*;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentPackage {
    pub commitment: Commitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaPackage {
    pub z: Sign,
}

pub struct Signer {
    pub id: usize,

    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    pub taps_kp: Option<KeyPair>,

    current_commitment: Option<Commit>,
}

impl Signer {
    pub fn new(id: usize) -> Self {
        Signer {
            id,
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            taps_kp: None,
            current_commitment: None,
        }
    }

    pub fn set_taps_key(&mut self, kp: KeyPair) {
        self.taps_kp = Some(kp);
    }

    fn secure_package<T: Serialize>(&self, package: &T, receiver_pk: &PublicKey) -> SecurePackage {
        let plain_bytes = bincode::serialize(package).expect("Serialization failed");
        let (ciphertext, nonce) = self.transport_kp.encrypt_to(receiver_pk, &plain_bytes);
        let timestamp = current_timestamp();
        let signature = self.identity_kp.sign_data(&ciphertext, &nonce, timestamp);

        SecurePackage {
            ciphertext,
            nonce,
            timestamp,
            signature,
        }
    }

    pub fn load_from_authority(
        &mut self,
        secure_pkg: &SecurePackage,
        authority_pk: &PublicKey,
        identity_pk: &PublicKey,
    ) -> Result<(), Error> {
        let is_valid = IdentityKeyPair::verify_data(identity_pk, secure_pkg);

        if !is_valid {
            eprintln!(
                "[Combiner] Error: SecurePackage verification failed (Invalid Signature or Expired)."
            );
            return Err(Error::InvalidSignature);
        }

        let plaintext_bytes = self.transport_kp.decrypt_from(
            authority_pk,
            &secure_pkg.ciphertext,
            &secure_pkg.nonce,
        );

        let config: SignerPackage =
            bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)?;

        println!("[Signer] Bootstrap successful. Loading configuration...");

        self.taps_kp = Some(config.my_kp);

        println!("[Signer] Configuration Loaded:");

        Ok(())
    }

    pub fn set_commitment(&mut self, combiner_pk: &PublicKey) -> SecurePackage {
        let commit = Commit::commit();
        let comm = Commitment::set(&commit);

        self.current_commitment = Some(commit);

        let pkg = CommitmentPackage { commitment: comm };

        self.secure_package(&pkg, combiner_pk)
    }

    pub fn set_sigma(&mut self, signed_pkg: &BroadcastPackage, combiner_pk: &PublicKey, identity_pk: &PublicKey) -> Result<SecurePackage, Error> {

        let is_valid = IdentityKeyPair::verify_broadcast_data(&identity_pk, &signed_pkg);


        if !is_valid {
            eprintln!(
                "[Combiner] Error: SecurePackage verification failed (Invalid Signature or Expired)."
            );
            return Err(Error::InvalidSignature);
        }

        let payload: combiner::SignerPackage = bincode::deserialize(&signed_pkg.text).expect("Serialization failed");

        let comm = self.current_commitment.as_ref()
            .expect("Protocol Error: No commitment found for this round!");

        let my_key = self.taps_kp.as_ref()
            .expect("Protocol Error: TAPS keys not initialized");

        let signature = Sign::sign(&comm, &my_key, &payload.c);

        let pkg = SigmaPackage { z: signature };

        Ok(self.secure_package(&pkg, combiner_pk))
    }
}
