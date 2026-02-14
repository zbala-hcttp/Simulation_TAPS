use taps::protocol::taps::*;
use crate::crypto::*;
use secp256k1::{PublicKey, Scalar};
use serde::{Serialize, Deserialize};
use bincode;

// --- Payload Structs (What we send over the wire) ---

/// Step 1: The Public Nonce (R_i) sent to the Combiner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentPackage {
    pub commitment: Commitment, // The public point of the nonce
}

/// Step 2: The Partial Signature (z_i) sent to the Combiner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaPackage {
    pub z: Sign,
}

// --- Signer Actor ---

pub struct Signer {
    pub id: usize,

    // 1. Networking Keys
    pub identity_kp: IdentityKeyPair,   // Long-term Identity (Signing)
    pub transport_kp: TransportKeyPair, // Ephemeral Transport (Encryption)

    // 2. TAPS Protocol Keys
    pub taps_kp: Option<KeyPair>,

    // 3. Round State
    // We store the full Commitment object (which holds the private nonce)
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

    // --- Secure Package Helper ---
    // (Reused from previous step)
    fn secure_package<T: Serialize>(
        &self,
        package: &T,
        receiver_pk: &PublicKey
    ) -> SecurePackage {
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

    // --- Protocol Step 1: Send Commitment ---
    pub fn set_commitment(&mut self, combiner_pk: &PublicKey) -> SecurePackage {
        // 1. Create Commitment using TAPS logic
        let commit = Commit::commit();
        let comm = Commitment::set(&commit);

        // 3. Store the FULL commitment (with private nonce) for the next step
        self.current_commitment = Some(commit);

        // 4. Create Package with only public info
        let pkg = CommitmentPackage {
            commitment: comm,
        };

        // 5. Encrypt & Sign
        self.secure_package(&pkg, combiner_pk)
    }

    // --- Protocol Step 2: Send Sigma (Partial Signature) ---
    pub fn set_sigma(&mut self, challenge: &Scalar, combiner_pk: &PublicKey) -> SecurePackage {
        // 1. Retrieve State
        let comm = self.current_commitment.as_ref()
            .expect("Protocol Error: No commitment found for this round!");

        let my_key = self.taps_kp.as_ref()
            .expect("Protocol Error: TAPS keys not initialized");

        // 2. Compute Signature using TAPS logic (z = r + c * sk)
        // This uses the specific implementation you provided
        let signature = Sign::sign(comm, my_key, challenge);

        // 3. Create Package
        let pkg = SigmaPackage {
            z: signature,
        };

        // 4. Encrypt & Sign
        self.secure_package(&pkg, combiner_pk)
    }
}