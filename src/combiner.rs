use taps::protocol::taps::*;
use crate::crypto::*;
use secp256k1::{PublicKey, SecretKey, Scalar, Error};
use serde::{Serialize, Deserialize};
use bincode;
use std::collections::HashMap;

// Internal Simulation Imports
use crate::crypto::{IdentityKeyPair, TransportKeyPair};

// External TAPS Library Imports
// We use the Commitment struct you just defined (public R only)
use taps::protocol::taps::{PK, Quorum, Commitment};

pub struct Combiner {
    // 1. Networking Keys (For secure communication)
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    // 2. TAPS Protocol State (Global info)
    pub pk: Option<PK>,          // The Group Public Key
    pub quorum: Option<Quorum>,  // The set of allowed signers

    // 3. Round State (What we collect during a signing session)
    // We map SignerID -> Commitment (public R)
    commitments: HashMap<usize, Commitment>,
    // We map SignerID -> Scalar (partial signature z)
    sigmas: HashMap<usize, Scalar>,
}

impl Combiner {
    /// Creates a new Combiner with fresh network keys.
    /// Does not yet have the TAPS group public key or quorum.
    pub fn new() -> Self {
        Combiner {
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            // TAPS state starts empty
            pk: None,
            quorum: None,
            // Round state starts empty
            commitments: HashMap::new(),
            sigmas: HashMap::new(),
        }
    }

    /// Initializes the Combiner with the Group Public Key and Quorum.
    /// This effectively "boots" the Combiner into the protocol.
    pub fn init(&mut self, pk: PK, quorum: Quorum) {
        self.pk = Some(pk);
        self.quorum = Some(quorum);
    }

    pub fn handle_commitment(&mut self, signer_id: usize, comm: Commitment) {
        // Only accept if we have a quorum set and the signer is in it
        if let Some(q) = &self.quorum {
            // In a real implementation, you'd check q.participants[signer_id] bit here
            // For now, just store it.
            println!("[Combiner] Stored Commitment from Signer #{}", signer_id);
            self.commitments.insert(signer_id, comm);
        }
    }

    // --- 2. Aggregate Commitments (The Logic You Provided) ---

    pub fn compute_aggregated_nonce(&self, n: usize) -> Result<PublicKey, Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");

        let mut ordered_commitments = Vec::with_capacity(n);

        for i in 0..n {
            if let Some(c) = self.commitments.get(&i) {
                ordered_commitments.push(c.clone());
            } else {
                // If a signer is in the quorum but hasn't sent a commitment yet,
                // we technically can't proceed.
                // For this simulation step, we might need a "dummy" commitment
                // or return an error if data is missing.
                eprintln!("[Combiner] Missing commitment from Signer #{}", i);
                return Err(Error::InvalidPublicKey); // Or a specific "MissingCommitment" error
            }
        }

        // 2. Call your TAPS implementation
        Commitment::aggregate(&ordered_commitments, quorum)
    }
}