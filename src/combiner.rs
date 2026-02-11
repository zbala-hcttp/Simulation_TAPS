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
use crate::authority::CombinerPackage;

pub struct Combiner {
    // 1. Networking Keys (For secure communication)
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    // 2. TAPS Protocol State (Global info)
    pub pk: Option<PK>,
    pub quorum: Option<Quorum>,
    pub t: Option<usize>,
    pub tks: Option<TracingKeys>,
    pub taps_kp: Option<KeyPair>,

    // Round State (Signing)
    commitments: HashMap<usize, Commitment>,
    sigmas: HashMap<usize, Sign>,

    // ZKP State
    pub T: Option<ElGamalCiphertext>, // e.g. Encrypted Sum of Participants
    pub C: Option<ElGamalCiphertext>, // e.g. Encrypted Sign

    pub R: Option<PublicKey>,

    pub c: Option<Scalar>,     // The Challenge
    pub alpha: Option<Scalar>, // Fiat-Shamir param
    pub beta: Option<Scalar>,  // Fiat-Shamir param

    pub w_z: Option<Sign>,         // Aggregated signature (z) <--- CHANGED
    pub w_rho: Option<Secret>,     // Randomness for Encrypting t <--- CHANGED
    pub w_gamma: Option<Secret>,   // Randomness <--- CHANGED
    pub w_psi: Option<Secret>,     // Randomness <--- CHANGED
    pub w_phi_i: Option<Phis>,

    pub v0: Option<PublicKey>,
    pub v_vec: Option<Vec<PublicKey>>,

    // Zero-Knowledge Proof State (New)
    pub blinds: Option<Blinds>,
    pub hats: Option<Hats>,
    pub proofs: Option<Proofs>,
}

impl Combiner {
    /// Creates a new Combiner with fresh network keys.
    /// Does not yet have the TAPS group public key or quorum.
    pub fn new() -> Self {
        Combiner {
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            pk: None,
            quorum: None,
            t: None,
            tks: None,
            taps_kp: None,
            commitments: HashMap::new(),
            sigmas: HashMap::new(),
            T: None,
            C: None,
            R: None,
            c: None,
            alpha: None,
            beta: None,
            w_z: None,
            w_rho: None,
            w_gamma: None,
            w_psi: None,
            w_phi_i: None,
            v0: None,
            v_vec: None,
            blinds: None,
            hats: None,
            proofs: None,
        }
    }

    pub fn init(&mut self, pkg: CombinerPackage) {
        self.pk = Some(pkg.pk);
        self.quorum = Some(pkg.quo);
        self.t = Some(pkg.t);
        self.tks = Some(pkg.tks);
        self.taps_kp = Some(pkg.kp_cs);

        println!("[Combiner] Initialized with Threshold t={}", pkg.t);
    }

    pub fn handle_commitment(&mut self, signer_id: usize, comm: Commitment) {
        // Use self.t (participant count) for validation, just like handle_sigma
        if let Some(participant_count) = self.t {
            if signer_id < participant_count {
                println!("[Combiner] Stored Commitment from Signer #{}", signer_id);
                self.commitments.insert(signer_id, comm);
            } else {
                println!("[Combiner] Rejected Commitment: Signer #{} out of range (>= {})", signer_id, participant_count);
            }
        } else {
            println!("[Combiner] Error: Participant count (t) not set, cannot accept Commitment.");
        }
    }

    // --- Protocol Step: Aggregate Commitments (R) ---

    pub fn compute_aggregated_nonce(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");

        // We use self.t as the total participant count 'n'
        let n = self.t.expect("Participant count (t) not set");

        let mut ordered_commitments = Vec::with_capacity(n);

        // Strict loop: We must find a commitment for every index 0..n
        for i in 0..n {
            if let Some(c) = self.commitments.get(&i) {
                ordered_commitments.push(c.clone());
            } else {
                eprintln!("[Combiner] Error: Missing commitment from Signer #{}", i);
                return Err(Error::InvalidPublicKey);
            }
        }

        // 2. Call TAPS implementation
        // This returns Result<PublicKey, Error> based on your snippet
        let R_val = Commitment::aggregate(&ordered_commitments, quorum)?;

        // 3. Store State
        self.R = Some(R_val);
        println!("[Combiner] Aggregated Nonce R computed and stored.");

        Ok(())
    }

    // --- Protocol Step: Compute Challenge & Parameters (Phase 1) ---

    pub fn compute_parameters(
        &mut self,
        message: &[u8]
    ) -> Result<(), Error> { // Returns unit

        let pk = self.pk.as_ref().expect("PK not set");
        let t_val = self.t.expect("Threshold t not set");

        // 1. Generate Witness: psi (Secret Randomness for Threshold)
        let psi_secret = Secret::create();

        // 2. Encrypt Threshold t -> T (using psi)
        let t_scalar = {
            let mut bytes = [0u8; 32];
            let t_bytes = (t_val as u64).to_be_bytes();
            bytes[24..32].copy_from_slice(&t_bytes);
            Scalar::from_be_bytes(bytes).expect("Threshold scalar conversion failed")
        };

        // Encrypt using psi
        let T_cipher = ElGamalCiphertext::encrypt_value(&psi_secret, &t_scalar);

        let R= self.R.as_ref().expect("Aggregated Nonce R not computed yet");
        // 3. Compute Protocol Parameters (c, alpha, beta)
        let (c, alpha, beta) = get_parameters(pk, &T_cipher, R, message);

        // 4. Store State
        self.w_psi = Some(psi_secret);
        self.T = Some(T_cipher);

        // Store Protocol Parameters internally
        self.c = Some(c);
        self.alpha = Some(alpha);
        self.beta = Some(beta);

        println!("[Combiner] Computed Parameters. Stored w_psi, T, c, alpha, beta.");

        Ok(())
    }


    pub fn handle_sigma(&mut self, signer_id: usize, signature_share: Sign) {
        if let Some(participant_count) = self.t {
            // "t" acts as the size of participants
            if signer_id < participant_count {
                println!("[Combiner] Stored Sign (z) from Signer #{}", signer_id);
                self.sigmas.insert(signer_id, signature_share);
            } else {
                println!("[Combiner] Rejected Sign: Signer #{} out of range (>= {})", signer_id, participant_count);
            }
        } else {
            println!("[Combiner] Error: Participant count (t) not set.");
        }
    }

    pub fn compute_aggregated_sign(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");
        // We use self.t as the total participant count 'n'
        let n = self.t.expect("Participant count (t) not set");

        let mut ordered_signs = Vec::with_capacity(n);

        // Strict loop: We must find a signature for every index 0..n
        for i in 0..n {
            if let Some(s) = self.sigmas.get(&i) {
                ordered_signs.push(s.clone());
            } else {
                eprintln!("[Combiner] Error: Missing signature from Signer #{}", i);
                return Err(Error::InvalidPublicKey);
            }
        }

        let aggregated_sign = Sign::aggregate(&ordered_signs, quorum);

        // Update Internal State
        println!("[Combiner] Aggregation complete. Stored w_z.");
        self.w_z = Some(aggregated_sign);

        Ok(())
    }

    // --- Protocol Step: Encrypt Signature (C) ---

    pub fn compute_encrypted_signature(&mut self, kp_t: &KeyPair) -> Result<(), Error> {

        // Get the aggregated signature 'z' we computed earlier
        let z_struct = self.w_z.as_ref().expect("w_z (Aggregated Signature) not computed yet");

        // 2. Generate Randomness (rho)
        // This is the "secret" we create here to encrypt z.
        let rho_secret = Secret::create();

        // 3. Encrypt z -> C
        // We use the specific syntax you requested: ElGamalEncrypt::encrypt
        // Arguments: (randomness, message, key)
        let C_cipher = ElGamalCiphertext::encrypt(
            &rho_secret,
            z_struct,
            kp_t
        );

        // 4. Store State
        self.w_rho = Some(rho_secret); // Store the randomness rho
        self.C = Some(C_cipher);       // Store the encrypted signature C

        println!("[Combiner] Encrypted z -> C. Stored w_rho (Secret) and C.");

        Ok(())
    }

    // --- Protocol Step: Compute Phi Vector & Gamma ---

    pub fn compute_phis(&mut self) -> Result<(), Error> {
        // 1. Retrieve Context
        let alpha = self.alpha.as_ref().expect("Alpha not set");
        let quorum = self.quorum.as_ref().expect("Quorum not set");

        // 2. Generate Secret Gamma
        let gamma_secret = Secret::create();

        // 3. Call Phis::set from taps.rs
        // This handles the alpha^i * gamma * (1-b_i) logic internally
        let phis_struct = Phis::set(alpha, &gamma_secret, quorum);

        // 4. Store State
        self.w_gamma = Some(gamma_secret);
        // We assume Phis has a public field 'phis' or we can extract it.
        // Based on your snippet "Phis { phis: phi_vec }", it should be accessible.
        self.w_phi_i = Some(phis_struct);

        println!("[Combiner] Computed w_phi_i (via Phis::set) and w_gamma.");

        Ok(())
    }

    // --- Protocol Step: Encrypt Bits (v0, v_vec) ---

    pub fn compute_encrypted_bits(&mut self) -> Result<(), Error> {
        // 1. Retrieve Context
        let gamma_secret = self.w_gamma.as_ref().expect("w_gamma (Secret Gamma) not computed yet");
        let quorum = self.quorum.as_ref().expect("Quorum not set");
        let tks = self.tks.as_ref().expect("Tracing Keys not set");

        // 2. Call encrypt_bits from taps.rs
        // Arguments: (sec, quo, kps) -> (v0, v_vec)
        // Uses: w_gamma (sec), quorum (quo), tks (kps)
        let (v0_val, v_vec_val) = encrypt_bits(gamma_secret, quorum, tks);

        // 3. Store State
        self.v0 = Some(v0_val);
        self.v_vec = Some(v_vec_val);

        println!("[Combiner] Computed Encrypted Bits (v0, v_vec).");

        Ok(())
    }

    // --- Protocol Step: Generate Blinds (Random k values) ---

    pub fn compute_blinds(&mut self, n: usize) -> Result<(), Error> {
        // n is passed explicitly (Total Participants)

        // Call Blinds::set from taps.rs with n
        let blinds_struct = Blinds::set(n);

        // Store State
        self.blinds = Some(blinds_struct);
        println!("[Combiner] Computed Blinds (Randomness k) for n={} participants.", n);

        Ok(())
    }

    // --- Protocol Step: Compute Proofs (Commitments S) ---

    pub fn compute_proofs(&mut self) -> Result<(), Error> {
        // 1. Retrieve Context
        let blinds = self.blinds.as_ref().expect("Blinds not computed");
        let pk = self.pk.as_ref().expect("PK not set");
        let tks = self.tks.as_ref().expect("Tracing Keys not set");
        let v_vec = self.v_vec.as_ref().expect("Encrypted Bits (v_vec) not computed");
        let c = self.c.as_ref().expect("Challenge c not set");
        let alpha = self.alpha.as_ref().expect("Alpha not set");

        // 2. Call Proofs::compute_proofs from taps.rs
        // Arguments: (bli, pk, h_i_vec, v_i, c, alpha)
        // Note: h_i_vec maps to tks (TracingKeys) in your description
        let proofs_struct = Proofs::compute_proofs(
            blinds,
            pk,
            tks,
            v_vec,
            c,
            alpha
        );

        // 3. Store State
        self.proofs = Some(proofs_struct);
        println!("[Combiner] Computed Proofs (Commitments S).");

        Ok(())
    }

    // --- Protocol Step: Compute Hats (Responses) ---

    pub fn compute_hats(&mut self) -> Result<(), Error> {
        // 1. Retrieve Witness Components
        // We clone these because Witnesses::set likely takes ownership or we need to pass values
        let z = self.w_z.as_ref().expect("w_z (Signature) not set").clone();
        let rho = self.w_rho.as_ref().expect("w_rho not set").clone();
        let gamma = self.w_gamma.as_ref().expect("w_gamma not set").clone();
        let psi = self.w_psi.as_ref().expect("w_psi not set").clone();

        let quorum = self.quorum.as_ref().expect("Quorum not set");
        let phis = self.w_phi_i.as_ref().expect("w_phi_i not set");

        // 2. Construct Temporary 'Witnesses' Struct
        // This bundles the secrets just for the calculation
        let witnesses_struct = Witnesses::set(
            z,
            rho,
            gamma,
            psi,
            quorum,
            phis
        );

        // 3. Retrieve Challenge & Blinds
        let beta = self.beta.as_ref().expect("Beta (Challenge) not set");
        let blinds = self.blinds.as_ref().expect("Blinds not computed");

        // 4. Compute Hats
        // Arguments: (beta, witt, bli)
        // Formula: hat = k + beta * witness
        let hats_struct = Hats::set(beta, &witnesses_struct, blinds);

        // 5. Store State
        self.hats = Some(hats_struct);
        println!("[Combiner] Computed Hats (Responses).");

        Ok(())
    }

    // --- Protocol Step: Construct Proof Package (Pi) ---

    pub fn construct_pi(&self) -> Result<Pi, Error> {
        // 1. Retrieve Context
        // We clone beta (Scalar is Copy) and hats (Clone)
        let beta = self.beta.as_ref().expect("Beta (Challenge) not set").clone();
        let hats = self.hats.as_ref().expect("Hats (Responses) not computed").clone();

        // 2. Construct Pi
        let pi_struct = Pi {
            beta,
            hats,
        };

        println!("[Combiner] Constructed Pi (Proof Package).");

        Ok(pi_struct)
    }

    
}