use taps::protocol::taps::*;
use crate::crypto::*;
use secp256k1::{PublicKey, Scalar, Error};
use serde::{Serialize, Deserialize};
use bincode;
use std::collections::HashMap;

use crate::authority::CombinerPackage;
use crate::signer::{CommitmentPackage, SigmaPackage};

mod serde_scalar {
    use serde::{Deserialize, Deserializer, Serializer};
    use secp256k1::Scalar;

    // Serialize a single Scalar
    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&scalar.to_be_bytes())
    }

    // Deserialize a single Scalar
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We expect 32 bytes
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Scalar::from_be_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignerPackage {
    pub R: PublicKey,
    #[serde(with = "serde_scalar")]
    pub c: Scalar,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TracerPackage {
    pub T: ElGamalCiphertext,
    pub v0: PublicKey,
    pub v_vec: Vec<PublicKey>,
    pub proof: Proofs,
    pub sigma: Sigma,
    #[serde(with = "serde_scalar")]
    pub c: Scalar,
    #[serde(with = "serde_scalar")]
    pub alpha: Scalar,
    pub m: Vec<u8>,
}

pub struct Combiner {
    // 1. Networking Keys (For secure communication)
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    // 2. TAPS Protocol State (Global info)
    pub pk: Option<PK>,
    pub quorum: Option<Quorum>,
    pub n: Option<usize>,
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
            n: None,
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

    // --- Bootstrap: Load Configuration from Authority ---
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

        // 3. DESERIALIZE Configuration
        let config: CombinerPackage = bincode::deserialize(&plaintext_bytes)
            .map_err(|_| Error::InvalidMessage)?;

        // 4. LOAD State
        println!("[Combiner] Bootstrap successful. Loading configuration...");

        self.pk = Some(config.pk);
        self.quorum = Some(config.quo);
        self.n = Some(config.n);
        self.t = Some(config.t);
        self.tks = Some(config.tks);
        self.taps_kp = Some(config.kp_cs);

        // Optional: Log what we loaded
        println!("[Combiner] Configuration Loaded:");
        println!("           - Threshold (t): {}", config.t);
        println!("           - Quorum Size:   {}", self.n.as_ref().unwrap());

        Ok(())
    }

    pub fn handle_commitment(&mut self, signer_id: usize, comm: Commitment) {
        // Use self.t (participant count) for validation, just like handle_sigma
        if let Some(participant_count) = self.n {
            if signer_id < participant_count {
                println!("[Combiner] Stored Commitment from Signer #{}", signer_id);
                self.commitments.insert(signer_id, comm);
            } else {
                println!("[Combiner] Rejected Commitment: Signer #{} out of range (>= {})", signer_id, participant_count);
            }
        } else {
            println!("[Combiner] Error: Participant count (n) not set, cannot accept Commitment.");
        }
    }

    pub fn load_commitment(
        &mut self,
        signer_id: &usize,
        secure_pkg: &SecurePackage,
        signer_pk: &PublicKey,
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
            &signer_pk,          // Sender PK (Authority)
            &secure_pkg.ciphertext,
            &secure_pkg.nonce
        );

        // 3. DESERIALIZE Configuration
        let config: CommitmentPackage = bincode::deserialize(&plaintext_bytes)
            .map_err(|_| Error::InvalidMessage)?;

        // 4. LOAD State
        println!("[Combiner] Bootstrap successful. Loading configuration...");

        self.handle_commitment(*signer_id, config.commitment.clone());

        // Optional: Log what we loaded
        println!("[Combiner] Commitment Loaded:");
        println!("           - Signer ID: {}", *signer_id);
        println!("           - Signer Commitment: {:?}", config.commitment.clone());

        Ok(())
    }

    // --- Protocol Step: Aggregate Commitments (R) ---

    pub fn compute_aggregated_nonce(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");

        // We use self.n as the total participant count 'n'
        let n = self.n.expect("Participant count (n) not set");

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
        if let Some(participant_count) = self.n {
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

    pub fn load_sigma(
        &mut self,
        signer_id: &usize,
        secure_pkg: &SecurePackage,
        signer_pk: &PublicKey,
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
            &signer_pk,          // Sender PK (Authority)
            &secure_pkg.ciphertext,
            &secure_pkg.nonce
        );

        // 3. DESERIALIZE Configuration
        let config: SigmaPackage = bincode::deserialize(&plaintext_bytes)
            .map_err(|_| Error::InvalidMessage)?;

        // 4. LOAD State
        println!("[Combiner] Bootstrap successful. Loading configuration...");

        self.handle_sigma(*signer_id, config.z.clone());

        // Optional: Log what we loaded
        println!("[Combiner] Configuration Loaded:");
        println!("           - Sign: {:?}", config.z.clone());

        Ok(())
    }

    pub fn compute_aggregated_sign(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");
        // We use self.n as the total participant count 'n'
        let n = self.n.expect("Participant count (n) not set");

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
        let c_cipher = ElGamalCiphertext::encrypt(
            &rho_secret,
            z_struct,
            kp_t
        );

        // 4. Store State
        self.w_rho = Some(rho_secret); // Store the randomness rho
        self.C = Some(c_cipher);       // Store the encrypted signature C

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
        // This handles the alpha^(i+1) * gamma * (1-b_i) logic internally
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

    // --- Protocol Step: Construct Final Signature (Sigma) ---

    pub fn construct_sigma(&self, message: &[u8]) -> Result<Sigma, Error> {

        // 1. Construct Pi (Proof)
        // We use the helper method we defined earlier to assemble Beta + Hats
        let pi = self.construct_pi()?;

        // 2. Retrieve Context
        let taps_kp = self.taps_kp.as_ref().expect("TAPS KeyPair not set");
        let R = self.R.as_ref().expect("Aggregated Nonce R not set");
        let C = self.C.as_ref().expect("Encrypted Signature C not computed");

        // 3. Call Sigma::sign from taps.rs
        // Arguments: (kp, message, R, C, pi)
        // This generates the final Schnorr signature over the whole package
        let sigma = Sigma::sign(
            taps_kp,
            message,
            R,
            C,
            pi
        );

        println!("[Combiner] Constructed Final Sigma.");

        Ok(sigma)
    }

    // --- Generic Signing Function ---
    // Takes any Serializable struct, wraps it in SignedPackage, and signs it.
    pub fn sign_package<T: Serialize>(&self, payload: &T) -> BroadcastPackage {

        // 1. Serialize the Payload (e.g., using bincode)
        let text = bincode::serialize(payload).expect("Failed to serialize package");

        // 2. Generate Metadata
        // Nonce: 12 random bytes
        let mut nonce = vec![0u8; 12];
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        rng.fill_bytes(&mut nonce);

        // Timestamp: Current unix time
        let timestamp = current_timestamp();

        // 4. Sign with Identity Key
        // Assuming identity_kp has a method .sign(&[u8]) -> Signature
        let signature = self.identity_kp.sign_data(&text, &nonce, timestamp);

        // 5. Construct Package
        BroadcastPackage {
            text,
            nonce,
            timestamp,
            signature,
        }
    }

    // --- Prepare Specific Packages ---

    // 1. For Signers: Contains R and c
    pub fn prepare_signer_package(&self) -> BroadcastPackage {
        let R = self.R.as_ref().expect("R not set");
        let c = self.c.as_ref().expect("c not set");

        let payload = SignerPackage {
            R: *R,
            c: *c,
        };

        self.sign_package(&payload)
    }

    // 2. For Tracer: Contains T, Sigma, c, alpha
    pub fn prepare_tracer_package(&self, sigma: &Sigma, m: &[u8]) -> BroadcastPackage {
        let T = self.T.as_ref().expect("T not set");
        let proof_struct = self.proofs.as_ref().expect("Proofs not computed");
        let c = self.c.as_ref().expect("c not set");
        let alpha = self.alpha.as_ref().expect("alpha not set");
        let v0 : PublicKey = self.v0.as_ref().expect("v0 not computed").clone();
        let v = self.v_vec.as_ref().expect("v_vec not computed").clone();

        let payload = TracerPackage {
            T: T.clone(),
            v0: v0,
            v_vec: v,
            proof: proof_struct.clone(),
            sigma: sigma.clone(), // Passed in from construct_sigma
            c: *c,
            alpha: *alpha,
            m: m.to_vec(),
        };

        self.sign_package(&payload)
    }
}