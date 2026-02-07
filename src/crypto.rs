use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdh::SharedSecret};
use secp256k1::ecdsa::Signature;
use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a secure package sent over the network.
#[derive(Debug, Clone)]
pub struct SecurePackage {
    pub ciphertext: Vec<u8>,  
    pub nonce: Vec<u8>,       // AES-GCM Nonce (12 bytes)
    pub timestamp: u64,       
    pub signature: Signature, 
}

/// Gets current Unix timestamp.
pub fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// derives a 32-byte AES key from (My_SK, Their_PK) using ECDH.
fn derive_aes_key(my_sk: &SecretKey, their_pk: &PublicKey) -> Key<Aes256Gcm> {
    // 1. Compute Shared Secret (ECDH)
    // This creates a point P = my_sk * their_pk
    let shared_point = SharedSecret::new(their_pk, my_sk);
    
    // 2. Hash it to get a uniform 32-byte key
    // SharedSecret implements AsRef<[u8]>, which gives the X-coordinate hash usually.
    // To be perfectly explicit/safe, we hash the bytes provided by the library.
    let mut hasher = Sha256::new();
    hasher.update(shared_point.as_ref());
    *Key::<Aes256Gcm>::from_slice(hasher.finalize().as_slice())
}

/// Encrypts data using AES-256-GCM + ECDH.
pub fn encrypt_package(
    sender_sk: &SecretKey,
    receiver_pk: &PublicKey, 
    plain_bytes: &[u8]
) -> (Vec<u8>, Vec<u8>) { // Returns (Ciphertext, Nonce)
    
    // 1. Derive Shared Key
    let key = derive_aes_key(sender_sk, receiver_pk);
    let cipher = Aes256Gcm::new(&key);

    // 2. Generate unique Nonce (96-bits / 12 bytes)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Random nonce is critical!

    // 3. Encrypt
    let ciphertext = cipher.encrypt(&nonce, plain_bytes)
        .expect("Encryption failure!");

    (ciphertext, nonce.to_vec())
}

/// Decrypts data using AES-256-GCM + ECDH.
pub fn decrypt_package(
    receiver_sk: &SecretKey,
    sender_pk: &PublicKey,
    ciphertext: &[u8],
    nonce_bytes: &[u8]
) -> Vec<u8> {
    // 1. Derive SAME Shared Key (ECDH is symmetric: a*B = b*A)
    let key = derive_aes_key(receiver_sk, sender_pk);
    let cipher = Aes256Gcm::new(&key);

    // 2. Decrypt
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
        .expect("Decryption failed! Invalid key or tampered data.")
}

/// Signs the package contents (Ciphertext + Nonce + Timestamp).
pub fn sign_package(
    signer_sk: &SecretKey, 
    ciphertext: &[u8], 
    nonce: &[u8],
    timestamp: u64
) -> Signature {
    let secp = Secp256k1::new();
    
    let mut buffer = Vec::new();
    buffer.extend_from_slice(ciphertext);
    buffer.extend_from_slice(nonce); // Must sign nonce too!
    buffer.extend_from_slice(&timestamp.to_be_bytes());
    
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let msg = Message::from_digest(hasher.finalize().into());
    
    secp.sign_ecdsa(&msg, signer_sk)
}

/// Verifies origin, integrity, and freshness.
pub fn verify_package(
    sender_pk: &PublicKey, 
    package: &SecurePackage,
    max_age_seconds: u64
) -> bool {
    let secp = Secp256k1::new();

    // 1. Check Timestamp
    let now = current_timestamp();
    if package.timestamp > now || (now - package.timestamp) > max_age_seconds {
        println!("[Crypto] Message expired or invalid time.");
        return false;
    }

    // 2. Reconstruct Message
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&package.ciphertext);
    buffer.extend_from_slice(&package.nonce);
    buffer.extend_from_slice(&package.timestamp.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let msg = Message::from_digest(hasher.finalize().into());

    secp.verify_ecdsa(&msg, &package.signature, sender_pk).is_ok()
}