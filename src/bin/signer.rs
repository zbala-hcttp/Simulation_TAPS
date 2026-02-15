use simulation_taps::{
    signer::{Signer},
    network::{self, Message, Role},
    crypto::IdentityKeyPair,
};
use tokio::net::TcpStream;
use secp256k1::PublicKey;
use std::env;
use std::error::Error;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Parse Signer ID from Command Line Args
    // Example usage: cargo run --bin signer 0
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: signer <id>");
        return Ok(());
    }
    let my_id: usize = args[1].parse()?;

    println!("[Signer #{}] Starting Node...", my_id);

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    // 1. Initialize our keys
    let mut signer = Signer::new(my_id);
    let my_transport_pk = signer.transport_kp.pk;

    // 2. Connect to Authority
    println!("[Signer #{}] Connecting to Authority...", my_id);
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    // 3. Handshake: Send our Hello
    let hello_auth = Message::Hello {
        id: my_id,
        role: Role::Signer,
        pk: my_transport_pk.serialize().to_vec(),
    };
    network::send(&mut auth_stream, &hello_auth).await?;

    // 4. Receive Credentials (Encrypted SignerPackage)
    let msg = network::receive(&mut auth_stream).await?;

    match msg {
        Message::Secure {pk, identity_pk, package } => {
            println!("[Signer #{}] Received Credentials.", my_id);
            let transport_key = PublicKey::from_slice(&pk)?;
            let identity_key = PublicKey::from_slice(&identity_pk)?;
            signer.load_from_authority(&package, &transport_key, &identity_key)?;
            println!("[Signer #{}] TAPS Key Loaded.", my_id);
        },
        _ => return Err("Expected Welcome from Authority".into()),
    }
    drop(auth_stream); // Close Authority connection


    // =========================================================================
    // Phase 2: Combiner Interaction
    // =========================================================================

    println!("[Signer #{}] Connecting to Combiner at {}...", my_id, COMBINER_ADDR);

    // FIX: Retry Loop. Keep trying until Combiner is ready.
    let mut combiner_stream = loop {
        match TcpStream::connect(COMBINER_ADDR).await {
            Ok(stream) => {
                println!("[Signer #{}] Connected to Combiner!", my_id);
                break stream;
            },
            Err(_) => {
                println!("[Signer #{}] Combiner not ready. Retrying in 2 seconds...", my_id);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // 1. Handshake: Send Hello
    let hello_combiner = Message::Hello {
        id: my_id,
        role: Role::Signer,
        pk: my_transport_pk.serialize().to_vec(),
    };
    network::send(&mut combiner_stream, &hello_combiner).await?;

    // 2. Handshake: Receive Combiner's Hello (Contains Combiner's Public Key)
    // CRITICAL: We obtain the Combiner's key here.
    let combiner_pk = match network::receive(&mut combiner_stream).await? {
        Message::Hello { role: Role::Combiner, pk, .. } => {
            PublicKey::from_slice(&pk)?
        },
        _ => return Err("Expected Hello from Combiner".into()),
    };
    println!("[Signer #{}] Handshake Complete. Combiner Key Verified.", my_id);


    // --- Round 1: Send Commitment ---

    println!("[Signer #{}] >> Round 1: Sending Commitment...", my_id);

    // Encrypt the commitment using the Combiner's Key we just received
    let comm_package = signer.set_commitment(&combiner_pk);

    let msg_comm = Message::Secure {
        pk: my_transport_pk.serialize().to_vec(), // Send our PK so Combiner knows who encrypted it
        identity_pk: signer.identity_kp.pk.serialize().to_vec(), // Send our Identity PK for signature verification
        package: comm_package,
    };
    network::send(&mut combiner_stream, &msg_comm).await?;


    // --- Round 2: Receive Challenge & Sign ---

    println!("[Signer #{}] >> Round 2: Waiting for Challenge (R, c)...", my_id);

    let msg = network::receive(&mut combiner_stream).await?;

    match msg {
        Message::Broadcast {identity_pk, package: signed_pkg } => {
            // 1. Verify Combiner's Signature
            // We use the same 'combiner_pk' we trusted from the Handsh
            let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
            if !IdentityKeyPair::verify_broadcast_data(&identity_pubkey, &signed_pkg) {
                return Err("Security Alert: Invalid Signature on Challenge!".into());
            }

            // 2. Deserialize Challenge
            let payload: simulation_taps::combiner::SignerPackage = bincode::deserialize(&signed_pkg.text)?;
            println!("[Signer #{}] Received Challenge.", my_id);

            // 3. Compute Share (z_i)
            // We use the 'c' from the payload.
            // We encrypt the result for the Combiner using 'combiner_pk'.
            let sigma_pkg = signer.set_sigma(&payload.c, &combiner_pk);

            // 4. Send Share
            let msg_share = Message::Secure {
                pk: my_transport_pk.serialize().to_vec(),
                identity_pk: signer.identity_kp.pk.serialize().to_vec(),
                package: sigma_pkg,
            };
            network::send(&mut combiner_stream, &msg_share).await?;
            println!("[Signer #{}] Sent Signature Share.", my_id);
        },
        _ => return Err("Expected SignerPackage from Combiner".into()),
    }

    println!("[Signer #{}] Protocol Finished Successfully.", my_id);
    Ok(())
}