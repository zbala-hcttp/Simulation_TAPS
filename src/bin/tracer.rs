//use tokio::net::TcpListener;
use std::error::Error;
use simulation_taps::{
    tracer::{Tracer},
    network::{self, Message, Role}
};
use tokio::net::TcpStream;
use secp256k1::PublicKey;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
println!("[Combiner] Starting TAPS Combiner Node...");

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    // 1. Connect to Authority
    println!("[Tracer] Connecting to Authority at {}...", AUTHORITY_ADDR);
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    // 2. Generate Ephemeral Transport Keys
    let mut tracer = Tracer::new();
    let transport_pk_bytes = tracer.transport_kp.pk.serialize().to_vec();

    // 3. Send Hello
    let hello = Message::Hello {
        id: 0,
        role: Role::Tracer,
        pk: transport_pk_bytes,
    };
    network::send(&mut auth_stream, &hello).await?;

    // 4. Receive Welcome Package
    let msg = network::receive(&mut auth_stream).await?;
    match msg {
        Message::Secure { pk, identity_pk, package } => {
            println!("[Tracer] Received SecurePackage from Authority. Bootstrapping...");
            let pubkey = PublicKey::from_slice(&pk)?;
            let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
            tracer.load_from_authority(&package, &pubkey, &identity_pubkey)?;
        },
        _ => return Err("Unexpected message from Authority".into()),
    } 

    // =========================================================================
    // Phase 2: Combiner Interaction
    // =========================================================================

    println!("[Tracer] Connecting to Combiner...");
    let mut combiner_stream = TcpStream::connect(COMBINER_ADDR).await?;

    // 1. Handshake: Send Hello
    let hello_combiner = Message::Hello {
        id: 0,
        role: Role::Tracer,
        pk: tracer.transport_kp.pk.serialize().to_vec(),
    };
    network::send(&mut combiner_stream, &hello_combiner).await?;

    // --- Round 2: Receive Challenge & Sign ---

    let msg = network::receive(&mut combiner_stream).await?;

    match msg {
        Message::Broadcast {identity_pk, package: signed_pkg } => {
            // 1. Verify Combiner's Signature
            // We use the same 'combiner_pk' we trusted from the Handsh
            let identity_pk = PublicKey::from_slice(&identity_pk)?;
            tracer.load_from_combiner(&signed_pkg, &identity_pk)?;
        },
        _ => return Err("Expected TracerPackage from Combiner".into()),
    }


    tracer.verify_sigma()?;
    tracer.verify_proof()?;
    tracer.verify_sign();
    
    println!("[Tracer] Protocol Finished Successfully.");

    Ok(())
}