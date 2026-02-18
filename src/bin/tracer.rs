//use tokio::net::TcpListener;
use secp256k1::PublicKey;
use simulation_taps::{
    network::{self, Message, Role},
    tracer::Tracer,
};
use std::error::Error;
use std::time::Instant;
use tokio::net::TcpStream;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[Tracer] Starting TAPS Tracer Node...");

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    let start_setup = Instant::now();
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
        Message::Secure {
            pk,
            identity_pk,
            package,
        } => {
            println!("[Tracer] Received SecurePackage from Authority. Bootstrapping...");
            let pubkey = PublicKey::from_slice(&pk)?;
            let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
            tracer.load_from_authority(&package, &pubkey, &identity_pubkey)?;
        }
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
        Message::Broadcast {
            identity_pk,
            package: signed_pkg,
        } => {
            // 1. Verify Combiner's Signature
            // We use the same 'combiner_pk' we trusted from the Handsh
            let identity_pk = PublicKey::from_slice(&identity_pk)?;
            tracer.load_from_combiner(&signed_pkg, &identity_pk)?;
        }
        _ => return Err("Expected TracerPackage from Combiner".into()),
    }
    println!("BENCH,Setup,{}", start_setup.elapsed().as_micros());

    let start_verify_sigma = Instant::now();
    tracer.verify_sigma()?;
    let duration = start_verify_sigma.elapsed();
    println!("BENCH,VerifySigma,{}", duration.as_micros());

    let start_verify_proof = Instant::now();
    tracer.verify_proof()?;
    let duration_verify_proof = start_verify_sigma.elapsed();
    println!("BENCH,VerifyProof,{}", duration.as_micros());

    let start_verify_sign = Instant::now();
    tracer.verify_sign();
    let duration_verify_sign = start_verify_sign.elapsed();
    println!("BENCH,VerifySign,{}", duration.as_micros());

    println!("[Tracer] Protocol Finished Successfully.");

    Ok(())
}
