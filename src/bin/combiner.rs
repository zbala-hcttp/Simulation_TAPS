use simulation_taps::{
    combiner::Combiner,
    network::{self, Message, Role}
};
use secp256k1::PublicKey;
use tokio::net::{TcpListener, TcpStream};
use std::error::Error;
use simulation_taps::crypto::BroadcastPackage;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_PORT: &str = "127.0.0.1:8081";

// The message to be signed in this simulation
const MESSAGE_BYTES: &[u8] = b"Hello TAPS: Distributed Privacy-Preserving Blockchain Transaction";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[Combiner] Starting TAPS Combiner Node...");

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    // 1. Connect to Authority
    println!("[Combiner] Connecting to Authority at {}...", AUTHORITY_ADDR);
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    // 2. Generate Ephemeral Transport Keys
    let mut combiner = Combiner::new();
    let transport_pk_bytes = combiner.transport_kp.pk.serialize().to_vec();

    // 3. Send Hello
    let hello = Message::Hello {
        id: 0,
        role: Role::Combiner,
        pk: transport_pk_bytes.clone(),
    };
    network::send(&mut auth_stream, &hello).await?;

    // 4. Receive Welcome Package
    let msg = network::receive(&mut auth_stream).await?;
    match msg {
        Message::Secure { pk, identity_pk, package } => {
            println!("[Combiner] Received SecurePackage from Authority. Bootstrapping...");
            let pubkey = PublicKey::from_slice(&pk)?;
            let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
            combiner.load_from_authority(&package, &pubkey, &identity_pubkey)?;
        },
        _ => return Err("Unexpected message from Authority".into()),
    }    

    // FIX: Copy the value (usize) immediately. Do not keep a reference.
    let n_signers = combiner.n.unwrap();

    println!("[Combiner] Bootstrap Complete. Quorum Size: {}", n_signers);


    // =========================================================================
    // Phase 2: Network Setup (Server)
    // =========================================================================

    let listener = TcpListener::bind(COMBINER_PORT).await?;
    println!("[Combiner] Listening on {}...", COMBINER_PORT);

    let expected_connections = n_signers + 1;

    // Fix: Explicit type annotation for the vector
    let mut signer_streams: Vec<Option<TcpStream>> = (0..n_signers)
        .map(|_| None)
        .collect();

    let mut tracer_stream: Option<TcpStream> = None;
    let mut connected_count = 0;

    println!("[Combiner] Waiting for {} participants...", expected_connections);

    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Combiner] Incoming connection from {}", addr);

        // Handshake
        let msg = network::receive(&mut socket).await?;
        if let Message::Hello { id, role, .. } = msg {
            match role {
                Role::Signer => {
                    if id < n_signers {
                        println!("[Combiner] Signer #{} verified.", id);
                        signer_streams[id] = Some(socket);
                        connected_count += 1;
                        
                        let hello = Message::Hello {
                            id: 0,
                            role: Role::Combiner,
                            pk: transport_pk_bytes.clone(),
                        };
                        network::send(signer_streams[id].as_mut().unwrap(), &hello).await?;

                    }
                },
                Role::Tracer => {
                    println!("[Combiner] Tracer verified.");
                    tracer_stream = Some(socket);
                    connected_count += 1;
                },
                _ => {},
            }
        }
    }
    println!("[Combiner] All participants connected. Starting Protocol.\n");


    // =========================================================================
    // Phase 3: Protocol Execution
    // =========================================================================

    // --- Step 1: Collect Commitments (Round 1) ---
    println!("[Combiner] >> Round 1: Collecting Commitments...");

    for (id, stream_opt) in signer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;

            if let Message::Secure { pk, identity_pk, package } = msg {
                // n_signers is a usize (copy), so it doesn't block mutable borrow of combiner
                let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
                let pubkey = PublicKey::from_slice(&pk)?;
                combiner.load_commitment(&id, &package, &pubkey, &identity_pubkey)?;
                println!("[Combiner] Verified Commitment from Signer #{}", id);
            }
        }
    }

    // --- Compute Challenge ---
    println!("[Combiner] >> Computing Parameters (R, c)...");
    combiner.compute_aggregated_nonce()?;
    combiner.compute_parameters(MESSAGE_BYTES)?;

    // --- Round 2: Distribute Challenge & Receive Shares ---
    println!("[Combiner] >> Round 2: Broadcasting Challenge...");

    // Prepare the authenticated package (R, c)
    let signer_pkg: BroadcastPackage = combiner.prepare_signer_package(); // Added ? for Result

    // Broadcast to Signers
    for stream_opt in signer_streams.iter_mut() {
        if let Some(stream) = stream_opt {
            network::send(stream, &Message::Broadcast {identity_pk: combiner.identity_kp.pk.serialize().to_vec(), package: signer_pkg.clone() }).await?;
        }
    }

    println!("[Combiner] >> Round 2: Collecting Signature Shares...");
    for (id, stream_opt) in signer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure { pk, identity_pk, package } = msg {
                let pubkey = PublicKey::from_slice(&pk)?;
                let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
                combiner.load_sigma(&id, &package, &pubkey, &identity_pubkey)?;
                println!("[Combiner] Received Share from Signer #{}", id);
            }
        }
    }

    // --- Finalization: Encrypt, ZKP, Sign ---
    println!("[Combiner] >> Finalization: Aggregating and Generating ZKP...");

    // 1. Aggregate z
    combiner.compute_aggregated_sign()?;

    // 2. Encrypt z -> C
    // We need to clone the key so we aren't borrowing 'combiner' inside the function call arguments
    let taps_kp = combiner.taps_kp.clone().ok_or("TAPS KP missing")?;

    // Now call mutable method with the cloned key
    combiner.compute_encrypted_signature(&taps_kp)?;

    // 3. Generate ZKP Components
    combiner.compute_encrypted_bits()?;
    combiner.compute_phis()?;
    combiner.compute_blinds(n_signers)?; // n_signers is just a usize
    combiner.compute_proofs()?;
    combiner.compute_hats()?;

    // 4. Construct Final Sigma
    let sigma = combiner.construct_sigma(MESSAGE_BYTES)?;
    println!("[Combiner] >> Final Sigma Constructed!");

    // --- Send to Tracer ---
    if let Some(stream) = tracer_stream.as_mut() {
        println!("[Combiner] Sending Result to Tracer...");
        let tracer_pkg = combiner.prepare_tracer_package(&sigma, &MESSAGE_BYTES);
        network::send(stream, &Message::Broadcast {identity_pk: combiner.identity_kp.pk.serialize().to_vec(), package: tracer_pkg }).await?;
    }

    println!("\n[Combiner] Protocol Finished Successfully.");
    Ok(())
}