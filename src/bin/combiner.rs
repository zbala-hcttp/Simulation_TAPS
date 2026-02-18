use secp256k1::PublicKey;
use simulation_taps::crypto::BroadcastPackage;
use simulation_taps::{
    combiner::Combiner,
    network::{self, Message, Role},
};
use std::error::Error;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};

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
    println!(
        "[Combiner] Connecting to Authority at {}...",
        AUTHORITY_ADDR
    );

    let start_setup = Instant::now();
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
        Message::Secure {
            pk,
            identity_pk,
            package,
        } => {
            println!("[Combiner] Received SecurePackage from Authority. Bootstrapping...");
            let pubkey = PublicKey::from_slice(&pk)?;
            let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
            combiner.load_from_authority(&package, &pubkey, &identity_pubkey)?;
        }
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
    let mut signer_streams: Vec<Option<TcpStream>> = (0..n_signers).map(|_| None).collect();

    let mut tracer_stream: Option<TcpStream> = None;
    let mut connected_count = 0;

    println!(
        "[Combiner] Waiting for {} participants...",
        expected_connections
    );

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
                }
                Role::Tracer => {
                    println!("[Combiner] Tracer verified.");
                    tracer_stream = Some(socket);
                    connected_count += 1;
                }
                _ => {}
            }
        }
    }
    println!("[Combiner] All participants connected. Starting Protocol.\n");

    println!("BENCH,[Combiner] Setup,{}", start_setup.elapsed().as_micros());
    // =========================================================================
    // Phase 3: Protocol Execution
    // =========================================================================

    // --- Step 1: Collect Commitments (Round 1) ---
    println!("[Combiner] >> Round 1: Collecting Commitments...");
    let start_round1 = Instant::now();
    for (id, stream_opt) in signer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;

            if let Message::Secure {
                pk,
                identity_pk,
                package,
            } = msg
            {
                // n_signers is a usize (copy), so it doesn't block mutable borrow of combiner
                let identity_pubkey = PublicKey::from_slice(&identity_pk)?;
                let pubkey = PublicKey::from_slice(&pk)?;
                combiner.load_commitment(&id, &package, &pubkey, &identity_pubkey)?;
                println!("[Combiner] Verified Commitment from Signer #{}", id);
            }
        }
    }
    let duration_round1 = start_round1.elapsed();
    println!("BENCH,[Combiner] Aggregation,{}", duration_round1.as_micros());

    // --- Compute Challenge ---
    println!("[Combiner] >> Computing Parameters (R, c)...");
    let start_aggregate_nonce = Instant::now();
    combiner.compute_aggregated_nonce()?;
    let duration_aggregate_nonce = start_aggregate_nonce.elapsed();
    println!("BENCH,[Combiner] Round_Aggregate_Nonce,{}", duration_aggregate_nonce.as_micros());

    let start_encrypt_threshold = Instant::now();
    combiner.encrypt_threshold()?;
    let duration_encrypt_threshold = start_encrypt_threshold.elapsed();
    println!("BENCH,[Combiner] EncryptionThreshold,{}", duration_encrypt_threshold.as_micros());

    let start_compute_parameters = Instant::now();
    combiner.compute_parameters(MESSAGE_BYTES)?;
    let duration_compute_parameters = start_compute_parameters.elapsed();
    println!("BENCH,[Combiner] Compute Parameters,{}", duration_compute_parameters.as_micros());

    // --- Round 2: Distribute Challenge & Receive Shares ---
    println!("[Combiner] >> Round 2: Broadcasting Challenge...");

    // Prepare the authenticated package (R, c)
    let signer_pkg: BroadcastPackage = combiner.prepare_signer_package(); // Added ? for Result

    // Broadcast to Signers
    for stream_opt in signer_streams.iter_mut() {
        if let Some(stream) = stream_opt {
            network::send(
                stream,
                &Message::Broadcast {
                    identity_pk: combiner.identity_kp.pk.serialize().to_vec(),
                    package: signer_pkg.clone(),
                },
            )
            .await?;
        }
    }

    println!("[Combiner] >> Round 2: Collecting Signature Shares...");
    for (id, stream_opt) in signer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure {
                pk,
                identity_pk,
                package,
            } = msg
            {
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
    let start_aggregate_sign = Instant::now();
    combiner.compute_aggregated_sign()?;
    let duration_aggregate_sign = start_aggregate_sign.elapsed();
    println!("BENCH,[Combiner] Aggregate Sign,{}", duration_aggregate_sign.as_micros());

    // 2. Encrypt z -> C
    let start_encrypted_signature = Instant::now();
    combiner.compute_encrypted_signature()?;
    let duration_encrypted_signature = start_encrypted_signature.elapsed();
    println!("BENCH,[Combiner] Encrypted Signature,{}", duration_encrypted_signature.as_micros());

    // 3. Generate ZKP Components
    let start_compute_phis = Instant::now();
    combiner.compute_phis()?;
    let duration_compute_phis = start_compute_phis.elapsed();
    println!("BENCH,[Combiner] Compute Phis,{}", duration_compute_phis.as_micros());

    let start_compute_encrypted_bits = Instant::now();
    combiner.compute_encrypted_bits()?;
    let duration_compute_encrypted_bits = start_compute_encrypted_bits.elapsed();
    println!("BENCH,[Combiner] Compute Encrypted Bits,{}", duration_compute_encrypted_bits.as_micros());

    let start_compute_blinds = Instant::now();
    combiner.compute_blinds(n_signers)?;
    let duration_compute_blinds = start_compute_blinds.elapsed();
    println!("BENCH,[Combiner] Blinds,{}", duration_compute_blinds.as_micros());

    let start_compute_proofs = Instant::now();
    combiner.compute_proofs()?;
    let duration_compute_proofs = start_compute_proofs.elapsed();
    println!("BENCH,[Combiner] Proof s,{}", duration_compute_proofs.as_micros());

    let start_compute_compute_hats = Instant::now();
    combiner.compute_hats()?;
    let duration_compute_compute_hats = start_compute_compute_hats.elapsed();
    println!("BENCH,[Combiner] Compute Hats,{}", duration_compute_compute_hats.as_micros());

    // 4. Construct Final Sigma
    let start_construct_sigma = Instant::now();
    let sigma = combiner.construct_sigma(MESSAGE_BYTES)?;
    let duration_construct_sigma = start_construct_sigma.elapsed();
    println!("BENCH,[Combiner] Construct Sigma,{}", duration_construct_sigma.as_micros());

    println!("[Combiner] >> Final Sigma Constructed!");

    // --- Send to Tracer ---
    if let Some(stream) = tracer_stream.as_mut() {
        println!("[Combiner] Sending Result to Tracer...");
        let tracer_pkg = combiner.prepare_tracer_package(&sigma, &MESSAGE_BYTES);
        network::send(
            stream,
            &Message::Broadcast {
                identity_pk: combiner.identity_kp.pk.serialize().to_vec(),
                package: tracer_pkg,
            },
        )
        .await?;
    }

    println!("\n[Combiner] Protocol Finished Successfully.");
    Ok(())
}
