use simulation_taps::{
    authority::Authority,
    network::{self, Message, Role},
    crypto::TransportKeyPair,
};
use tokio::net::{TcpListener, TcpStream};
use secp256k1::PublicKey;
use std::error::Error;

const N_SIGNERS: usize = 3; // Let's start with 3 signers for simplicity
const PORT: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[Authority] Starting TAPS Setup Server on {}...", PORT);

    // 1. Initialize Cryptographic Authority
    let auth = Authority::new(N_SIGNERS);
    println!("[Authority] Generated Master Keys.");

    // 2. Start TCP Listener
    let listener = TcpListener::bind(PORT).await?;

    // We need to collect streams for: Signers (0..N), Combiner, Tracer
    let mut signers: Vec<Option<(TcpStream, PublicKey)>> = (0..N_SIGNERS)
        .map(|_| None)
        .collect();
    let mut combiner = None;
    let mut tracer = None;

    let expected_connections = N_SIGNERS + 2;
    let mut connected_count = 0;

    println!("[Authority] Waiting for {} actors to connect...", expected_connections);

    // 3. Connection Loop (Handshake)
    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Authority] Connection from {}", addr);

        // Receive "Hello" Handshake
        let msg = network::receive(&mut socket).await?;

        match msg {
            Message::Hello { id, role, pk } => {
                let pubkey = PublicKey::from_slice(&pk)?; // Deserialize their transport key

                match role {
                    Role::Signer => {
                        if id < N_SIGNERS {
                            println!("[Authority] Signer #{} Handshake Verified.", id);
                            signers[id] = Some((socket, pubkey));
                            connected_count += 1;
                        } else {
                            println!("[Authority] Signer ID {} is out of bounds!", id);
                        }
                    },
                    Role::Combiner => {
                        println!("[Authority] Combiner Handshake Verified.");
                        combiner = Some((socket, pubkey));
                        connected_count += 1;
                    },
                    Role::Tracer => {
                        println!("[Authority] Tracer Handshake Verified.");
                        tracer = Some((socket, pubkey));
                        connected_count += 1;
                    }
                }
            },
            _ => println!("[Authority] Unexpected message during handshake."),
        }
    }

    println!("\n[Authority] All actors connected! Distributing keys...\n");

    // 4. Distribution Phase

    // A. Send to Signers
    for (i, opt) in signers.iter_mut().enumerate() {
        if let Some((stream, pk)) = opt {
            // Prepare package
            let (pk, pkg) = auth.prepare_signer_package(i, pk);

            // Send
            network::send(stream, &Message::Secure {pk: pk.serialize().to_vec(), identity_pk: auth.identity_kp.pk.serialize().to_vec(), package: pkg }).await?;
            println!("[Authority] Sent SecurePackage to Signer #{}", i);
        }
    }

    // B. Send to Combiner (Requires Quorum)
    if let Some((stream, pk)) = combiner.as_mut() {
        let quorum = auth.keys.set_quorum(2); // Threshold t=2
        let (pk, pkg) = auth.prepare_combiner_package(quorum, N_SIGNERS, 2, pk);
        network::send(stream, &Message::Secure {pk: pk.serialize().to_vec(), identity_pk: auth.identity_kp.pk.serialize().to_vec(), package: pkg }).await?;
        println!("[Authority] Sent SecurePackage to Combiner");
    }

    // C. Send to Tracer
    if let Some((stream, pk)) = tracer.as_mut() {
        let (pk, pkg) = auth.prepare_tracer_package(pk);
        network::send(stream, &Message::Secure {pk: pk.serialize().to_vec(), identity_pk: auth.identity_kp.pk.serialize().to_vec(), package: pkg }).await?;
        println!("[Authority] Sent SecurePackage to Tracer");
    }

    println!("[Authority] Setup Complete. Shutting down.");
    Ok(())
}