use secp256k1::PublicKey;
use simulation_taps::{
    authority::Authority,
    network::{self, Message, Role},
};
use std::env;
use std::error::Error;
use tokio::net::{TcpListener, TcpStream};

const PORT: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let args: Vec<String> = env::args().collect();
    let n = args.get(1).unwrap_or(&"6".to_string()).parse::<usize>().unwrap();
    let t = args.get(2).unwrap_or(&"4".to_string()).parse::<usize>().unwrap();

    println!("[Authority] Starting with N={} T={}...", n, t);
    println!("[Authority] Starting TAPS Setup Server on {}...", PORT);

    let auth = Authority::new(n);
    println!("[Authority] Generated Master Keys.");

    let listener = TcpListener::bind(PORT).await?;

    let mut signers: Vec<Option<(TcpStream, PublicKey)>> = (0..n).map(|_| None).collect();
    let mut combiner = None;
    let mut tracer = None;

    let expected_connections = n + 2;
    let mut connected_count = 0;

    println!(
        "[Authority] Waiting for {} actors to connect...",
        expected_connections
    );

    // 3. Connection Loop (Handshake)
    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Authority] Connection from {}", addr);

        // Receive "Hello" Handshake
        let msg = network::receive(&mut socket).await?;

        match msg {
            Message::Hello { id, role, pk } => {
                let pubkey = PublicKey::from_slice(&pk)?;

                match role {
                    Role::Signer => {
                        if id < n {
                            println!("[Authority] Signer #{} Handshake Verified.", id);
                            signers[id] = Some((socket, pubkey));
                            connected_count += 1;
                        } else {
                            println!("[Authority] Signer ID {} is out of bounds!", id);
                        }
                    }
                    Role::Combiner => {
                        println!("[Authority] Combiner Handshake Verified.");
                        combiner = Some((socket, pubkey));
                        connected_count += 1;
                    }
                    Role::Tracer => {
                        println!("[Authority] Tracer Handshake Verified.");
                        tracer = Some((socket, pubkey));
                        connected_count += 1;
                    }
                }
            }
            _ => println!("[Authority] Unexpected message during handshake."),
        }
    }

    println!("\n[Authority] All actors connected! Distributing keys...\n");

    for (i, opt) in signers.iter_mut().enumerate() {
        if let Some((stream, pk)) = opt {
            let pkg = auth.prepare_signer_package(i, pk);

            network::send(
                stream,
                &Message::Secure {
                    pk: auth.transport_kp.pk.serialize().to_vec(),
                    identity_pk: auth.identity_kp.pk.serialize().to_vec(),
                    package: pkg,
                },
            )
            .await?;
            println!("[Authority] Sent SecurePackage to Signer #{}", i);
        }
    }

    if let Some((stream, pk)) = combiner.as_mut() {
        let quorum = auth.keys.set_quorum(t);
        let pkg = auth.prepare_combiner_package(quorum, n, t, pk);
        network::send(
            stream,
            &Message::Secure {
                pk: auth.transport_kp.pk.serialize().to_vec(),
                identity_pk: auth.identity_kp.pk.serialize().to_vec(),
                package: pkg,
            },
        )
        .await?;
        println!("[Authority] Sent SecurePackage to Combiner");
    }

    if let Some((stream, pk)) = tracer.as_mut() {
        let pkg = auth.prepare_tracer_package(pk);
        network::send(
            stream,
            &Message::Secure {
                pk: auth.transport_kp.pk.serialize().to_vec(),
                identity_pk: auth.identity_kp.pk.serialize().to_vec(),
                package: pkg,
            },
        )
        .await?;
        println!("[Authority] Sent SecurePackage to Tracer");
    }

    println!("[Authority] Setup Complete. Shutting down.");
    Ok(())
}
