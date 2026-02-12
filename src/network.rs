use serde::{Serialize, Deserialize};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use crate::crypto::{SecurePackage, BroadcastPackage};
use secp256k1::PublicKey;

/// The roles an actor can play in the system.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum Role {
    Signer,
    Combiner,
    Tracer,
}

/// The protocol messages exchanged over TCP.
#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    /// Sent by Actor -> Authority to join the network.
    Hello {
        id: usize,       // 0..n for Signers, 0 for others
        role: Role,
        pk: Vec<u8>      // Transport Public Key (serialized)
    },

    /// Sent by Authority -> Actor containing their encrypted keys.
    Welcome {
        pk: PublicKey,
        package: SecurePackage
    },

    Commitment {
        pk: PublicKey,
        package: SecurePackage
    },

    Sign {
        pk: PublicKey,
        package: SecurePackage
    },

    Broadcast {
        pk: PublicKey,
        package: BroadcastPackage
    }
}

/// Helper: Send a message with a 4-byte length header.
pub async fn send(stream: &mut TcpStream, msg: &Message) -> Result<(), Box<dyn Error>> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?; // 1. Write Length
    stream.write_all(&bytes).await?;             // 2. Write Payload
    stream.flush().await?;
    Ok(())
}

/// Helper: Receive a length-prefixed message.
pub async fn receive(stream: &mut TcpStream) -> Result<Message, Box<dyn Error>> {
    // 1. Read Length (4 bytes)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // 2. Read Payload
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    // 3. Deserialize
    let msg = bincode::deserialize(&buf)?;
    Ok(msg)
}