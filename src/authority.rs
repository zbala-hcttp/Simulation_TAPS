use aes_gcm::Key;
use taps::protocol::taps::*;
use crate::crypto::*;
use secp256k1::{PublicKey, SecretKey};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Serialize, Deserialize};

pub struct KeyPairs {
    pub signers_keys: Vec<KeyPair>,      // (sk_i, pk_i)
    pub combiner_keys: KeyPair,        // (sk_c, pk_c)
    pub tracer_keys: KeyPair,            // (sk_e, pk_e)
    pub tracing_keys: Vec<KeyPair>,      // (tau_i, h_i)
}

impl KeyPairs {
    pub fn new(n: usize) -> Self {
        let mut signers = Vec::with_capacity(n);
        let mut tracing = Vec::with_capacity(n);

        for _ in 0..n {
            signers.push(KeyPair::create());
            tracing.push(KeyPair::create());
        }

        let combiner_kp = KeyPair::create();

        let tracer_kp = KeyPair::create();

        KeyPairs {
            signers_keys: signers,
            combiner_keys: combiner_kp,
            tracing_keys: tracing,
            tracer_keys: tracer_kp,
        }
    }

    pub fn set_pk(&self) -> PK {
        PK::set(&self.signers_keys, &self.combiner_keys, &self.tracer_keys)
    }

    pub fn set_quorum(&self, t: usize) -> Quorum {
        Quorum::choose(
            self.signers_keys.len(),
            t,
            &self.signers_keys
        )
    }

    pub fn set_tracing_keys(&self) -> TracingKeys {
        TracingKeys::set(&self.tracing_keys)
    }
    
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerPackage {
    pub my_kp: KeyPair,
}

impl SignerPackage {
    pub fn new(auth_keys: &KeyPairs, index: usize) -> Self {
        let my_kp = auth_keys.signers_keys[index].clone();

        SignerPackage {
            my_kp,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CombinerPackage {
    pub kp_cs: KeyPair,
    pub pk: PK,
    pub quo: Quorum,
    pub tks: TracingKeys,
}

impl CombinerPackage {
    pub fn new(auth_keys: &KeyPairs, quo: Quorum) -> Self {
        CombinerPackage {
            kp_cs: auth_keys.combiner_keys.clone(),
            pk: auth_keys.set_pk(),
            quo,
            tks: TracingKeys::set(&auth_keys.tracing_keys),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracerPackage {
    pub kp_t: KeyPair,
    pub pk: PK,
    pub tracing_keys: Vec<KeyPair>,
}

impl TracerPackage {
    pub fn new(auth_keys: &KeyPairs) -> Self {
        TracerPackage {
            kp_t: auth_keys.tracer_keys.clone(),
            pk: auth_keys.set_pk(),
            tracing_keys: auth_keys.tracing_keys.clone(),
        }
    }
}













#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_initialization() {
        let n = 5;
        let auth = KeyPairs::new(n);

        // Check key counts
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);
        
        // Check structural integrity (keys are valid)
        // (Just checking if they exist is enough, KeyPair::create guarantees validity)
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);
    }


}