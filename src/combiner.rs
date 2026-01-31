use taps::PublicKey;
use secp256k1::Scalar;

pub struct Combiner {
    pub n: usize,
    pub signer_pks: Vec<PublicKey>,
}

impl Combiner {
    pub fn new(pks: Vec<PublicKey>) -> Self {
        Combiner {
            n: pks.len(),
            signer_pks: pks,
        }
    }

    // 1. Aggregates R_i -> R
    pub fn aggregate_commitments(&self, commitments: &[PublicKey]) -> PublicKey {
        taps::aggregate_commitments(commitments).unwrap()
    }

    // 2. Aggregates z_i -> z (Only for attended signers)
    pub fn aggregate_signatures(&self, shares: &[Scalar], bits: &[u8]) -> Scalar {
        taps::aggregate_scalars(shares, bits)
    }
}