//! Chaum-Pedersen NIZK proof that `log_G(B) == log_C(P)` for compliance key derivation.

use ark_ff::{BigInteger, PrimeField};
use ethers_core::types::U256;

use crate::bjj::{PublicKey, BASE8};
use crate::error::CryptoError;
use crate::field::{fr_to_u256, poseidon_hash, random_field, u256_to_fr};

/// BJJ scalar field type (native field arithmetic, zero heap allocation).
type BjjFr = ark_ed_on_bn254::Fr;

pub struct RawDleqProof {
    pub recipient_b: (U256, U256),
    pub recipient_p: (U256, U256),
    pub u: (U256, U256),
    pub v: (U256, U256),
    pub z: U256,
}

/// Generate a Chaum-Pedersen DLEQ NIZK proof that `log_G(B) == log_C(P)`.
pub fn generate_dleq_proof(
    recipient_sk: U256,
    compliance_pk: (U256, U256),
) -> Result<RawDleqProof, CryptoError> {
    let mut b_bytes_be = [0u8; 32];
    recipient_sk.to_big_endian(&mut b_bytes_be);
    let b_fr = BjjFr::from_be_bytes_mod_order(&b_bytes_be);
    let b_le = b_fr.into_bigint().to_bytes_le();

    // B = [b] * G
    let b_point = BASE8.mul_scalar(&b_le)?;
    let b_result = point_to_u256_pair(&b_point);

    // P = [b] * C
    let c_point =
        PublicKey::from_coordinates(u256_to_fr(compliance_pk.0), u256_to_fr(compliance_pk.1))?;
    let p_point = c_point.mul_scalar(&b_le)?;
    let p_result = point_to_u256_pair(&p_point);

    let r_fr = {
        let r_u256 = random_field();
        let mut r_bytes = [0u8; 32];
        r_u256.to_big_endian(&mut r_bytes);
        BjjFr::from_be_bytes_mod_order(&r_bytes)
    };
    let r_le = r_fr.into_bigint().to_bytes_le();

    // U = [r] * G
    let u_point = BASE8.mul_scalar(&r_le)?;
    let u_result = point_to_u256_pair(&u_point);

    // V = [r] * C
    let v_point = c_point.mul_scalar(&r_le)?;
    let v_result = point_to_u256_pair(&v_point);

    let g_x = fr_to_u256(BASE8.x());
    let g_y = fr_to_u256(BASE8.y());

    let e_u256 = poseidon_hash(&[
        u_result.0,
        u_result.1,
        v_result.0,
        v_result.1,
        g_x,
        g_y,
        compliance_pk.0,
        compliance_pk.1,
        b_result.0,
        b_result.1,
        p_result.0,
        p_result.1,
    ]);

    let mut e_bytes = [0u8; 32];
    e_u256.to_big_endian(&mut e_bytes);
    let e_fr = BjjFr::from_be_bytes_mod_order(&e_bytes);

    let z_fr = r_fr + e_fr * b_fr;
    let z_be = z_fr.into_bigint().to_bytes_be();
    let z_u256 = U256::from_big_endian(&z_be);

    Ok(RawDleqProof {
        recipient_b: b_result,
        recipient_p: p_result,
        u: u_result,
        v: v_result,
        z: z_u256,
    })
}

fn point_to_u256_pair(point: &PublicKey) -> (U256, U256) {
    (fr_to_u256(point.x()), fr_to_u256(point.y()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bjj::SecretKey;

    fn bjj_fr_to_le_bytes(fr: &BjjFr) -> Vec<u8> {
        fr.into_bigint().to_bytes_le()
    }

    #[test]
    fn test_dleq_proof_generation_and_verification() {
        let mut rng = rand::thread_rng();

        let compliance_sk = SecretKey::generate(&mut rng);
        let compliance_pk = compliance_sk.public_key().expect("compliance pk");
        let compliance_pk_tuple = (fr_to_u256(compliance_pk.x()), fr_to_u256(compliance_pk.y()));

        let recipient_sk_val = random_field();

        let proof = generate_dleq_proof(recipient_sk_val, compliance_pk_tuple)
            .expect("DLEQ proof generation should succeed");

        // Verify: [z]*G == U + [e]*B and [z]*C == V + [e]*P
        let g_x = fr_to_u256(BASE8.x());
        let g_y = fr_to_u256(BASE8.y());
        let e_u256 = poseidon_hash(&[
            proof.u.0,
            proof.u.1,
            proof.v.0,
            proof.v.1,
            g_x,
            g_y,
            compliance_pk_tuple.0,
            compliance_pk_tuple.1,
            proof.recipient_b.0,
            proof.recipient_b.1,
            proof.recipient_p.0,
            proof.recipient_p.1,
        ]);

        let mut e_bytes = [0u8; 32];
        e_u256.to_big_endian(&mut e_bytes);
        let e_fr = BjjFr::from_be_bytes_mod_order(&e_bytes);
        let e_le = bjj_fr_to_le_bytes(&e_fr);

        let mut z_bytes = [0u8; 32];
        proof.z.to_big_endian(&mut z_bytes);
        let z_fr = BjjFr::from_be_bytes_mod_order(&z_bytes);
        let z_le = bjj_fr_to_le_bytes(&z_fr);
        let z_g = BASE8.mul_scalar(&z_le).expect("[z]*G");
        let b_point = PublicKey::new_unchecked(
            u256_to_fr(proof.recipient_b.0),
            u256_to_fr(proof.recipient_b.1),
        );
        let e_b = b_point.mul_scalar(&e_le).expect("[e]*B");
        let u_point = PublicKey::new_unchecked(u256_to_fr(proof.u.0), u256_to_fr(proof.u.1));
        let u_plus_eb = u_point.add(&e_b).expect("U + [e]*B");
        assert_eq!(
            z_g.x(),
            u_plus_eb.x(),
            "DLEQ check 1 failed: [z]*G.x != (U + [e]*B).x"
        );
        assert_eq!(
            z_g.y(),
            u_plus_eb.y(),
            "DLEQ check 1 failed: [z]*G.y != (U + [e]*B).y"
        );

        let c_point = PublicKey::new_unchecked(
            u256_to_fr(compliance_pk_tuple.0),
            u256_to_fr(compliance_pk_tuple.1),
        );
        let z_c = c_point.mul_scalar(&z_le).expect("[z]*C");
        let p_point = PublicKey::new_unchecked(
            u256_to_fr(proof.recipient_p.0),
            u256_to_fr(proof.recipient_p.1),
        );
        let e_p = p_point.mul_scalar(&e_le).expect("[e]*P");
        let v_point = PublicKey::new_unchecked(u256_to_fr(proof.v.0), u256_to_fr(proof.v.1));
        let v_plus_ep = v_point.add(&e_p).expect("V + [e]*P");
        assert_eq!(
            z_c.x(),
            v_plus_ep.x(),
            "DLEQ check 2 failed: [z]*C.x != (V + [e]*P).x"
        );
        assert_eq!(
            z_c.y(),
            v_plus_ep.y(),
            "DLEQ check 2 failed: [z]*C.y != (V + [e]*P).y"
        );
    }

    #[test]
    fn test_dleq_wrong_witness_fails() {
        let mut rng = rand::thread_rng();

        let compliance_sk = SecretKey::generate(&mut rng);
        let compliance_pk = compliance_sk.public_key().expect("compliance pk");
        let compliance_pk_tuple = (fr_to_u256(compliance_pk.x()), fr_to_u256(compliance_pk.y()));

        let recipient_sk_val = random_field();
        let proof = generate_dleq_proof(recipient_sk_val, compliance_pk_tuple)
            .expect("proof generation must succeed");

        let tampered_z = proof.z + ethers_core::types::U256::from(1u64);
        let g_x = fr_to_u256(BASE8.x());
        let g_y = fr_to_u256(BASE8.y());
        let e_u256 = poseidon_hash(&[
            proof.u.0,
            proof.u.1,
            proof.v.0,
            proof.v.1,
            g_x,
            g_y,
            compliance_pk_tuple.0,
            compliance_pk_tuple.1,
            proof.recipient_b.0,
            proof.recipient_b.1,
            proof.recipient_p.0,
            proof.recipient_p.1,
        ]);

        let mut e_bytes = [0u8; 32];
        e_u256.to_big_endian(&mut e_bytes);
        let e_fr = BjjFr::from_be_bytes_mod_order(&e_bytes);
        let e_le = bjj_fr_to_le_bytes(&e_fr);

        let mut tz_bytes = [0u8; 32];
        tampered_z.to_big_endian(&mut tz_bytes);
        let tz_fr = BjjFr::from_be_bytes_mod_order(&tz_bytes);
        let tz_le = bjj_fr_to_le_bytes(&tz_fr);

        let zp_g = BASE8.mul_scalar(&tz_le).expect("[z']*G");
        let b_point = PublicKey::new_unchecked(
            u256_to_fr(proof.recipient_b.0),
            u256_to_fr(proof.recipient_b.1),
        );
        let e_b = b_point.mul_scalar(&e_le).expect("[e]*B");
        let u_point = PublicKey::new_unchecked(u256_to_fr(proof.u.0), u256_to_fr(proof.u.1));
        let u_plus_eb = u_point.add(&e_b).expect("U + [e]*B");

        assert!(
            zp_g.x() != u_plus_eb.x() || zp_g.y() != u_plus_eb.y(),
            "Tampered z must fail DLEQ verification -- soundness violation!"
        );
    }
}
