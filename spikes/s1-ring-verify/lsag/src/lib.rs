//! Throwaway spike: LSAG (Liu, Wei, Wong 2004) over edwards25519 with a
//! scope-derived second generator. Written to measure verification cost,
//! not for use.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use sha2::{Digest, Sha512};

pub struct Signature {
    pub image: [u8; 32],
    pub c0: [u8; 32],
    pub responses: Vec<[u8; 32]>,
}

pub fn hash_to_point(scope: &[u8]) -> EdwardsPoint {
    let mut counter: u32 = 0;
    loop {
        let digest = Sha512::new()
            .chain_update(b"s1-spike/hash-to-point")
            .chain_update(scope)
            .chain_update(counter.to_le_bytes())
            .finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest[..32]);
        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            let cleared = point.mul_by_cofactor();
            if !cleared.is_identity() {
                return cleared;
            }
        }
        counter += 1;
    }
}

fn transcript(ring: &[[u8; 32]], image: &[u8; 32], scope: &[u8], message: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new()
        .chain_update(b"s1-spike/transcript")
        .chain_update((ring.len() as u32).to_le_bytes());
    for key in ring {
        hasher.update(key);
    }
    hasher.update(image);
    hasher.update((scope.len() as u32).to_le_bytes());
    hasher.update(scope);
    hasher.update(message);
    let mut out = [0u8; 64];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn challenge(transcript: &[u8; 64], l: &EdwardsPoint, r: &EdwardsPoint) -> Scalar {
    Scalar::from_hash(
        Sha512::new()
            .chain_update(b"s1-spike/challenge")
            .chain_update(transcript)
            .chain_update(l.compress().as_bytes())
            .chain_update(r.compress().as_bytes()),
    )
}

fn derived_scalar(secret: &Scalar, transcript: &[u8; 64], label: &[u8], index: u32) -> Scalar {
    Scalar::from_hash(
        Sha512::new()
            .chain_update(b"s1-spike/nonce")
            .chain_update(secret.as_bytes())
            .chain_update(transcript)
            .chain_update(label)
            .chain_update(index.to_le_bytes()),
    )
}

pub fn sign(
    secret: &Scalar,
    ring: &[[u8; 32]],
    signer_index: usize,
    scope: &[u8],
    message: &[u8],
) -> Option<Signature> {
    let n = ring.len();
    let points: Vec<EdwardsPoint> = ring
        .iter()
        .map(|key| CompressedEdwardsY(*key).decompress())
        .collect::<Option<_>>()?;
    let generator_h = hash_to_point(scope);
    let image_point = secret * generator_h;
    let image = image_point.compress().to_bytes();
    let transcript = transcript(ring, &image, scope, message);

    let alpha = derived_scalar(secret, &transcript, b"alpha", 0);
    let mut challenges = alloc::vec![Scalar::ZERO; n];
    let mut responses = alloc::vec![Scalar::ZERO; n];

    let mut index = (signer_index + 1) % n;
    challenges[index] = challenge(
        &transcript,
        &(alpha * ED25519_BASEPOINT_POINT),
        &(alpha * generator_h),
    );
    while index != signer_index {
        responses[index] = derived_scalar(secret, &transcript, b"response", index as u32);
        let l = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &challenges[index],
            &points[index],
            &responses[index],
        );
        let r = EdwardsPoint::vartime_multiscalar_mul(
            [responses[index], challenges[index]],
            [generator_h, image_point],
        );
        let next = (index + 1) % n;
        challenges[next] = challenge(&transcript, &l, &r);
        index = next;
    }
    responses[signer_index] = alpha - challenges[signer_index] * secret;

    Some(Signature {
        image,
        c0: challenges[0].to_bytes(),
        responses: responses.iter().map(Scalar::to_bytes).collect(),
    })
}

pub fn verify(ring: &[[u8; 32]], scope: &[u8], message: &[u8], signature: &Signature) -> bool {
    let n = ring.len();
    if n == 0 || signature.responses.len() != n {
        return false;
    }
    let Some(image_point) = CompressedEdwardsY(signature.image).decompress() else {
        return false;
    };
    if image_point.is_identity() || !image_point.is_torsion_free() {
        return false;
    }
    let Some(c0) = Option::<Scalar>::from(Scalar::from_canonical_bytes(signature.c0)) else {
        return false;
    };
    let generator_h = hash_to_point(scope);
    let transcript = transcript(ring, &signature.image, scope, message);

    let mut current = c0;
    for (key, response) in ring.iter().zip(&signature.responses) {
        let Some(point) = CompressedEdwardsY(*key).decompress() else {
            return false;
        };
        let Some(response) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*response))
        else {
            return false;
        };
        let l = EdwardsPoint::vartime_double_scalar_mul_basepoint(&current, &point, &response);
        let r = EdwardsPoint::vartime_multiscalar_mul(
            [response, current],
            [generator_h, image_point],
        );
        current = challenge(&transcript, &l, &r);
    }
    current == c0
}

pub fn encode(ring: &[[u8; 32]], scope: &[u8], message: &[u8], signature: &Signature) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(ring.len() as u32).to_le_bytes());
    for key in ring {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&signature.image);
    out.extend_from_slice(&signature.c0);
    for response in &signature.responses {
        out.extend_from_slice(response);
    }
    out.extend_from_slice(&(scope.len() as u32).to_le_bytes());
    out.extend_from_slice(scope);
    out.extend_from_slice(message);
    out
}

pub fn verify_encoded(input: &[u8]) -> bool {
    fn take<'a>(input: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
        if input.len() < len {
            return None;
        }
        let (head, tail) = input.split_at(len);
        *input = tail;
        Some(head)
    }
    fn take_u32(input: &mut &[u8]) -> Option<usize> {
        Some(u32::from_le_bytes(take(input, 4)?.try_into().ok()?) as usize)
    }
    fn take_keys(input: &mut &[u8], count: usize) -> Option<Vec<[u8; 32]>> {
        (0..count)
            .map(|_| take(input, 32)?.try_into().ok())
            .collect()
    }
    fn parse(mut input: &[u8]) -> Option<bool> {
        let n = take_u32(&mut input)?;
        let ring = take_keys(&mut input, n)?;
        let image = take(&mut input, 32)?.try_into().ok()?;
        let c0 = take(&mut input, 32)?.try_into().ok()?;
        let responses = take_keys(&mut input, n)?;
        let scope_len = take_u32(&mut input)?;
        let scope = take(&mut input, scope_len)?;
        Some(verify(
            &ring,
            scope,
            input,
            &Signature {
                image,
                c0,
                responses,
            },
        ))
    }
    parse(input).unwrap_or(false)
}
