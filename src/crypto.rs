//! Crypto primitives for N0NOS DAO CLI
//! eK@nonos-tech.xyz
//! This module provides oriented building blocks:
//! Versioned **AEAD** with key rotation (headered format), HKDF subkeys by purpose, optional XChaCha20.
//! EVM signatures: **EIP-191 personal_sign** and **EIP-712** (digest-based) with **RSV recovery**.
//! Solana (ed25519) signatures (hex pubkey only).
//! Domain-separated **vote digest** helper.
//! Back-compat wrappers for legacy call sites.
//!
//! Env
//! ----
//! - `N0NOS_ENC_KEYS`: comma-separated list of 32-byte hex master keys (first is active).
//! - `N0NOS_ENC_KEY` : fallback single 32-byte hex key.
//! - `N0NOS_SIGNER_EVM_PK`: hex secp256k1 private key.
//! - `N0NOS_SIGNER_EVM_ADDR` (optional): expected 0x-address for sanity checks.
//! - `N0NOS_SIGNER_SOL_KP`: path to Solana JSON keypair file (array of 64 numbers/bytes).
//! - `N0NOS_SIGNER_SOL_PUB` (optional): hex-encoded 32-byte ed25519 public key.

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
#[cfg(feature = "xchacha20poly1305")]
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek as ed25519;
use ed25519::{Keypair as Ed25519Keypair, PublicKey as Ed25519Pub, SecretKey as Ed25519Secret, Signature as Ed25519Sig, Signer as _, Verifier as _};
use hkdf::Hkdf;
use k256::{
    ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature as K256Signature, SigningKey, VerifyingKey,
    },
    ecdsa::recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
    SecretKey,
};
use secrecy::SecretVec;
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
use zeroize::Zeroize;

// for randomness
use getrandom::getrandom;

// keccak
use ethers::utils::keccak256;

// json
use serde_json;

// ---------- constants / types ----------
const MAGIC: &[u8; 5] = b"N0ENC";
const VERSION: u8 = 1;
const ALG_CHACHA20: u8 = 1;
const ALG_XCHACHA20: u8 = 2; // requires feature

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    ChaCha20,
    XChaCha20,
}

#[derive(Debug)]
struct KeyEntry {
    kid: [u8; 4],
    master: SecretVec<u8>,
}

// ---------- public API (encryption) ----------

/// Encrypt with headered format; `purpose` binds HKDF subkey; `aad` protects header too.
/// If `alg` is None, prefer XChaCha20 when compiled; otherwise ChaCha20.
pub fn encrypt_with_header(
    purpose: &str,
    aad: Option<&[u8]>,
    alg: Option<AeadAlg>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let keys = load_master_keys()?;
    if keys.is_empty() {
        bail!("no encryption keys configured");
    }
    let key0 = &keys[0]; // active key

    // pick algorithm
    let use_alg = match alg {
        Some(AeadAlg::ChaCha20) => ALG_CHACHA20,
        Some(AeadAlg::XChaCha20) => ALG_XCHACHA20,
        None => {
            #[cfg(feature = "xchacha20poly1305")]
            { ALG_XCHACHA20 }
            #[cfg(not(feature = "xchacha20poly1305"))]
            { ALG_CHACHA20 }
        }
    };

    // derive subkey (SecretVec zeroizes on drop)
    let mut subkey = derive_aead_subkey(&key0.master, purpose)?; // 32 bytes

    // assemble fixed header (without nonce)
    let mut header = Vec::with_capacity(5 + 1 + 1 + 4 + 1);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(use_alg);
    header.extend_from_slice(&key0.kid);

    // seal
    let mut out = Vec::new();
    match use_alg {
        ALG_CHACHA20 => {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey.expose_secret()));
            let mut nonce_bytes = [0u8; 12];
            getrandom(&mut nonce_bytes)?;
            header.push(12u8);
            out.extend_from_slice(&header);
            out.extend_from_slice(&nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let aad_full = aad_concat(aad, &header);
            let ct = cipher
                .encrypt(nonce, Payload { msg: plaintext, aad: &aad_full })
                .map_err(|_| anyhow!("encryption failed"))?;
            out.extend_from_slice(&ct);
        }
        ALG_XCHACHA20 => {
            #[cfg(feature = "xchacha20poly1305")]
            {
                let cipher = XChaCha20Poly1305::new(Key::from_slice(subkey.expose_secret()));
                let mut nonce_bytes = [0u8; 24];
                getrandom(&mut nonce_bytes)?;
                header.push(24u8);
                out.extend_from_slice(&header);
                out.extend_from_slice(&nonce_bytes);
                let nonce = XNonce::from_slice(&nonce_bytes);
                let aad_full = aad_concat(aad, &header);
                let ct = cipher
                    .encrypt(nonce, Payload { msg: plaintext, aad: &aad_full })
                    .map_err(|_| anyhow!("encryption failed"))?;
                out.extend_from_slice(&ct);
            }
            #[cfg(not(feature = "xchacha20poly1305"))]
            { bail!("XChaCha20 requested but feature not enabled"); }
        }
        _ => bail!("unsupported algorithm id"),
    }

    // explicit wipe (also happens on drop, belt + suspenders)
    subkey.expose_secret_mut().zeroize();

    Ok(out)
}

/// Decrypt headered ciphertext. Caller must provide the same `purpose` and `aad`.
pub fn decrypt_with_header(purpose: &str, aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 { bail!("ciphertext too short"); }

    // parse fixed header
    let (magic, rest) = ciphertext.split_at(5); if magic != MAGIC { bail!("bad magic" ); }
    let (ver, rest)   = rest.split_first().ok_or_else(|| anyhow!("truncated"))?; if *ver != VERSION { bail!("bad version" ); }
    let (alg, rest)   = rest.split_first().ok_or_else(|| anyhow!("truncated"))?; let alg = *alg;
    let (kid, rest)   = rest.split_at(4); let mut kid_arr=[0u8;4]; kid_arr.copy_from_slice(kid);
    let (nlen_b, rest)= rest.split_first().ok_or_else(|| anyhow!("truncated"))?; let nlen=*nlen_b as usize;
    let (nonce_bytes, ct) = rest.split_at(nlen);

    // load matching key
    let keys = load_master_keys()?;
    let key = keys.into_iter().find(|k| k.kid == kid_arr)
        .ok_or_else(|| anyhow!("unknown key id {}", hex::encode(kid_arr)))?;
    let mut subkey = derive_aead_subkey(&key.master, purpose)?;

    // reconstruct header for AAD
    let mut aad_hdr = Vec::with_capacity(5+1+1+4+1);
    aad_hdr.extend_from_slice(MAGIC);
    aad_hdr.push(VERSION);
    aad_hdr.push(alg);
    aad_hdr.extend_from_slice(&kid_arr);
    aad_hdr.push(nlen as u8);
    let aad_full = aad_concat(aad, &aad_hdr);

    let res = match alg {
        ALG_CHACHA20 => {
            if nlen != 12 { bail!("bad nonce length for ChaCha20"); }
            let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey.expose_secret()));
            let nonce = Nonce::from_slice(nonce_bytes);
            cipher.decrypt(nonce, Payload { msg: ct, aad: &aad_full }).map_err(|_| anyhow!("decryption failed"))
        }
        ALG_XCHACHA20 => {
            #[cfg(feature = "xchacha20poly1305")]
            {
                if nlen != 24 { bail!("bad nonce length for XChaCha20"); }
                let cipher = XChaCha20Poly1305::new(Key::from_slice(subkey.expose_secret()));
                let nonce = XNonce::from_slice(nonce_bytes);
                cipher.decrypt(nonce, Payload { msg: ct, aad: &aad_full }).map_err(|_| anyhow!("decryption failed"))
            }
            #[cfg(not(feature = "xchacha20poly1305"))]
            { bail!("ciphertext requires XChaCha20 but feature not enabled"); }
        }
        _ => bail!("unsupported algorithm id"),
    };

    // explicit wipe
    subkey.expose_secret_mut().zeroize();

    res
}

/// Back-compat symmetric helpers (no explicit purpose/AAD in API).
/// Internally uses headered format with purpose = "ballot:v1".
pub fn encrypt_data(plaintext: &[u8]) -> Result<Vec<u8>> { encrypt_with_header("ballot:v1", None, None, plaintext) }
pub fn decrypt_data(data: &[u8]) -> Result<Vec<u8>> { decrypt_with_header("ballot:v1", None, data) }

// ---------- public API (EVM signatures) ----------

/// EIP-191 personal_sign ("\x19Ethereum Signed Message:\nlen" || message) -> `evm_rsv:<hex>`
pub fn evm_personal_sign(message: &[u8]) -> Result<String> {
    let sk = load_evm_privkey()?;
    let digest = keccak256(&eth_personal_prefix(message));
    let rec = sk.sign_prehash_recoverable(&digest).map_err(|_| anyhow!("secp256k1 sign failed"))?;
    Ok(format!("evm_rsv:{}", hex::encode(rec_to_rsv(&rec))))
}

pub fn evm_personal_verify(message: &[u8], rsv_hex: &str, expected_addr: &str) -> Result<bool> {
    let digest = keccak256(&eth_personal_prefix(message));
    verify_evm_sig_against(&digest, rsv_hex, expected_addr)
}

/// Recover the address from a personal_sign RSV signature and message.
pub fn evm_personal_recover(message: &[u8], rsv_hex: &str) -> Result<String> {
    let digest = keccak256(&eth_personal_prefix(message));
    evm_recover_address_from_hash(&digest, rsv_hex)
}

/// EIP-712 digest form. If have `DOMAIN_SEPARATOR` and `struct_hash`, should use this.
pub fn evm_sign_712(domain_separator: [u8;32], struct_hash: [u8;32]) -> Result<String> {
    let sk = load_evm_privkey()?;
    let mut blob = [0u8; 66];
    blob[0] = 0x19; blob[1] = 0x01;
    blob[2..34].copy_from_slice(&domain_separator);
    blob[34..66].copy_from_slice(&struct_hash);
    let digest = keccak256(&blob);
    let rec = sk.sign_prehash_recoverable(&digest).map_err(|_| anyhow!("secp256k1 sign failed"))?;
    Ok(format!("evm_rsv:{}", hex::encode(rec_to_rsv(&rec))))
}

pub fn evm_verify_712(domain_separator: [u8;32], struct_hash: [u8;32], rsv_hex: &str, expected_addr: &str) -> Result<bool> {
    let mut blob = [0u8; 66];
    blob[0] = 0x19; blob[1] = 0x01;
    blob[2..34].copy_from_slice(&domain_separator);
    blob[34..66].copy_from_slice(&struct_hash);
    let digest = keccak256(&blob);
    verify_evm_sig_against(&digest, rsv_hex, expected_addr)
}

/// Recover address from a 32-byte message hash and RSV signature.
pub fn evm_recover_address_from_hash(message_hash32: &[u8], rsv_hex: &str) -> Result<String> {
    if message_hash32.len() != 32 { bail!("message_hash must be 32 bytes"); }
    let mut rsv = hex::decode(rsv_hex.trim_start_matches("0x")).context("invalid hex for EVM RSV signature")?;
    if rsv.len() != 65 { bail!("RSV signature must be 65 bytes"); }
    rsv[64] = norm_v(rsv[64]);
    let rec = RecoverableSignature::from_bytes(&rsv[..64], RecoveryId::from_byte(rsv[64]).map_err(|_| anyhow!("invalid recovery id"))?)
        .map_err(|_| anyhow!("invalid recoverable signature bytes"))?;
    let vk = rec.recover_verifying_key(message_hash32).map_err(|_| anyhow!("failed to recover public key"))?;
    Ok(evm_address_from_vk(&vk))
}

/// Verify an EVM recoverable signature (RSV hex) against an expected EVM address (0x...).
pub fn verify_evm_sig_against(message_hash32: &[u8], rsv_hex: &str, expected_addr: &str) -> Result<bool> {
    if message_hash32.len() != 32 { bail!("message_hash must be 32 bytes"); }
    let mut rsv = hex::decode(rsv_hex.trim_start_matches("0x")).context("invalid hex for EVM RSV signature")?;
    if rsv.len() != 65 { return Ok(false); }
    rsv[64] = norm_v(rsv[64]);
    let rec = RecoverableSignature::from_bytes(&rsv[..64], RecoveryId::from_byte(rsv[64]).map_err(|_| anyhow!("invalid recovery id"))?)
        .map_err(|_| anyhow!("invalid recoverable signature bytes"))?;
    let vk = rec.recover_verifying_key(message_hash32).map_err(|_| anyhow!("failed to recover public key"))?;
    let addr = evm_address_from_vk(&vk).to_lowercase();
    Ok(addr == expected_addr.to_lowercase())
}

/// Legacy verifier kept for compatibility with existing call sites.
/// Supports: `evm_rsv:<hex>`, `evm:<DER-hex>`, `ed25519:<hex>`.
#[deprecated(note = "use specific verify_* or recover helpers; this API is ambiguous")]
pub fn verify_signature(message_hash: &[u8], signature: &str) -> bool {
    if let Some(rest) = signature.strip_prefix("evm_rsv:") {
        if let Some(exp) = load_evm_expected_addr() {
            return verify_evm_sig_against(message_hash, rest, &exp).unwrap_or(false);
        }
        let mut rsv = match hex::decode(rest) { Ok(b) => b, Err(_) => return false };
        if rsv.len() != 65 { return false; }
        rsv[64] = norm_v(rsv[64]);
        let rec = match RecoverableSignature::from_bytes(&rsv[..64], RecoveryId::from_byte(rsv[64]).ok()?) { Ok(x) => x, Err(_) => return false };
        return rec.recover_verifying_key(message_hash).is_ok();
    }
    if let Some(rest) = signature.strip_prefix("evm:") {
        let der: Vec<u8> = match hex::decode(rest) { Ok(b) => b, Err(_) => return false };
        let sig = match K256Signature::from_der(&der) { Ok(s) => s, Err(_) => return false };
        // Reject non-canonical (high-S) signatures
        if sig.normalize_s().is_some() { return false; }
        if let Ok(sk) = load_evm_privkey() {
            let vk = VerifyingKey::from(&sk);
            if let Some(exp) = load_evm_expected_addr() { if evm_address_from_vk(&vk).to_lowercase() != exp { return false; } }
            return vk.verify_prehash(message_hash, &sig).is_ok();
        }
        return false;
    }
    if let Some(rest) = signature.strip_prefix("ed25519:") {
        let bytes: Vec<u8> = match hex::decode(rest) { Ok(b) => b, Err(_) => return false };
        let sig = match Ed25519Sig::from_bytes(&bytes) { Ok(s) => s, Err(_) => return false };
        let pubkey = if let Some(p) = load_solana_expected_pub() { p } else if let Ok(kp) = load_solana_keypair() { kp.public } else { return false };
        return pubkey.verify(message_hash, &sig).is_ok();
    }
    false
}

// ---------- public API (Solana signatures) ----------

pub fn ed25519_sign(message_hash32: &[u8]) -> Result<String> {
    if message_hash32.len() != 32 { bail!("message_hash must be 32 bytes"); }
    let kp = load_solana_keypair()?;
    let sig: Ed25519Sig = kp.sign(message_hash32);
    Ok(format!("ed25519:{}", hex::encode(sig.to_bytes())))
}

pub fn verify_ed25519_against(message_hash32: &[u8], sig_hex: &str, expected_pub_hex: &str) -> Result<bool> {
    if message_hash32.len() != 32 { bail!("message_hash must be 32 bytes"); }
    let sig_bytes = hex::decode(sig_hex).context("invalid hex for ed25519 signature")?;
    let sig = Ed25519Sig::from_bytes(&sig_bytes).map_err(|_| anyhow!("invalid ed25519 signature"))?;
    let pub_bytes = hex::decode(expected_pub_hex.trim_start_matches("0x")).context("expected_pub must be hex")?;
    if pub_bytes.len() != 32 { bail!("ed25519 public key must be 32 bytes"); }
    let pubkey = Ed25519Pub::from_bytes(&pub_bytes).map_err(|_| anyhow!("invalid ed25519 public key"))?;
    Ok(pubkey.verify(message_hash32, &sig).is_ok())
}

// ---------- public API (vote digest) ----------

/// Canonical, domain-separated vote digest (SHA-256) with length-prefixing.
#[allow(clippy::too_many_arguments)]
pub fn vote_digest(
    proposal_id: &str,
    merkle_root_hex: &str,
    chain_id: u64,
    voter_identity: &str, // e.g., "evm:0x..." or "sol:hex..."
    choice: &str,
    weight: u128,
    window_start_unix: i64,
    window_end_unix: i64,
    ballot_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(b"N0NOS-VOTE\x00v1\x00");
    put_str(&mut s, proposal_id);
    put_hex(&mut s, merkle_root_hex);
    put_u64(&mut s, chain_id);
    put_str(&mut s, voter_identity);
    put_str(&mut s, choice);
    put_u128(&mut s, weight);
    put_i64(&mut s, window_start_unix);
    put_i64(&mut s, window_end_unix);
    s.update(ballot_nonce);
    let out = s.finalize();
    let mut arr = [0u8; 32]; arr.copy_from_slice(&out); arr
}

// ---------- legacy sign entrypoints ----------

pub fn sign_data(message_hash32: &[u8]) -> String { match try_sign_data(message_hash32) { Ok(s) => s, Err(e) => panic!("No signer configured: {e}") } }

pub fn try_sign_data(message_hash32: &[u8]) -> Result<String> {
    if env::var("N0NOS_SIGNER_EVM_PK").is_ok() {
        let sk = load_evm_privkey()?;
        let sig: K256Signature = sk.sign_prehash(message_hash32).map_err(|_| anyhow!("secp256k1 prehash sign failed"))?;
        // Reject non-canonical (high-S) just in case
        if sig.normalize_s().is_some() { bail!("non-canonical ECDSA signature (high-S)"); }
        return Ok(format!("evm:{}", hex::encode(sig.to_der())));
    }
    if env::var("N0NOS_SIGNER_SOL_KP").is_ok() {
        let kp = load_solana_keypair()?;
        let sig: Ed25519Sig = kp.sign(message_hash32);
        return Ok(format!("ed25519:{}", hex::encode(sig.to_bytes())));
    }
    bail!("Set N0NOS_SIGNER_EVM_PK or N0NOS_SIGNER_SOL_KP to sign")
}

/// Sign a purpose string as SHA-256 prehash (legacy compat)
pub fn sign_chain_message(_wallet_path: &Path, purpose: &str) -> Result<String> {
    let msg_hash = Sha256::digest(purpose.as_bytes());
    try_sign_data(&msg_hash)
}

// ---------- helpers ----------

fn eth_personal_prefix(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 32 + message.len());
    out.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    out.extend_from_slice(message.len().to_string().as_bytes());
    out.extend_from_slice(message);
    out
}

fn rec_to_rsv(rec: &RecoverableSignature) -> [u8;65] {
    let (sig, rid) = (rec.to_bytes(), rec.recovery_id());
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig);
    out[64] = rid.to_byte();
    out
}

fn norm_v(v: u8) -> u8 {
    if v == 27 || v == 28 { v - 27 }
    else if v >= 35 { ((v - 35) % 2) }
    else { v }
}

fn evm_address_from_vk(vk: &VerifyingKey) -> String {
    let uncompressed = vk.to_encoded_point(false); // 0x04 || X || Y
    let bytes = uncompressed.as_bytes();
    let h = keccak256(&bytes[1..]);
    let addr = &h[12..]; // last 20 bytes
    format!("0x{}", hex::encode(addr))
}

fn derive_aead_subkey(master: &SecretVec<u8>, purpose: &str) -> Result<SecretVec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(purpose.as_bytes()), master.expose_secret());
    let mut okm = SecretVec::new(vec![0u8; 32]);
    hk.expand(b"N0NOS/aead/v1", okm.expose_secret_mut()).map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

fn aad_concat(aad_opt: Option<&[u8]>, header: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(header.len() + aad_opt.map(|a| a.len()).unwrap_or(0));
    v.extend_from_slice(header);
    if let Some(a) = aad_opt { v.extend_from_slice(a); }
    v
}

fn load_master_keys() -> Result<Vec<KeyEntry>> {
    let mut keys_hex: Vec<String> = vec![];
    if let Ok(kset) = env::var("N0NOS_ENC_KEYS") { keys_hex.extend(kset.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())); }
    // If both are set, prefer N0NOS_ENC_KEYS and ignore N0NOS_ENC_KEY
    if keys_hex.is_empty() { if let Ok(single) = env::var("N0NOS_ENC_KEY") { keys_hex.push(single); } }

    let mut out = Vec::new();
    for hexk in keys_hex {
        let kb = hex::decode(hexk.trim()).context("invalid hex in encryption key")?;
        if kb.len() != 32 { bail!("encryption master key must be 32 bytes"); }
        let mut hasher = Sha256::new(); hasher.update(&kb); hasher.update(b"kid:v1");
        let kid_full = hasher.finalize();
        let mut kid = [0u8;4]; kid.copy_from_slice(&kid_full[..4]);
        out.push(KeyEntry { kid, master: SecretVec::new(kb) });
    }
    Ok(out)
}

fn load_evm_privkey() -> Result<SigningKey> {
    let pk_hex = env::var("N0NOS_SIGNER_EVM_PK").context("N0NOS_SIGNER_EVM_PK not set (hex secp256k1 privkey)")?;
    let raw: Vec<u8> = hex::decode(pk_hex.trim_start_matches("0x")).context("invalid hex in N0NOS_SIGNER_EVM_PK")?;
    if raw.len() != 32 { bail!("EVM private key must be exactly 32 bytes"); }
    let mut arr = [0u8; 32]; arr.copy_from_slice(&raw);
    let secret = SecretKey::from_slice(&arr).map_err(|_| anyhow!("invalid secp256k1 scalar"))?;
    arr.zeroize();
    Ok(SigningKey::from(secret))
}

fn load_evm_expected_addr() -> Option<String> { env::var("N0NOS_SIGNER_EVM_ADDR").ok().map(|s| s.to_lowercase()) }

fn load_solana_keypair() -> Result<Ed25519Keypair> {
    let path = env::var("N0NOS_SIGNER_SOL_KP").context("N0NOS_SIGNER_SOL_KP not set (path to Solana keypair JSON)")?;
    let raw = fs::read_to_string(&path).with_context(|| format!("reading Solana keypair at {path}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw).context("parsing Solana keypair JSON")?;
    if bytes.len() != 64 { bail!("invalid Solana keypair json (expect 64 bytes)"); }
    let secret = Ed25519Secret::from_bytes(&bytes[..32])?;
    let public = Ed25519Pub::from(&secret);
    Ok(Ed25519Keypair { secret, public })
}

fn load_solana_expected_pub() -> Option<Ed25519Pub> {
    env::var("N0NOS_SIGNER_SOL_PUB").ok().and_then(|hexs| {
        hex::decode(hexs.trim_start_matches("0x")).ok().and_then(|v| if v.len()==32 { Ed25519Pub::from_bytes(&v).ok() } else { None })
    })
}

fn put_u64(s: &mut Sha256, v: u64) { s.update(&v.to_be_bytes()); }
fn put_u128(s: &mut Sha256, v: u128) { s.update(&v.to_be_bytes()); }
fn put_i64(s: &mut Sha256, v: i64) { s.update(&v.to_be_bytes()); }
fn put_str(s: &mut Sha256, v: &str) { let b = v.as_bytes(); s.update(&(b.len() as u64).to_be_bytes()); s.update(b); }
fn put_hex(s: &mut Sha256, v: &str) { let b = hex::decode(v.trim_start_matches("0x")).unwrap_or_default(); s.update(&(b.len() as u64).to_be_bytes()); s.update(&b); }

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer; // only in tests
    use rand_core::OsRng;

    fn with_test_key() { std::env::set_var("N0NOS_ENC_KEYS", hex::encode([7u8; 32])); }

    #[test]
    fn header_roundtrip_chacha() {
        with_test_key();
        let aad = b"hdr"; let pt = b"secret payload";
        let ct = encrypt_with_header("test:v1", Some(aad), Some(AeadAlg::ChaCha20), pt).unwrap();
        let back = decrypt_with_header("test:v1", Some(aad), &ct).unwrap();
        assert_eq!(pt.to_vec(), back);
    }

    #[test]
    fn header_tamper_fails() {
        with_test_key();
        let ct = encrypt_with_header("test:v1", None, Some(AeadAlg::ChaCha20), b"x").unwrap();
        // flip ALG byte in header (at index 5+1=6)
        let mut tampered = ct.clone();
        tampered[6] ^= 0x01;
        assert!(decrypt_with_header("test:v1", None, &tampered).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        with_test_key();
        let ct = encrypt_with_header("test:v1", Some(b"A"), Some(AeadAlg::ChaCha20), b"x").unwrap();
        assert!(decrypt_with_header("test:v1", Some(b"B"), &ct).is_err());
    }

    #[test]
    fn evm_personal_recover_and_v_norm() {
        // random EVM key
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let addr = super::evm_address_from_vk(&vk);
        // temporarily set env key for signing helpers
        std::env::set_var("N0NOS_SIGNER_EVM_PK", hex::encode(sk.to_bytes()));
        let msg = b"hello";
        let sig = evm_personal_sign(msg).unwrap();
        // Verify normally
        assert!(evm_personal_verify(msg, sig.trim_start_matches("evm_rsv:"), &addr).unwrap());
        // Force v=27 and verify still passes due to normalization
        let mut raw = hex::decode(sig.trim_start_matches("evm_rsv:")).unwrap();
        raw[64] = 27;
        assert!(evm_personal_verify(msg, &hex::encode(raw), &addr).unwrap());
    }

    #[test]
    fn vote_digest_is_stable() {
        let d1 = vote_digest("p1","abcd",1,"evm:0x1","YES",1,0,10,&[0u8;16]);
        let d2 = vote_digest("p1","abcd",1,"evm:0x1","YES",1,0,10,&[0u8;16]);
        assert_eq!(d1, d2);
    }
}
