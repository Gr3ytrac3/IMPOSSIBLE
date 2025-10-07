use std::time::Instant;
use std::io::{self, Write};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use bcrypt::verify;
use hex;
use super::HashType;

pub fn index_to_candidate(mut index: u64, charset: &[u8], length: usize, buf: &mut Vec<u8>) -> String {
    buf.clear();
    let base = charset.len() as u64;
    for _ in 0..length {
        let pos = (index % base) as usize;
        buf.push(charset[pos]);
        index /= base;
    }
    // Removed buf.reverse() for standard base-N conversion
    String::from_utf8_lossy(buf).to_string()
}

pub fn compare_hash(candidate: &str, target: &str, hash_type: HashType) -> bool {
    match hash_type {
        HashType::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(candidate.as_bytes());
            let result = hasher.finalize();
            hex::encode(result) == target.to_lowercase()
        }
        HashType::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(candidate.as_bytes());
            let result = hasher.finalize();
            hex::encode(result) == target.to_lowercase()
        }
        HashType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(candidate.as_bytes());
            let result = hasher.finalize();
            hex::encode(result) == target.to_lowercase()
        }
        HashType::Bcrypt => {
            verify(candidate, target).unwrap_or(false)
        }
    }
}

pub fn print_progress(current: u64, total: u64, start: Instant) {
    let percentage = (current as f64 / total as f64) * 100.0;
    let elapsed = start.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 { current as f64 / elapsed } else { 0.0 };
    let remaining = if rate > 0.0 { (total - current) as f64 / rate } else { 0.0 };

    print!(
        "\rProgress: {:>6.2}% | Tried: {} / {} | ETA: {:.2}s",
        percentage, current, total, remaining
    );
    io::stdout().flush().unwrap();
}