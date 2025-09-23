// src/helpers.rs

pub fn index_to_candidate(mut index: u64, charset: &[u8], length: usize, buf: &mut Vec<u8>) -> String {
    buf.clear();
    let base = charset.len() as u64;
    for _ in 0..length {
        let pos = (index % base) as usize;
        buf.push(charset[pos]);
        index /= base;
    }
    buf.reverse();
    String::from_utf8_lossy(buf).to_string()
}

pub fn compare_hash(candidate: &str, target: &str) -> bool {
    let hash_bytes = md5::compute(candidate.as_bytes());
    format!("{:x}", hash_bytes) == target
}
    