use md5;
use std::time::Instant;

fn index_to_candidate(mut index: u64, charset: &Vec<char>, length: usize) -> String {
    let base = charset.len() as u64;
    let mut chars = Vec::with_capacity(length);

    for _ in 0..length {
        let pos = (index % base) as usize;
        chars.push(charset[pos]);
        index /= base;
    }

    chars.into_iter().rev().collect()
}

fn crack_md5(target: &str, charset: &Vec<char>, min_len: usize, max_len: usize) -> Option<String> {
    for length in min_len..=max_len {
        let total: u64 = (charset.len() as u64).pow(length as u32);

        for i in 0..total {
            let candidate = index_to_candidate(i, charset, length);
            let hash = format!("{:x}", md5::compute(candidate.as_bytes()));

            if hash == target {
                return Some(candidate);
            }
        }
    }
    None
}

fn main() {
    let target = "5d41402abc4b2a76b9719d911017c592"; // "hello"
    let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();

    let start = Instant::now();
    match crack_md5(target, &charset, 1, 6) {
        Some(pw) => println!("Found password: {}", pw),
        None => println!("Password not found in given range."),
    }
    println!("Time taken: {:?}", start.elapsed());
}
