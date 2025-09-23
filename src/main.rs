use md5;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

fn index_to_candidate(mut index: u64, charset: &[u8], length: usize, buf: &mut Vec<u8>) -> String {
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

fn crack_md5(target: &str, charset: &[u8], min_len: usize, max_len: usize, num_threads: usize) -> Option<String> {
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));

    thread::scope(|s| {
        for _ in 0..num_threads {
            let target = target.to_string();
            let charset = charset.to_vec();
            let found = found.clone();
            let result = result.clone();

            s.spawn(move || {
                let mut buf = Vec::with_capacity(max_len);
                for length in min_len..=max_len {
                    let total: u64 = (charset.len() as u64).pow(length as u32);

                    for i in 0..total {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }

                        let candidate = index_to_candidate(i, &charset, length, &mut buf);
                        let hash = format!("{:x}", md5::compute(candidate.as_bytes()));

                        if hash == target {
                            found.store(true, Ordering::Relaxed);
                            *result.lock().unwrap() = Some(candidate);
                            return;
                        }
                    }
                }
            });
        }
    });

    result.lock().unwrap().clone()
}

fn main() {
    println!("Enter the target MD5 hash:");
    let mut target = String::new();
    io::stdin().read_line(&mut target).unwrap();
    let target = target.trim();

    println!("Enter the character set (e.g., abcdefghijklmnopqrstuvwxyz):");
    let mut charset_input = String::new();
    io::stdin().read_line(&mut charset_input).unwrap();
    let charset: Vec<u8> = charset_input.trim().bytes().collect();

    println!("Enter minimum password length:");
    let mut min_len = String::new();
    io::stdin().read_line(&mut min_len).unwrap();
    let min_len: usize = min_len.trim().parse().unwrap();

    println!("Enter maximum password length:");
    let mut max_len = String::new();
    io::stdin().read_line(&mut max_len).unwrap();
    let max_len: usize = max_len.trim().parse().unwrap();

    println!("Enter number of threads:");
    let mut num_threads = String::new();
    io::stdin().read_line(&mut num_threads).unwrap();
    let num_threads: usize = num_threads.trim().parse().unwrap();

    let start = Instant::now();
    match crack_md5(target, &charset, min_len, max_len, num_threads) {
        Some(pw) => println!("Found password: {}", pw),
        None => println!("Password not found."),
    }
    println!("Time taken: {:?}", start.elapsed());
}
