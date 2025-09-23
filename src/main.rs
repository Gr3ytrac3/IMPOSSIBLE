use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

mod helpers;
use helpers::{index_to_candidate, compare_hash};

fn crack_md5(target: &str, charset: &[u8], min_len: usize, max_len: usize, num_threads: usize) -> Option<String> {
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));

    for length in min_len..=max_len {
        let total: u64 = (charset.len() as u64).pow(length as u32);
        let chunk = (total + num_threads as u64 - 1) / num_threads as u64; // ceil division

        thread::scope(|s| {
            for thread_id in 0..num_threads {
                let start = thread_id as u64 * chunk;
                let end = std::cmp::min(start + chunk, total);

                let charset = charset.to_vec();
                let target = target.to_string();
                let found = found.clone();
                let result = result.clone();

                s.spawn(move || {
                    let mut buf = Vec::with_capacity(length);
                    for i in start..end {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }
                        let candidate = index_to_candidate(i, &charset, length, &mut buf);
                        if compare_hash(&candidate, &target) {
                            found.store(true, Ordering::Relaxed);
                            *result.lock().unwrap() = Some(candidate);
                            return;
                        }
                    }
                });
            }
        });

        if found.load(Ordering::Relaxed) {
            break; 
        }
    }

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
