use std::io::{self, BufRead, BufReader};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

#[derive(Clone, Copy)]
enum HashType {
    Md5,
    Sha1,
    Sha256,
    Bcrypt,
}

impl HashType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "md5" => Some(HashType::Md5),
            "sha1" => Some(HashType::Sha1),
            "sha256" => Some(HashType::Sha256),
            "bcrypt" => Some(HashType::Bcrypt),
            _ => None,
        }
    }

    fn detect(hash: &str) -> Option<Self> {
        if hash.starts_with("$2a$") || hash.starts_with("$2y$") {
            return Some(HashType::Bcrypt);
        }
        match hash.len() {
            32 if hash.chars().all(|c| c.is_ascii_hexdigit()) => Some(HashType::Md5), // Could be SHA-1
            40 if hash.chars().all(|c| c.is_ascii_hexdigit()) => Some(HashType::Sha1),
            64 if hash.chars().all(|c| c.is_ascii_hexdigit()) => Some(HashType::Sha256),
            _ => None,
        }
    }
}

mod helpers {
    use super::HashType;
    use std::io::{self, Write};
    use std::time::Instant;
    use md5::compute as md5_compute;
    use sha1::Digest as Sha1Digest;
    use sha2::Sha256;
    use bcrypt;

    pub fn index_to_candidate(mut index: u64, charset: &[u8], length: usize, buf: &mut Vec<u8>) -> String {
        buf.clear();
        let base = charset.len() as u64;
        for _ in 0..length {
            let pos = (index % base) as usize;
            buf.push(charset[pos]);
            index /= base;
        }
        String::from_utf8_lossy(buf).to_string()
    }

    pub fn compare_hash(candidate: &str, target: &str, hash_type: HashType) -> bool {
        match hash_type {
            HashType::Md5 => {
                let hash = md5_compute(candidate.as_bytes());
                format!("{:x}", hash) == target.to_lowercase()
            }
            HashType::Sha1 => {
                let mut hasher = sha1::Sha1::new();
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
                bcrypt::verify(candidate, target).unwrap_or(false)
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
}

fn crack_hash_with_wordlist(target: &str, wordlist: &[String], hash_type: HashType) -> Option<String> {
    for word in wordlist {
        if helpers::compare_hash(word, target, hash_type) {
            return Some(word.clone());
        }
    }
    None
}

fn crack_hash(
    target: &str,
    charset: Arc<Vec<u8>>,
    min_len: usize,
    max_len: usize,
    num_threads: usize,
    hash_type: HashType,
) -> Option<String> {
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));
    let progress_lock = Arc::new(Mutex::new(()));

    for length in min_len..=max_len {
        let total: u64 = (charset.len() as u64).pow(length as u32);
        let chunk = (total + num_threads as u64 - 1) / num_threads as u64;
        let start_time = Instant::now();

        thread::scope(|s| {
            for thread_id in 0..num_threads {
                let start = thread_id as u64 * chunk;
                let end = std::cmp::min(start + chunk, total);

                let charset = charset.clone();
                let target = target.to_string();
                let found = found.clone();
                let result = result.clone();
                let progress_lock = progress_lock.clone();
                let hash_type = hash_type;

                s.spawn(move || {
                    let mut buf = Vec::with_capacity(length);
                    let mut last_print = start;

                    for i in start..end {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }

                        let candidate = helpers::index_to_candidate(i, &charset, length, &mut buf);
                        if helpers::compare_hash(&candidate, &target, hash_type) {
                            found.store(true, Ordering::Relaxed);
                            *result.lock().unwrap() = Some(candidate);
                            return;
                        }

                        if i - last_print >= 100_000 {
                            let _guard = progress_lock.lock().unwrap();
                            helpers::print_progress(i, total, start_time);
                            last_print = i;
                        }
                    }
                });
            }
        });

        if found.load(Ordering::Relaxed) {
            break;
        }
    }

    println!();
    result.lock().unwrap().clone()
}

fn main() {
    println!("Enter the target hash:");
    let mut target = String::new();
    io::stdin().read_line(&mut target).expect("Failed to read input");
    let target = target.trim();

    println!("Enter the hash type (md5, sha1, sha256, bcrypt, or 'auto' to detect):");
    let mut hash_type_input = String::new();
    io::stdin().read_line(&mut hash_type_input).expect("Failed to read input");
    let hash_type_input = hash_type_input.trim().to_lowercase();

    let hash_type = if hash_type_input == "auto" {
        HashType::detect(target).unwrap_or_else(|| {
            eprintln!("Could not detect hash type. Please specify (md5, sha1, sha256, bcrypt).");
            std::process::exit(1);
        })
    } else {
        HashType::from_str(&hash_type_input).unwrap_or_else(|| {
            eprintln!("Invalid hash type. Choose md5, sha1, sha256, or bcrypt.");
            std::process::exit(1);
        })
    };

    println!("Enter the character set (e.g., abcdefghijklmnopqrstuvwxyz, or press Enter for default):");
    let mut charset_input = String::new();
    io::stdin().read_line(&mut charset_input).expect("Failed to read input");
    let charset: Arc<Vec<u8>> = Arc::new(if charset_input.trim().is_empty() {
        b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec()
    } else {
        charset_input.trim().bytes().collect()
    });
    if charset.is_empty() {
        eprintln!("Character set cannot be empty.");
        return;
    }

    println!("Enter path to wordlist (or press Enter to skip):");
    let mut wordlist_path = String::new();
    io::stdin().read_line(&mut wordlist_path).expect("Failed to read input");
    let wordlist_path = wordlist_path.trim();

    println!("Enter minimum password length:");
    let mut min_len = String::new();
    io::stdin().read_line(&mut min_len).expect("Failed to read input");
    let min_len: usize = match min_len.trim().parse::<usize>() {
        Ok(num) if num > 0 => num,
        _ => {
            eprintln!("Invalid minimum length. Please enter a positive number.");
            return;
        }
    };

    println!("Enter maximum password length:");
    let mut max_len = String::new();
    io::stdin().read_line(&mut max_len).expect("Failed to read input");
    let max_len: usize = match max_len.trim().parse::<usize>() {
        Ok(num) if num >= min_len => num,
        _ => {
            eprintln!("Invalid maximum length. Must be >= minimum length.");
            return;
        }
    };

    println!("Enter number of threads:");
    let mut num_threads = String::new();
    io::stdin().read_line(&mut num_threads).expect("Failed to read input");
    let num_threads: usize = match num_threads.trim().parse::<usize>() {
        Ok(num) if num > 0 => num.min(thread::available_parallelism().unwrap().get()),
        _ => {
            eprintln!("Invalid number of threads. Please enter a positive number.");
            return;
        }
    };

    if matches!(hash_type, HashType::Bcrypt) {
        eprintln!("Warning: Bcrypt is slow to brute-force. A wordlist is recommended.");
    }

    let start = Instant::now();

    // Try wordlist first if provided
    if !wordlist_path.is_empty() {
        let file = match File::open(wordlist_path) {
            Ok(file) => file,
            Err(_) => {
                eprintln!("Failed to open wordlist: {}", wordlist_path);
                return;
            }
        };
        let wordlist: Vec<String> = BufReader::new(file)
            .lines()
            .filter_map(|line| line.ok())
            .collect();
        if let Some(pw) = crack_hash_with_wordlist(&target, &wordlist, hash_type) {
            println!("Found password (wordlist): {}", pw);
            println!("Time taken: {:?}", start.elapsed());
            return;
        }
        println!("Wordlist cracking failed, proceeding to brute-force...");
    }

    // Brute-force if wordlist fails or is not provided
    match crack_hash(&target, charset, min_len, max_len, num_threads, hash_type) {
        Some(pw) => println!("Found password: {}", pw),
        None => println!("Password not found."),
    }
    println!("Time taken: {:?}", start.elapsed());
}