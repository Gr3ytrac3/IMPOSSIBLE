use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

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
    let progress_lock = Arc::new(Mutex::new(())); // Serialize progress output

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

                        if i - last_print >= 100_000 { // Increased interval for less contention
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