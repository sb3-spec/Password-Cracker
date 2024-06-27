use crypto::{digest::Digest, md5::Md5};
use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Instant;
struct PasswordCracker {
    charset: Vec<char>,
    current_password: Vec<usize>,
    length: usize,
    done: bool,    // Indicate if all passwords of length have been generated
    offset: usize, // Starting index in password space. Make sure each thread doesn't redo previous work
    stride: usize, // Steps to take in password space. Usually 1 unless you want to skip passwords
}

impl PasswordCracker {
    fn new(charset: Vec<char>, length: usize) -> Self {
        Self {
            charset: charset.to_vec(),
            current_password: vec![0; length],
            length,
            done: false,
            offset: 0,
            stride: 1,
        }
    }

    fn with_offset_and_stride(
        charset: &[char],
        length: usize,
        offset: usize,
        stride: usize,
    ) -> Self {
        let mut cracker = Self::new(charset.to_vec(), length);
        cracker.stride = stride;
        cracker.offset = offset;
        cracker.current_password[0] = offset;
        cracker
    }

    fn increment(&mut self) {
        for _ in 0..self.stride {
            let mut i = self.length - 1;
            loop {
                self.current_password[i] += 1;
                if self.current_password[i] < self.charset.len() {
                    break;
                }

                if i == 0 {
                    self.done = true;
                    break;
                }

                self.current_password[i] = 0;
                i -= 1;
            }
        }
    }
}

impl Iterator for PasswordCracker {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let password: String = self
            .current_password
            .iter()
            .map(|&index| self.charset[index])
            .collect();
        self.increment();
        Some(password)
    }
}

fn hash(password: &str) -> String {
    let mut hasher = Md5::new();
    hasher.input_str(password);
    hasher.result_str()
}

fn get_target_from_user() -> String {
    print!("Please enter a password to crack: ");
    io::stdout().flush().unwrap();

    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();

    password = password.trim().to_string();

    let password_hash = hash(&password);

    println!(
        "Solving for password {} with hash {}",
        password, password_hash
    );
    password_hash
}

fn main() {
    let target = get_target_from_user();
    let charset: Vec<char> = (32..127).map(|x| x as u8 as char).collect(); // All ASCII characters

    let target = Arc::new(target.to_string());
    let charset = Arc::new(charset);

    let num_threads = 4;
    // let password_found = Mutex::new(None);
    // let password_length = target.len();
    // let found_flag = AtomicBool::new(false);
    // let solving_thread = AtomicUsize::new(0);

    // let start = Instant::now();

    // let i = AtomicUsize::new(0);

    // std::thread::scope(|scope| {
    //     while i.load(Ordering::Relaxed) < num_threads {
    //         scope.spawn(|| {
    //             let mut cracker = PasswordCracker::with_offset_and_stride(
    //                 &charset,
    //                 password_length,
    //                 i.load(Ordering::Relaxed),
    //                 1,
    //             );
    //             while let Some(password) = cracker.next() {
    //                 if found_flag.load(Ordering::Relaxed) {
    //                     break;
    //                 }
    //                 if hash(&password) == *target {
    //                     let mut password_found = password_found.lock().unwrap();
    //                     *password_found = Some(password);
    //                     solving_thread.store(i.load(Ordering::Relaxed), Ordering::Relaxed);
    //                     found_flag.store(true, Ordering::Relaxed);
    //                 }
    //             }
    //         });
    //         i.fetch_add(1, Ordering::SeqCst);
    //     }
    // });

    // let duration = start.elapsed();

    // if found_flag.load(Ordering::Relaxed) {
    //     let password_found = password_found.lock().unwrap();
    //     match &*password_found {
    //         Some(password) => {
    //             println!(
    //                 "Found password: {password} in {duration:?} by thread {}",
    //                 solving_thread.load(Ordering::Relaxed)
    //             );
    //             return;
    //         }
    //         None => (),
    //     }
    // } else {
    //     println!("No password found for length {password_length} in {duration:?}");
    // }

    for password_length in 1.. {
        let password_found = Mutex::new(None);
        let found_flag = AtomicBool::new(false);
        let solving_thread = AtomicUsize::new(0);

        let start = Instant::now();

        let i = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            while i.load(Ordering::Relaxed) < num_threads {
                scope.spawn(|| {
                    let mut cracker = PasswordCracker::with_offset_and_stride(
                        &charset,
                        password_length,
                        i.load(Ordering::Relaxed),
                        1,
                    );
                    while let Some(password) = cracker.next() {
                        if found_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        if hash(&password) == *target {
                            let mut password_found = password_found.lock().unwrap();
                            *password_found = Some(password);
                            solving_thread.store(i.load(Ordering::Relaxed), Ordering::Relaxed);
                            found_flag.store(true, Ordering::Relaxed);
                        }
                    }
                });
                i.fetch_add(1, Ordering::SeqCst);
            }
        });

        let duration = start.elapsed();

        if found_flag.load(Ordering::Relaxed) {
            let password_found = password_found.lock().unwrap();
            match &*password_found {
                Some(password) => {
                    println!(
                        "Found password: {password} in {duration:?} by thread {}",
                        solving_thread.load(Ordering::Relaxed)
                    );
                    return;
                }
                None => (),
            }
        } else {
            println!("No password found for length {password_length} in {duration:?}");
        }
    }
}
