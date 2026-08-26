// qr_login_manager.rs
use clap::{App, Arg};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use qrcode::QrCode;
use image::Luma;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const ITERATIONS: u32 = 100_000;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    use ring::pbkdf2;
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), data)?;
    let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(encrypted: &[u8], password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN {
        return Err("Invalid encrypted data".into());
    }
    let salt = &encrypted[..SALT_LEN];
    let nonce = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];
    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;
    Ok(plaintext)
}

#[derive(Serialize, Deserialize)]
struct BackupData {
    created: String,
    codes: Vec<String>,
}

fn generate_codes(count: usize, length: usize) -> Vec<String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut code = String::with_capacity(length);
        for _ in 0..length {
            let idx = rng.next_u32() as usize % CHARS.len();
            code.push(CHARS[idx] as char);
        }
        codes.push(code);
    }
    codes
}

fn save_to_file(data: &BackupData, password: &str, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(data)?;
    let enc = encrypt_data(&json, password)?;
    fs::write(filename, enc)?;
    println!("Saved encrypted backup to {}", filename);
    Ok(())
}

fn load_from_file(filename: &str, password: &str) -> Result<BackupData, Box<dyn std::error::Error>> {
    let enc = fs::read(filename)?;
    let plain = decrypt_data(&enc, password)?;
    let data: BackupData = serde_json::from_slice(&plain)?;
    Ok(data)
}

fn list_codes(filename: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = load_from_file(filename, password)?;
    println!("Backup: {}", filename);
    println!("Created: {}", data.created);
    println!("Codes:");
    for code in data.codes {
        println!("  {}", code);
    }
    Ok(())
}

fn generate_qr(filename: &str, password: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = load_from_file(filename, password)?;
    let codes_str = data.codes.join("\n");
    let qr = QrCode::new(codes_str)?;
    let img = qr.render::<Luma<u8>>().build();
    img.save(output)?;
    println!("QR code saved to {}", output);
    Ok(())
}

fn check_code(filename: &str, password: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = load_from_file(filename, password)?;
    if data.codes.contains(&code.to_string()) {
        println!("Code '{}' is valid (found in backup).", code);
    } else {
        println!("Code '{}' is NOT in backup.", code);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("QR Login Manager")
        .arg(Arg::with_name("generate").long("generate").takes_value(true).help("Generate N codes"))
        .arg(Arg::with_name("output").long("output").takes_value(true).help("Output file"))
        .arg(Arg::with_name("password").long("password").takes_value(true).help("Password"))
        .arg(Arg::with_name("list").long("list").takes_value(true).help("List codes from file"))
        .arg(Arg::with_name("qr").long("qr").takes_value(true).help("Generate QR from file"))
        .arg(Arg::with_name("check").long("check").takes_value(true).help("Check code in backup"))
        .get_matches();

    if let Some(count_str) = matches.value_of("generate") {
        let count = count_str.parse()?;
        let output = matches.value_of("output").ok_or("--output required")?;
        let password = matches.value_of("password").ok_or("--password required")?;
        let codes = generate_codes(count, 8);
        let data = BackupData {
            created: format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap()),
            codes,
        };
        save_to_file(&data, password, output)?;
    } else if let Some(file) = matches.value_of("list") {
        let password = matches.value_of("password").ok_or("--password required")?;
        list_codes(file, password)?;
    } else if let Some(file) = matches.value_of("qr") {
        let password = matches.value_of("password").ok_or("--password required")?;
        let output = matches.value_of("output").ok_or("--output required for QR")?;
        generate_qr(file, password, output)?;
    } else if let Some(code) = matches.value_of("check") {
        let file = matches.value_of("list").ok_or("--list required for check")?;
        let password = matches.value_of("password").ok_or("--password required")?;
        check_code(file, password, code)?;
    } else {
        println!("Use --help for usage.");
    }
    Ok(())
}
