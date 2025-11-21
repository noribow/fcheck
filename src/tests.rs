use crate::HashCalc;

#[test]
fn it_works() {
    let hc: HashCalc = HashCalc::new();
    // Just checks construction
    assert!(!hc.hash_crc32_flag);
    assert!(!hc.hash_md5_flag);
    assert!(!hc.hash_sha1_flag);
    assert!(!hc.hash_sha256_flag);
    assert!(!hc.hash_sha512_flag);
    assert!(!hc.hash_blake2b_flag);
    assert!(!hc.hash_blake3_flag);
}

#[test]
fn set_all_flags_true() {
    let mut hc = HashCalc::new();
    hc.set_hash_flag(true, true, true, true, true, true, true);
    assert!(hc.hash_crc32_flag);
    assert!(hc.hash_md5_flag);
    assert!(hc.hash_sha1_flag);
    assert!(hc.hash_sha256_flag);
    assert!(hc.hash_sha512_flag);
    assert!(hc.hash_blake2b_flag);
    assert!(hc.hash_blake3_flag);
}

#[test]
fn set_some_flags_true() {
    let mut hc = HashCalc::new();
    hc.set_hash_flag(true, false, true, false, true, false, true);
    assert!(hc.hash_crc32_flag);
    assert!(!hc.hash_md5_flag);
    assert!(hc.hash_sha1_flag);
    assert!(!hc.hash_sha256_flag);
    assert!(hc.hash_sha512_flag);
    assert!(!hc.hash_blake2b_flag);
    assert!(hc.hash_blake3_flag);
}

#[test]
fn set_all_flags_false() {
    let mut hc = HashCalc::new();
    hc.set_hash_flag(false, false, false, false, false, false, false);
    assert!(!hc.hash_crc32_flag);
    assert!(!hc.hash_md5_flag);
    assert!(!hc.hash_sha1_flag);
    assert!(!hc.hash_sha256_flag);
    assert!(!hc.hash_sha512_flag);
    assert!(!hc.hash_blake2b_flag);
    assert!(!hc.hash_blake3_flag);
}

#[test]
fn set_individual_hash_crc32_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_crc32_flag(true);
    assert!(hc.hash_crc32_flag);
    hc.set_hash_crc32_flag(false);
    assert!(!hc.hash_crc32_flag);
}

#[test]
fn set_individual_hash_md5_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_md5_flag(true);
    assert!(hc.hash_md5_flag);
    hc.set_hash_md5_flag(false);
    assert!(!hc.hash_md5_flag);
}

#[test]
fn set_individual_hash_sha1_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_sha1_flag(true);
    assert!(hc.hash_sha1_flag);
    hc.set_hash_sha1_flag(false);
    assert!(!hc.hash_sha1_flag);
}

#[test]
fn set_individual_hash_sha256_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_sha256_flag(true);
    assert!(hc.hash_sha256_flag);
    hc.set_hash_sha256_flag(false);
    assert!(!hc.hash_sha256_flag);
}

#[test]
fn set_individual_hash_sha512_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_sha512_flag(true);
    assert!(hc.hash_sha512_flag);
    hc.set_hash_sha512_flag(false);
    assert!(!hc.hash_sha512_flag);
}

#[test]
fn set_individual_hash_blake2b_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_blake2b_flag(true);
    assert!(hc.hash_blake2b_flag);
    hc.set_hash_blake2b_flag(false);
    assert!(!hc.hash_blake2b_flag);
}

#[test]
fn set_individual_hash_blake3_flag() {
    let mut hc = HashCalc::new();
    hc.set_hash_blake3_flag(true);
    assert!(hc.hash_blake3_flag);
    hc.set_hash_blake3_flag(false);
    assert!(!hc.hash_blake3_flag);
}
