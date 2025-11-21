use crate::HashCalc;
use std::vec::Vec;

#[test]
fn crc32_known_vector() {
    let hc = HashCalc::new();
    let data = b"123456789";
    let crc = hc.crc32_bytes(data);
    // Standard CRC32 for ASCII "123456789"
    assert_eq!(crc, 0xCBF4_3926);
}

#[test]
fn crc32_empty() {
    let hc = HashCalc::new();
    let data: &[u8] = &[];
    let crc = hc.crc32_bytes(data);
    // CRC32 of empty string is 0
    assert_eq!(crc, 0x0000_0000);
}

#[test]
fn crc32_roundtrip() {
    let hc = HashCalc::new();
    let mut v = Vec::new();
    for i in 0..255u8 {
        v.push(i);
    }
    let _ = hc.crc32_bytes(&v);
    // Just ensure it runs without panicking; sanity: value type u32
}
