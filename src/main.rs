fn main() {
    println!("Hello, world!");
}

use std::sync::OnceLock;

struct HashCalc {
    //hash flag
    hash_crc32_flag: bool,
    hash_md5_flag: bool,
    hash_sha1_flag: bool,

    //hash flag not implemented
    hash_sha256_flag: bool,
    hash_sha512_flag: bool,
    hash_blake2b_flag: bool,
    hash_blake3_flag: bool,
}

impl HashCalc {
    //const
    const CRC32_POLY: u32 = 0xEDB88320;
    const INIT_CRC: u32 = 0xFFFFFFFF;
    const FINAL_XOR: u32 = 0xFFFFFFFF;
    static CRC32_TABLE: OnceLock<[u32; 256]> = OnceLock::new();

    //constructor
    fn new() -> Self {
        HashCalc {
            hash_crc32_flag: false,
            hash_md5_flag: false,
            hash_sha1_flag: false,
            hash_sha256_flag: false,
            hash_sha512_flag: false,
            hash_blake2b_flag: false,
            hash_blake3_flag: false,
        }
    }
    //set hash flag
    fn set_hash_flag(
        &mut self,
        crc32: bool,
        md5: bool,
        sha1: bool,
        sha256: bool,
        sha512: bool,
        blake2b: bool,
        blake3: bool,
    ) {
        self.hash_crc32_flag = crc32;
        self.hash_md5_flag = md5;
        self.hash_sha1_flag = sha1;
        self.hash_sha256_flag = sha256;
        self.hash_sha512_flag = sha512;
        self.hash_blake2b_flag = blake2b;
        self.hash_blake3_flag = blake3;
    }

    fn hash_start(&self) {
        // Placeholder for hash calculation logic
    }
    fn hash_start_crc32(&self) {
        // CRC32 calculation entry point (example wrapper)
    }
    
    /// Compute CRC32 (IEEE 802.3, reflected) for a byte slice.
    ///
    /// Uses a lazily-initialized 256-entry table. Returns the CRC32 value
    /// in the conventional form (post-xor), e.g. for "123456789" -> 0xCBF43926.
    fn crc32_bytes(&self, data: &[u8]) -> u32 {
        // Initialize table once
        static CRC32_TABLE: OnceLock<[u32; 256]> = OnceLock::new();
        let table = CRC32_TABLE.get_or_init(|| {
            let mut t = [0u32; 256];
            for i in 0..256 {
                let mut crc = i as u32;
                for _ in 0..8 {
                    if crc & 1 != 0 {
                        crc = (crc >> 1) ^ HashCalc::CRC32_POLY;
                    } else {
                        crc >>= 1;
                    }
                }
                t[i as usize] = crc;
            }
            t
        });

        let mut crc = HashCalc::INIT_CRC;
        for &b in data {
            let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ table[idx];
        }

        crc ^ HashCalc::FINAL_XOR
    }
    
    fn hash_end(&self) {
        // Placeholder for finalizing hash calculation
    }
}

#[cfg(test)]
mod tests {
    use crate::HashCalc;
    use std::vec::Vec;
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
}
