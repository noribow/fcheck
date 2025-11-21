fn main() {
    println!("Hello, world!");
}

use std::sync::OnceLock;

struct HashCalc {
    //state
    state: Option<u32>,

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

    //constructor
    fn new() -> Self {
        HashCalc {
            state: None,
            hash_crc32_flag: false,
            hash_md5_flag: false,
            hash_sha1_flag: false,
            hash_sha256_flag: false,
            hash_sha512_flag: false,
            hash_blake2b_flag: false,
            hash_blake3_flag: false,
        }
    }

    // set multiple flags at once
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

    fn build(self) -> Result<HashCalc, String> {
        Ok(HashCalc {
            state: self.state,
            hash_crc32_flag: self.hash_crc32_flag,
            hash_md5_flag: self.hash_md5_flag,
            hash_sha1_flag: self.hash_sha1_flag,
            hash_sha256_flag: self.hash_sha256_flag,
            hash_sha512_flag: self.hash_sha512_flag,
            hash_blake2b_flag: self.hash_blake2b_flag,
            hash_blake3_flag: self.hash_blake3_flag,
        })
    }

    fn set_hash_crc32_flag(&mut self, flag: bool) {
        self.hash_crc32_flag = flag;
    }

    fn set_hash_md5_flag(&mut self, flag: bool) {
        self.hash_md5_flag = flag;
    }

    fn set_hash_sha1_flag(&mut self, flag: bool) {
        self.hash_sha1_flag = flag;
    }

    fn set_hash_sha256_flag(&mut self, flag: bool) {
        self.hash_sha256_flag = flag;
    }

    fn set_hash_sha512_flag(&mut self, flag: bool) {
        self.hash_sha512_flag = flag;
    }

    fn set_hash_blake2b_flag(&mut self, flag: bool) {
        self.hash_blake2b_flag = flag;
    }

    fn set_hash_blake3_flag(&mut self, flag: bool) {
        self.hash_blake3_flag = flag;
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
    /// in the conventional form (post-xor), e.g. for \"123456789\" -> 0xCBF43926.
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
mod tests;

#[cfg(test)]
mod crc_tests;
