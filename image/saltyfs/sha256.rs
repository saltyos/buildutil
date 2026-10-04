// SPDX-License-Identifier: GPL-2.0-only
//! The image writer's SHA-256 for content dumps and deterministic identity inputs.

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const ROUND: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A streaming hash of the bytes supplied so far.
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    buffered: usize,
    bytes: u64,
}

impl Sha256 {
    /// Start an empty SHA-256 stream.
    pub fn new() -> Self {
        Self { state: INITIAL, block: [0; 64], buffered: 0, bytes: 0 }
    }

    fn compress(&mut self) {
        let mut words = [0u32; 64];
        for (index, bytes) in self.block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for index in 16..64 {
            let x = words[index - 15];
            let y = words[index - 2];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            words[index] = words[index - 16].wrapping_add(s0)
                .wrapping_add(words[index - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(sum1).wrapping_add(choice)
                .wrapping_add(ROUND[index]).wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = sum0.wrapping_add(majority);
            (a, b, c, d, e, f, g, h) =
                (t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }

    /// Append bytes to the stream.
    pub fn update(&mut self, mut data: &[u8]) {
        self.bytes = self.bytes.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.buffered).min(data.len());
            self.block[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                self.compress();
                self.buffered = 0;
            }
        }
    }

    /// Finish the stream and return the digest in canonical byte order.
    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.bytes.wrapping_mul(8);
        let mut padding = [0u8; 128];
        padding[0] = 0x80;
        let count = if self.buffered < 56 { 56 - self.buffered } else { 120 - self.buffered };
        padding[count..count + 8].copy_from_slice(&bits.to_be_bytes());
        self.update(&padding[..count + 8]);
        let mut digest = [0u8; 32];
        for (target, word) in digest.chunks_exact_mut(4).zip(self.state) {
            target.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// The lowercase hexadecimal SHA-256 of a byte slice.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    super::primitives::hex(&hash.finalize())
}

/// Hash a file without buffering its entire contents.
pub fn hash_file(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 { break; }
        hash.update(&buffer[..count]);
    }
    Ok(super::primitives::hex(&hash.finalize()))
}
