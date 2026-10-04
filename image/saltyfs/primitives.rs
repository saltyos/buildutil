// SPDX-License-Identifier: GPL-2.0-only
//! flake — the cryptographic primitives of the SaltyFS encrypted profile,
//! transcribed for the image writer alone: BLAKE3 (hash, keyed hash, key
//! derivation), ChaCha20 and Poly1305 with the XChaCha20-Poly1305 seal,
//! AES-256, GCM and XAES-256-GCM, SipHash-2-4, BLAKE2b and Argon2id. The
//! writer shares no code with the provider or the loader; the conformance
//! tests hold the published vectors that keep the three transcriptions on
//! one definition.

// ---------------------------------------------------------------------------
// BLAKE3
// ---------------------------------------------------------------------------

pub mod blake3 {
    const OUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    const CHUNK_LEN: usize = 1024;
    const CHUNK_START: u32 = 1;
    const CHUNK_END: u32 = 2;
    const PARENT: u32 = 4;
    const ROOT: u32 = 8;
    const KEYED_HASH: u32 = 16;
    const DERIVE_KEY_CONTEXT: u32 = 32;
    const DERIVE_KEY_MATERIAL: u32 = 64;
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];
    const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    #[inline(always)]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn round(state: &mut [u32; 16], m: &[u32; 16]) {
        g(state, 0, 4, 8, 12, m[0], m[1]);
        g(state, 1, 5, 9, 13, m[2], m[3]);
        g(state, 2, 6, 10, 14, m[4], m[5]);
        g(state, 3, 7, 11, 15, m[6], m[7]);
        g(state, 0, 5, 10, 15, m[8], m[9]);
        g(state, 1, 6, 11, 12, m[10], m[11]);
        g(state, 2, 7, 8, 13, m[12], m[13]);
        g(state, 3, 4, 9, 14, m[14], m[15]);
    }

    fn permute(m: &mut [u32; 16]) {
        let mut permuted = [0u32; 16];
        for i in 0..16 { permuted[i] = m[MSG_PERMUTATION[i]]; }
        *m = permuted;
    }

    fn compress(cv: &[u32; 8], block_words: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
        let mut state = [
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3],
            counter as u32, (counter >> 32) as u32, block_len, flags,
        ];
        let mut block = *block_words;
        for r in 0..7 {
            round(&mut state, &block);
            if r != 6 { permute(&mut block); }
        }
        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }
        state
    }

    fn words_from_le_bytes(bytes: &[u8]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (i, chunk) in bytes.chunks(4).enumerate().take(16) {
            let mut b = [0u8; 4];
            b[..chunk.len()].copy_from_slice(chunk);
            words[i] = u32::from_le_bytes(b);
        }
        words
    }

    fn key_words(key: &[u8; 32]) -> [u32; 8] {
        let mut words = [0u32; 8];
        for i in 0..8 { words[i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap_or([0; 4])); }
        words
    }

    #[derive(Clone, Copy)]
    struct Output { cv: [u32; 8], block: [u32; 16], counter: u64, block_len: u32, flags: u32 }

    impl Output {
        fn chaining_value(&self) -> [u32; 8] {
            let out = compress(&self.cv, &self.block, self.counter, self.block_len, self.flags);
            let mut cv = [0u32; 8];
            cv.copy_from_slice(&out[..8]);
            cv
        }
        fn root_bytes(&self, out: &mut [u8]) {
            let mut counter = 0u64;
            let mut at = 0usize;
            while at < out.len() {
                let words = compress(&self.cv, &self.block, counter, self.block_len, self.flags | ROOT);
                for word in words {
                    let bytes = word.to_le_bytes();
                    let take = (out.len() - at).min(4);
                    if take == 0 { break; }
                    out[at..at + take].copy_from_slice(&bytes[..take]);
                    at += take;
                }
                counter += 1;
            }
        }
    }

    struct ChunkState { cv: [u32; 8], counter: u64, block: [u8; BLOCK_LEN], block_len: u8, blocks_compressed: u8, flags: u32 }

    impl ChunkState {
        fn new(key: [u32; 8], counter: u64, flags: u32) -> Self { Self { cv: key, counter, block: [0; BLOCK_LEN], block_len: 0, blocks_compressed: 0, flags } }
        fn len(&self) -> usize { BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize }
        fn start_flag(&self) -> u32 { if self.blocks_compressed == 0 { CHUNK_START } else { 0 } }
        fn update(&mut self, mut input: &[u8]) {
            while !input.is_empty() {
                if self.block_len as usize == BLOCK_LEN {
                    let words = words_from_le_bytes(&self.block);
                    let out = compress(&self.cv, &words, self.counter, BLOCK_LEN as u32, self.flags | self.start_flag());
                    self.cv.copy_from_slice(&out[..8]);
                    self.blocks_compressed += 1;
                    self.block = [0; BLOCK_LEN];
                    self.block_len = 0;
                }
                let take = (BLOCK_LEN - self.block_len as usize).min(input.len());
                self.block[self.block_len as usize..self.block_len as usize + take].copy_from_slice(&input[..take]);
                self.block_len += take as u8;
                input = &input[take..];
            }
        }
        fn output(&self) -> Output {
            Output { cv: self.cv, block: words_from_le_bytes(&self.block), counter: self.counter, block_len: self.block_len as u32,
                flags: self.flags | self.start_flag() | CHUNK_END }
        }
    }

    fn parent_output(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
        let mut block = [0u32; 16];
        block[..8].copy_from_slice(&left);
        block[8..].copy_from_slice(&right);
        Output { cv: key, block, counter: 0, block_len: BLOCK_LEN as u32, flags: flags | PARENT }
    }

    /// An incremental hasher in one of the three modes.
    pub struct Hasher { chunk: ChunkState, key: [u32; 8], cv_stack: Vec<[u32; 8]>, flags: u32 }

    impl Hasher {
        fn with_key_words(key: [u32; 8], flags: u32) -> Self { Self { chunk: ChunkState::new(key, 0, flags), key, cv_stack: Vec::new(), flags } }
        pub fn new() -> Self { Self::with_key_words(IV, 0) }
        pub fn new_keyed(key: &[u8; 32]) -> Self { Self::with_key_words(key_words(key), KEYED_HASH) }
        pub fn new_derive_key(context: &[u8]) -> Self {
            let mut context_hasher = Self::with_key_words(IV, DERIVE_KEY_CONTEXT);
            context_hasher.update(context);
            let mut context_key = [0u8; 32];
            context_hasher.finalize_into(&mut context_key);
            Self::with_key_words(key_words(&context_key), DERIVE_KEY_MATERIAL)
        }

        fn add_chunk_cv(&mut self, mut cv: [u32; 8], mut total_chunks: u64) {
            while total_chunks & 1 == 0 {
                let left = self.cv_stack.pop().unwrap_or(IV);
                cv = parent_output(left, cv, self.key, self.flags).chaining_value();
                total_chunks >>= 1;
            }
            self.cv_stack.push(cv);
        }

        pub fn update(&mut self, mut input: &[u8]) {
            while !input.is_empty() {
                if self.chunk.len() == CHUNK_LEN {
                    let cv = self.chunk.output().chaining_value();
                    let total = self.chunk.counter + 1;
                    self.add_chunk_cv(cv, total);
                    self.chunk = ChunkState::new(self.key, total, self.flags);
                }
                let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
                self.chunk.update(&input[..take]);
                input = &input[take..];
            }
        }

        pub fn finalize_into(&self, out: &mut [u8]) {
            let mut output = self.chunk.output();
            for cv in self.cv_stack.iter().rev() {
                output = parent_output(*cv, output.chaining_value(), self.key, self.flags);
            }
            output.root_bytes(out);
        }

        pub fn finalize(&self) -> [u8; OUT_LEN] {
            let mut out = [0u8; OUT_LEN];
            self.finalize_into(&mut out);
            out
        }
    }

    pub fn hash(input: &[u8]) -> [u8; OUT_LEN] { let mut h = Hasher::new(); h.update(input); h.finalize() }
    pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> [u8; OUT_LEN] { let mut h = Hasher::new_keyed(key); h.update(input); h.finalize() }
    pub fn derive_key(context: &[u8], material: &[u8]) -> [u8; OUT_LEN] {
        let mut h = Hasher::new_derive_key(context);
        h.update(material);
        h.finalize()
    }
}

// ---------------------------------------------------------------------------
// ChaCha20, Poly1305, XChaCha20-Poly1305
// ---------------------------------------------------------------------------

pub mod chacha {
    fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
    }

    fn rounds(state: &mut [u32; 16]) {
        for _ in 0..10 {
            quarter(state, 0, 4, 8, 12); quarter(state, 1, 5, 9, 13); quarter(state, 2, 6, 10, 14); quarter(state, 3, 7, 11, 15);
            quarter(state, 0, 5, 10, 15); quarter(state, 1, 6, 11, 12); quarter(state, 2, 7, 8, 13); quarter(state, 3, 4, 9, 14);
        }
    }

    fn init(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
        let mut s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0, 0, 0, 0, 0, 0, 0, 0, counter, 0, 0, 0];
        for i in 0..8 { s[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap_or([0; 4])); }
        for i in 0..3 { s[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap_or([0; 4])); }
        s
    }

    pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
        let initial = init(key, counter, nonce);
        let mut state = initial;
        rounds(&mut state);
        for i in 0..16 { out[4 * i..4 * i + 4].copy_from_slice(&state[i].wrapping_add(initial[i]).to_le_bytes()); }
    }

    pub fn xor_stream(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
        let mut ks = [0u8; 64];
        for chunk in data.chunks_mut(64) {
            block(key, counter, nonce, &mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) { *d ^= *k; }
            counter = counter.wrapping_add(1);
        }
    }

    pub fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
        let mut s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for i in 0..8 { s[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap_or([0; 4])); }
        for i in 0..4 { s[12 + i] = u32::from_le_bytes(nonce16[4 * i..4 * i + 4].try_into().unwrap_or([0; 4])); }
        rounds(&mut s);
        let mut out = [0u8; 32];
        for i in 0..4 { out[4 * i..4 * i + 4].copy_from_slice(&s[i].to_le_bytes()); }
        for i in 0..4 { out[16 + 4 * i..16 + 4 * i + 4].copy_from_slice(&s[12 + i].to_le_bytes()); }
        out
    }

    /// Poly1305: the accumulator and `r` as 64-bit limbs, the
    /// product reduced modulo 2^130 - 5 by folding the bits above 130.
    pub fn poly1305(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        let mut r = [0u64; 2];
        r[0] = u64::from_le_bytes(key[..8].try_into().unwrap_or([0; 8])) & 0x0fff_fffc_0fff_ffff;
        r[1] = u64::from_le_bytes(key[8..16].try_into().unwrap_or([0; 8])) & 0x0fff_fffc_0fff_fffc;
        let s = u128::from_le_bytes(key[16..].try_into().unwrap_or([0; 16]));
        // h < 2^131 between steps: three limbs.
        let mut h = [0u64; 3];
        for chunk in message.chunks(16) {
            let mut block = [0u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1;
            let n0 = u64::from_le_bytes(block[..8].try_into().unwrap_or([0; 8]));
            let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap_or([0; 8]));
            let n2 = block[16] as u64;
            // h += n
            let (a0, c0) = h[0].overflowing_add(n0);
            let (a1, c1a) = h[1].overflowing_add(n1);
            let (a1, c1b) = a1.overflowing_add(c0 as u64);
            let a2 = h[2] + n2 + (c1a as u64) + (c1b as u64);
            // h * r with 128-bit partial products; h < 2^131, r < 2^124.
            let m = |x: u64, y: u64| x as u128 * y as u128;
            let d0 = m(a0, r[0]);
            let d1 = m(a0, r[1]) + m(a1, r[0]);
            let d2 = m(a1, r[1]) + m(a2, r[0]);
            let d3 = m(a2, r[1]);
            // Carry into 64-bit limbs p0..p4.
            let p0 = d0 as u64;
            let t1 = (d0 >> 64) + d1;
            let p1 = t1 as u64;
            let t2 = (t1 >> 64) + d2;
            let p2 = t2 as u64;
            let t3 = (t2 >> 64) + d3;
            let p3 = t3 as u64;
            let p4 = (t3 >> 64) as u64;
            // Split at bit 130: low = p0, p1, p2 & 3; high = the rest.
            let low2 = p2 & 3;
            let high = ((p2 >> 2) as u128) | ((p3 as u128) << 62) | ((p4 as u128) << 126);
            // h = low + 5 * high; high < 2^125, so 5 * high fits 128 bits.
            let five = high * 5;
            let (l0, c) = p0.overflowing_add(five as u64);
            let (l1, c2) = p1.overflowing_add((five >> 64) as u64);
            let (l1, c3) = l1.overflowing_add(c as u64);
            let l2 = low2 + (c2 as u64) + (c3 as u64);
            h = [l0, l1, l2];
        }
        // Final reduction: h may be up to ~2^130 + small; fold once more and
        // subtract p when h >= p.
        let high = h[2] >> 2;
        h[2] &= 3;
        let (l0, c) = h[0].overflowing_add(high * 5);
        let (l1, c2) = h[1].overflowing_add(c as u64);
        h = [l0, l1, h[2] + c2 as u64];
        // Compare with p = 2^130 - 5.
        let ge = h[2] > 3 || (h[2] == 3 && h[1] == u64::MAX && h[0] >= u64::MAX - 4);
        if ge {
            let (l0, b) = h[0].overflowing_sub(u64::MAX - 4);
            let (l1, b2) = h[1].overflowing_sub(u64::MAX);
            let (l1, b3) = l1.overflowing_sub(b as u64);
            let _ = h[2].wrapping_sub(3).wrapping_sub((b2 as u64) + (b3 as u64));
            h = [l0, l1, 0];
        }
        let acc = (h[0] as u128) | ((h[1] as u128) << 64);
        acc.wrapping_add(s).to_le_bytes()
    }

    pub fn tags_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
        let mut diff = 0u8;
        for i in 0..16 { diff |= a[i] ^ b[i]; }
        diff == 0
    }

    fn subkey(key: &[u8; 32], nonce: &[u8; 24]) -> ([u8; 32], [u8; 12]) {
        let mut first16 = [0u8; 16];
        first16.copy_from_slice(&nonce[..16]);
        let sub = hchacha20(key, &first16);
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&nonce[16..]);
        (sub, n)
    }

    fn one_time_key(sub: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
        let mut block0 = [0u8; 64];
        block(sub, 0, nonce, &mut block0);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&block0[..32]);
        otk
    }

    fn mac(otk: &[u8; 32], ad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut input = Vec::with_capacity(ad.len() + ciphertext.len() + 48);
        input.extend_from_slice(ad);
        input.resize(input.len().next_multiple_of(16), 0);
        input.extend_from_slice(ciphertext);
        input.resize(input.len().next_multiple_of(16), 0);
        input.extend_from_slice(&(ad.len() as u64).to_le_bytes());
        input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly1305(otk, &input)
    }

    /// XChaCha20-Poly1305 seal in place; returns the tag.
    pub fn xchacha_seal(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let (sub, n) = subkey(key, nonce);
        let otk = one_time_key(&sub, &n);
        xor_stream(&sub, 1, &n, data);
        mac(&otk, ad, data)
    }

    pub fn xchacha_open(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> Result<(), ()> {
        let (sub, n) = subkey(key, nonce);
        let otk = one_time_key(&sub, &n);
        if !tags_equal(&mac(&otk, ad, data), tag) { return Err(()); }
        xor_stream(&sub, 1, &n, data);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AES-256, GCM, XAES-256-GCM
// ---------------------------------------------------------------------------

pub mod aes {
    //! AES-256, GCM and XAES-256-GCM over the host's AES and carry-less
    //! multiply instructions: there is no portable AES and no portable
    //! GHASH, so a host without the instructions cannot write or read the
    //! AES suite. Every vector type stays inside the `target_feature`
    //! functions below.

    /// Proof that this host carries the AES and carry-less multiply
    /// instructions: only [`available`] makes one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Instructions {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        _found: (),
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        never: std::convert::Infallible,
    }

    /// Whether the host reports both instruction sets.
    pub fn host_has_instructions() -> bool {
        #[cfg(target_arch = "x86_64")]
        return std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse2");
        #[cfg(target_arch = "aarch64")]
        return std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("neon");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        false
    }

    /// The proof, when the host reports both instruction sets and the GCM
    /// known-answer test (NIST test case 14) agrees.
    pub fn available() -> Option<Instructions> {
        if !host_has_instructions() { return None; }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let instructions = Instructions { _found: () };
            known_answer(instructions).then_some(instructions)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        None
    }

    /// NIST GCM test case 14: the zero key, the zero 96-bit nonce and one
    /// zero block.
    fn known_answer(instructions: Instructions) -> bool {
        let cipher = Aes256::new(instructions, &[0; 32]);
        let mut data = [0u8; 16];
        let tag = gcm_seal(&cipher, &[0; 12], b"", &mut data);
        super::hex(&data) == "cea7403d4d606b6e074ec5d3baf39d18" && super::hex(&tag) == "d0d1c8a799996bf0265b98b5d48ab919"
    }

    impl Instructions {
        /// AES `SubWord` of a little-endian word.
        fn sub_word(self, word: u32) -> u32 {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            // SAFETY: `self` proves the host carries the instructions.
            return unsafe { hw::sub_word(word) };
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            match self.never {}
        }

        fn encrypt_block(self, round_keys: &[[u8; 16]; 15], block: &mut [u8; 16]) {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            // SAFETY: `self` proves the host carries the instructions.
            return unsafe { hw::encrypt_block(round_keys, block) };
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            match self.never {}
        }

        fn clmul128(self, a: u128, b: u128) -> (u128, u128) {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            // SAFETY: `self` proves the host carries the instructions.
            return unsafe { hw::clmul128(a, b) };
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            match self.never {}
        }
    }

    #[cfg(target_arch = "x86_64")]
    mod hw {
        use std::arch::x86_64::*;

        /// # Safety
        /// The host must carry `aes` and `sse2`.
        #[target_feature(enable = "aes,sse2")]
        pub(super) unsafe fn sub_word(word: u32) -> u32 {
            // With the word in every column ShiftRows moves nothing: the last
            // round under a zero key is SubBytes.
            _mm_cvtsi128_si32(_mm_aesenclast_si128(_mm_set1_epi32(word as i32), _mm_setzero_si128())) as u32
        }

        /// # Safety
        /// The host must carry `aes` and `sse2`.
        #[target_feature(enable = "aes,sse2")]
        pub(super) unsafe fn encrypt_block(round_keys: &[[u8; 16]; 15], block: &mut [u8; 16]) {
            // SAFETY: unaligned loads and stores of 16-byte arrays.
            unsafe {
                let load = |bytes: &[u8; 16]| -> __m128i { _mm_loadu_si128(bytes.as_ptr().cast()) };
                let mut state = _mm_xor_si128(load(block), load(&round_keys[0]));
                for round in round_keys.iter().take(14).skip(1) { state = _mm_aesenc_si128(state, load(round)); }
                state = _mm_aesenclast_si128(state, load(&round_keys[14]));
                _mm_storeu_si128(block.as_mut_ptr().cast(), state);
            }
        }

        /// # Safety
        /// The host must carry `pclmulqdq` and `sse2`.
        #[target_feature(enable = "pclmulqdq,sse2")]
        pub(super) unsafe fn clmul128(a: u128, b: u128) -> (u128, u128) {
            // SAFETY: unaligned loads and stores of 16-byte values.
            unsafe {
                let load = |v: u128| -> __m128i { _mm_loadu_si128(v.to_le_bytes().as_ptr().cast()) };
                let store = |v: __m128i| -> u128 {
                    let mut bytes = [0u8; 16];
                    _mm_storeu_si128(bytes.as_mut_ptr().cast(), v);
                    u128::from_le_bytes(bytes)
                };
                let (va, vb) = (load(a), load(b));
                let lo = store(_mm_clmulepi64_si128(va, vb, 0x00));
                let hi = store(_mm_clmulepi64_si128(va, vb, 0x11));
                let mid = store(_mm_clmulepi64_si128(va, vb, 0x10)) ^ store(_mm_clmulepi64_si128(va, vb, 0x01));
                (lo ^ (mid << 64), hi ^ (mid >> 64))
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod hw {
        use std::arch::aarch64::*;

        /// # Safety
        /// The host must carry `aes` and `neon`.
        #[target_feature(enable = "aes,neon")]
        pub(super) unsafe fn sub_word(word: u32) -> u32 {
            // With the word in every column ShiftRows moves nothing: AESE
            // under a zero key is SubBytes.
            vgetq_lane_u32(vreinterpretq_u32_u8(vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(word)), vdupq_n_u8(0))), 0)
        }

        /// # Safety
        /// The host must carry `aes` and `neon`.
        #[target_feature(enable = "aes,neon")]
        pub(super) unsafe fn encrypt_block(round_keys: &[[u8; 16]; 15], block: &mut [u8; 16]) {
            // SAFETY: loads and stores of 16-byte arrays.
            unsafe {
                let load = |bytes: &[u8; 16]| -> uint8x16_t { vld1q_u8(bytes.as_ptr()) };
                let mut state = load(block);
                for round in round_keys.iter().take(13) { state = vaesmcq_u8(vaeseq_u8(state, load(round))); }
                state = vaeseq_u8(state, load(&round_keys[13]));
                state = veorq_u8(state, load(&round_keys[14]));
                vst1q_u8(block.as_mut_ptr(), state);
            }
        }

        /// # Safety
        /// The host must carry `aes` (with PMULL) and `neon`.
        #[target_feature(enable = "aes,neon")]
        pub(super) unsafe fn clmul128(a: u128, b: u128) -> (u128, u128) {
            let (a0, a1) = (a as u64, (a >> 64) as u64);
            let (b0, b1) = (b as u64, (b >> 64) as u64);
            let lo = vmull_p64(a0, b0);
            let hi = vmull_p64(a1, b1);
            let mid = vmull_p64(a0, b1) ^ vmull_p64(a1, b0);
            (lo ^ (mid << 64), hi ^ (mid >> 64))
        }
    }

    pub struct Aes256 {
        round_keys: [[u8; 16]; 15],
        instructions: Instructions,
    }

    impl Aes256 {
        /// Expand `key` (FIPS 197 section 5.2) with the instructions'
        /// `SubWord`: words are little-endian, so `RotWord` is a rotation
        /// right by one byte and the round constant enters the low byte.
        pub fn new(instructions: Instructions, key: &[u8; 32]) -> Self {
            let mut w = [0u32; 60];
            for (i, word) in w.iter_mut().take(8).enumerate() {
                *word = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            }
            let mut rcon = 1u32;
            for i in 8..60 {
                let mut temp = w[i - 1];
                if i % 8 == 0 {
                    temp = instructions.sub_word(temp.rotate_right(8)) ^ rcon;
                    rcon = ((rcon << 1) ^ (0x1b * (rcon >> 7))) & 0xff;
                } else if i % 8 == 4 {
                    temp = instructions.sub_word(temp);
                }
                w[i] = w[i - 8] ^ temp;
            }
            let mut round_keys = [[0u8; 16]; 15];
            for (r, round) in round_keys.iter_mut().enumerate() {
                for c in 0..4 { round[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c].to_le_bytes()); }
            }
            Self { round_keys, instructions }
        }

        pub fn encrypt_block(&self, block: &mut [u8; 16]) { self.instructions.encrypt_block(&self.round_keys, block); }
    }

    /// Reduce a 256-bit product modulo `x^128 + x^7 + x^2 + x + 1`, the
    /// polynomials bit-reversed from GCM's byte order.
    fn reduce(lo: u128, hi: u128) -> u128 {
        let folded = lo ^ hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
        let carry = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
        folded ^ carry ^ (carry << 1) ^ (carry << 2) ^ (carry << 7)
    }

    fn gf_mul(instructions: Instructions, x: u128, y: u128) -> u128 {
        let (lo, hi) = instructions.clmul128(x, y);
        reduce(lo, hi)
    }

    fn to_poly(block: [u8; 16]) -> u128 { u128::from_be_bytes(block).reverse_bits() }

    fn ghash(instructions: Instructions, hblock: [u8; 16], ad: &[u8], ct: &[u8]) -> [u8; 16] {
        let h = to_poly(hblock);
        let mut y = 0u128;
        let absorb = |data: &[u8], y: &mut u128| {
            for chunk in data.chunks(16) {
                let mut b = [0u8; 16];
                b[..chunk.len()].copy_from_slice(chunk);
                *y = gf_mul(instructions, *y ^ to_poly(b), h);
            }
        };
        absorb(ad, &mut y);
        absorb(ct, &mut y);
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((ad.len() as u64) * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
        y = gf_mul(instructions, y ^ to_poly(lengths), h);
        y.reverse_bits().to_be_bytes()
    }

    fn gcm_run(cipher: &Aes256, nonce: &[u8; 12], data: &mut [u8]) -> ([u8; 16], [u8; 16]) {
        let mut hblock = [0u8; 16];
        cipher.encrypt_block(&mut hblock);
        let h = hblock;
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let mut counter = u32::from_be_bytes([j0[12], j0[13], j0[14], j0[15]]);
        for chunk in data.chunks_mut(16) {
            counter = counter.wrapping_add(1);
            let mut block = j0;
            block[12..].copy_from_slice(&counter.to_be_bytes());
            cipher.encrypt_block(&mut block);
            for (d, k) in chunk.iter_mut().zip(block.iter()) { *d ^= *k; }
        }
        let mut ej0 = j0;
        cipher.encrypt_block(&mut ej0);
        (h, ej0)
    }

    pub fn gcm_seal(cipher: &Aes256, nonce: &[u8; 12], ad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let (h, ej0) = gcm_run(cipher, nonce, data);
        let mut tag = ghash(cipher.instructions, h, ad, data);
        for i in 0..16 { tag[i] ^= ej0[i]; }
        tag
    }

    pub fn gcm_open(cipher: &Aes256, nonce: &[u8; 12], ad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> Result<(), ()> {
        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let mut ej0 = j0;
        cipher.encrypt_block(&mut ej0);
        let mut expected = ghash(cipher.instructions, h, ad, data);
        for i in 0..16 { expected[i] ^= ej0[i]; }
        if !super::chacha::tags_equal(&expected, tag) { return Err(()); }
        gcm_run(cipher, nonce, data);
        Ok(())
    }

    fn double(block: &mut [u8; 16]) {
        let msb = block[0] >> 7;
        let mut carry = 0u8;
        for i in (0..16).rev() {
            let next = block[i] >> 7;
            block[i] = (block[i] << 1) | carry;
            carry = next;
        }
        block[15] ^= 0x87 & 0u8.wrapping_sub(msb);
    }

    fn xaes_derive(instructions: Instructions, key: &[u8; 32], nonce: &[u8; 24]) -> Aes256 {
        let cipher = Aes256::new(instructions, key);
        let mut k1 = [0u8; 16];
        cipher.encrypt_block(&mut k1);
        double(&mut k1);
        let mut derived = [0u8; 32];
        for (index, half) in derived.chunks_exact_mut(16).enumerate() {
            let mut m = [0u8; 16];
            m[1] = index as u8 + 1;
            m[2] = b'X';
            m[4..].copy_from_slice(&nonce[..12]);
            for i in 0..16 { m[i] ^= k1[i]; }
            cipher.encrypt_block(&mut m);
            half.copy_from_slice(&m);
        }
        Aes256::new(instructions, &derived)
    }

    fn gcm_nonce(nonce: &[u8; 24]) -> [u8; 12] { let mut n = [0u8; 12]; n.copy_from_slice(&nonce[12..]); n }

    pub fn xaes_seal(instructions: Instructions, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], data: &mut [u8]) -> [u8; 16] {
        gcm_seal(&xaes_derive(instructions, key, nonce), &gcm_nonce(nonce), ad, data)
    }

    pub fn xaes_open(instructions: Instructions, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], data: &mut [u8], tag: &[u8; 16])
        -> Result<(), ()>
    {
        gcm_open(&xaes_derive(instructions, key, nonce), &gcm_nonce(nonce), ad, data, tag)
    }
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// The encrypted profile's two authenticated ciphers, selected by the
/// superblock's suite word. The AES suite carries the proof that this host
/// has the instructions it runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite { XChaCha20Poly1305, Xaes256Gcm(aes::Instructions) }

impl Suite {
    /// The AES suite, when this host carries its instructions.
    pub fn xaes() -> Result<Self, String> {
        aes::available().map(Self::Xaes256Gcm)
            .ok_or_else(|| "xaes-256-gcm needs the host's AES and carry-less multiply instructions".to_string())
    }
    pub fn from_word(word: u32) -> Result<Option<Self>, String> {
        match word {
            0 => Ok(None),
            1 => Ok(Some(Self::XChaCha20Poly1305)),
            2 => Self::xaes().map(Some),
            other => Err(format!("unknown suite {other}")),
        }
    }
    pub fn word(self) -> u32 { match self { Self::XChaCha20Poly1305 => 1, Self::Xaes256Gcm(_) => 2 } }
    pub fn seal(self, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], data: &mut [u8]) -> [u8; 16] {
        match self {
            Self::XChaCha20Poly1305 => chacha::xchacha_seal(key, nonce, ad, data),
            Self::Xaes256Gcm(instructions) => aes::xaes_seal(instructions, key, nonce, ad, data),
        }
    }
    pub fn open(self, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> Result<(), ()> {
        match self {
            Self::XChaCha20Poly1305 => chacha::xchacha_open(key, nonce, ad, data, tag),
            Self::Xaes256Gcm(instructions) => aes::xaes_open(instructions, key, nonce, ad, data, tag),
        }
    }
}

// ---------------------------------------------------------------------------
// SipHash-2-4
// ---------------------------------------------------------------------------

pub fn siphash24(key: &[u8; 16], message: &[u8]) -> u64 {
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]); v[1] = v[1].rotate_left(13); v[1] ^= v[0]; v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]); v[3] = v[3].rotate_left(16); v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]); v[3] = v[3].rotate_left(21); v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]); v[1] = v[1].rotate_left(17); v[1] ^= v[2]; v[2] = v[2].rotate_left(32);
    }
    let k0 = u64::from_le_bytes(key[..8].try_into().unwrap_or([0; 8]));
    let k1 = u64::from_le_bytes(key[8..].try_into().unwrap_or([0; 8]));
    let mut v = [k0 ^ 0x736f_6d65_7073_6575, k1 ^ 0x646f_7261_6e64_6f6d, k0 ^ 0x6c79_6765_6e65_7261, k1 ^ 0x7465_6462_7974_6573];
    let mut chunks = message.chunks_exact(8);
    for chunk in &mut chunks {
        let m = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
        v[3] ^= m; round(&mut v); round(&mut v); v[0] ^= m;
    }
    let rest = chunks.remainder();
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    last[7] = message.len() as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m; round(&mut v); round(&mut v); v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 { round(&mut v); }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

// ---------------------------------------------------------------------------
// BLAKE2b and Argon2id
// ---------------------------------------------------------------------------

pub mod argon2 {
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];

    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x); v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y); v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 { m[i] = u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap_or([0; 8])); }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= t as u64;
        v[13] ^= (t >> 64) as u64;
        if last { v[14] = !v[14]; }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]); g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]); g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]); g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]); g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 { h[i] ^= v[i] ^ v[i + 8]; }
    }

    /// BLAKE2b of `inputs` concatenated, `out.len()` bytes (1..=64).
    pub fn blake2b(inputs: &[&[u8]], out: &mut [u8]) {
        let out_len = out.len().clamp(1, 64);
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ out_len as u64;
        let mut buffer = [0u8; 128];
        let mut buffered = 0usize;
        let mut t: u128 = 0;
        for input in inputs {
            let mut data = *input;
            while !data.is_empty() {
                if buffered == 128 { t += 128; compress(&mut h, &buffer, t, false); buffered = 0; }
                let take = (128 - buffered).min(data.len());
                buffer[buffered..buffered + take].copy_from_slice(&data[..take]);
                buffered += take;
                data = &data[take..];
            }
        }
        t += buffered as u128;
        buffer[buffered..].fill(0);
        compress(&mut h, &buffer, t, true);
        let mut digest = [0u8; 64];
        for (i, word) in h.iter().enumerate() { digest[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes()); }
        out[..out_len].copy_from_slice(&digest[..out_len]);
    }

    /// Argon2's H'(T, X).
    pub fn h_prime(inputs: &[&[u8]], out: &mut [u8]) {
        let t = out.len();
        let length = (t as u32).to_le_bytes();
        let mut all: Vec<&[u8]> = vec![&length];
        all.extend_from_slice(inputs);
        if t <= 64 { blake2b(&all, out); return; }
        let r = t.div_ceil(32) - 2;
        let mut v = [0u8; 64];
        blake2b(&all, &mut v);
        let mut at = 0usize;
        for _ in 0..r {
            out[at..at + 32].copy_from_slice(&v[..32]);
            at += 32;
            let mut next = [0u8; 64];
            blake2b(&[&v], &mut next);
            v = next;
        }
        let remaining = t - 32 * r;
        let mut tail = [0u8; 64];
        blake2b(&[&v], &mut tail[..remaining]);
        out[at..].copy_from_slice(&tail[..remaining]);
    }

    const BLOCK_WORDS: usize = 128;
    const SYNC_POINTS: u32 = 4;

    fn fbla(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
        let mul = |x: u64, y: u64| 2u64.wrapping_mul((x as u32 as u64).wrapping_mul(y as u32 as u64));
        *a = a.wrapping_add(*b).wrapping_add(mul(*a, *b)); *d = (*d ^ *a).rotate_right(32);
        *c = c.wrapping_add(*d).wrapping_add(mul(*c, *d)); *b = (*b ^ *c).rotate_right(24);
        *a = a.wrapping_add(*b).wrapping_add(mul(*a, *b)); *d = (*d ^ *a).rotate_right(16);
        *c = c.wrapping_add(*d).wrapping_add(mul(*c, *d)); *b = (*b ^ *c).rotate_right(63);
    }

    fn permute(v: &mut [u64; 16]) {
        let idx = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15), (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)];
        for (a, b, c, d) in idx {
            let (mut x, mut y, mut z, mut w) = (v[a], v[b], v[c], v[d]);
            fbla(&mut x, &mut y, &mut z, &mut w);
            v[a] = x; v[b] = y; v[c] = z; v[d] = w;
        }
    }

    fn compress_block(out: &mut [u64; BLOCK_WORDS], x: &[u64; BLOCK_WORDS], y: &[u64; BLOCK_WORDS], xor: bool) {
        let mut r = [0u64; BLOCK_WORDS];
        for i in 0..BLOCK_WORDS { r[i] = x[i] ^ y[i]; }
        let mut q = r;
        for row in 0..8 {
            let mut v = [0u64; 16];
            v.copy_from_slice(&q[row * 16..row * 16 + 16]);
            permute(&mut v);
            q[row * 16..row * 16 + 16].copy_from_slice(&v);
        }
        for column in 0..8 {
            let mut v = [0u64; 16];
            for i in 0..8 { v[2 * i] = q[16 * i + 2 * column]; v[2 * i + 1] = q[16 * i + 2 * column + 1]; }
            permute(&mut v);
            for i in 0..8 { q[16 * i + 2 * column] = v[2 * i]; q[16 * i + 2 * column + 1] = v[2 * i + 1]; }
        }
        for i in 0..BLOCK_WORDS { let value = q[i] ^ r[i]; out[i] = if xor { out[i] ^ value } else { value }; }
    }

    /// Argon2id, version 0x13, with no secret and no associated
    /// data; `out.len()` is the tag length (4..=64 here).
    pub fn argon2id(password: &[u8], salt: &[u8], t_cost: u32, memory_kib: u32, lanes: u32, out: &mut [u8]) -> Result<(), String> {
        if t_cost == 0 || lanes == 0 || salt.len() < 8 || out.len() < 4 || out.len() > 64 || memory_kib < 8 * lanes {
            return Err("argon2 parameters".into());
        }
        let segment_length = memory_kib / (SYNC_POINTS * lanes);
        let blocks = segment_length * SYNC_POINTS * lanes;
        let lane_length = blocks / lanes;
        let mut memory = vec![[0u64; BLOCK_WORDS]; blocks as usize];
        // H0.
        let mut h0 = [0u8; 64];
        let words = [lanes, out.len() as u32, memory_kib, t_cost, 0x13, 2];
        let mut inputs: Vec<Vec<u8>> = words.iter().map(|w| w.to_le_bytes().to_vec()).collect();
        inputs.push((password.len() as u32).to_le_bytes().to_vec());
        inputs.push(password.to_vec());
        inputs.push((salt.len() as u32).to_le_bytes().to_vec());
        inputs.push(salt.to_vec());
        inputs.push(0u32.to_le_bytes().to_vec());
        inputs.push(0u32.to_le_bytes().to_vec());
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        blake2b(&refs, &mut h0);
        for lane in 0..lanes {
            for i in 0..2u32 {
                let mut block = [0u8; 1024];
                h_prime(&[&h0, &i.to_le_bytes(), &lane.to_le_bytes()], &mut block);
                let target = &mut memory[(lane * lane_length + i) as usize];
                for w in 0..BLOCK_WORDS { target[w] = u64::from_le_bytes(block[8 * w..8 * w + 8].try_into().unwrap_or([0; 8])); }
            }
        }
        let zero = [0u64; BLOCK_WORDS];
        for pass in 0..t_cost {
            for slice in 0..SYNC_POINTS {
                for lane in 0..lanes {
                    let data_independent = pass == 0 && slice < SYNC_POINTS / 2;
                    let mut address = [0u64; BLOCK_WORDS];
                    let mut input = [0u64; BLOCK_WORDS];
                    if data_independent {
                        input[0] = pass as u64; input[1] = lane as u64; input[2] = slice as u64;
                        input[3] = blocks as u64; input[4] = t_cost as u64; input[5] = 2;
                    }
                    let mut start = 0u32;
                    if pass == 0 && slice == 0 {
                        start = 2;
                        if data_independent {
                            input[6] += 1;
                            let mut tmp = [0u64; BLOCK_WORDS];
                            compress_block(&mut tmp, &zero, &input, false);
                            compress_block(&mut address, &zero, &tmp, false);
                        }
                    }
                    let mut current = lane * lane_length + slice * segment_length + start;
                    let mut previous = if current % lane_length == 0 { current + lane_length - 1 } else { current - 1 };
                    for index in start..segment_length {
                        let (j1, j2) = if data_independent {
                            if index % BLOCK_WORDS as u32 == 0 {
                                input[6] += 1;
                                let mut tmp = [0u64; BLOCK_WORDS];
                                compress_block(&mut tmp, &zero, &input, false);
                                compress_block(&mut address, &zero, &tmp, false);
                            }
                            let word = address[index as usize % BLOCK_WORDS];
                            (word as u32, (word >> 32) as u32)
                        } else {
                            let word = memory[previous as usize][0];
                            (word as u32, (word >> 32) as u32)
                        };
                        let ref_lane = if pass == 0 && slice == 0 { lane } else { j2 % lanes };
                        let same_lane = ref_lane == lane;
                        let reference_area = if pass == 0 {
                            if slice == 0 { index - 1 }
                            else if same_lane { slice * segment_length + index - 1 }
                            else { slice * segment_length - if index == 0 { 1 } else { 0 } }
                        } else if same_lane { lane_length - segment_length + index - 1 }
                        else { lane_length - segment_length - if index == 0 { 1 } else { 0 } };
                        let mut relative = j1 as u64;
                        relative = (relative * relative) >> 32;
                        relative = reference_area as u64 - 1 - ((reference_area as u64 * relative) >> 32);
                        let start_position = if pass == 0 || slice == SYNC_POINTS - 1 { 0 } else { (slice + 1) * segment_length };
                        let ref_index = ((start_position as u64 + relative) % lane_length as u64) as u32;
                        let reference = (ref_lane * lane_length + ref_index) as usize;
                        let prev_block = memory[previous as usize];
                        let ref_block = memory[reference];
                        compress_block(&mut memory[current as usize], &prev_block, &ref_block, pass != 0);
                        previous = current;
                        current += 1;
                    }
                }
            }
        }
        let mut final_block = memory[(lane_length - 1) as usize];
        for lane in 1..lanes {
            let last = memory[(lane * lane_length + lane_length - 1) as usize];
            for i in 0..BLOCK_WORDS { final_block[i] ^= last[i]; }
        }
        let mut bytes = [0u8; 1024];
        for (i, word) in final_block.iter().enumerate() { bytes[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes()); }
        h_prime(&[&bytes], out);
        Ok(())
    }
}

/// Hexadecimal rendering of bytes.
pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Parse hexadecimal into bytes.
pub fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.len() % 2 != 0 { return Err("odd hex length".into()); }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| format!("bad hex `{text}`"))).collect()
}
