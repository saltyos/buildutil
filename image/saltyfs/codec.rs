// SPDX-License-Identifier: GPL-2.0-only
//! flake — the codecs of SaltyFS format 2, transcribed for the image
//! writer: the LZ4 block format and the Zstandard frame format (a full
//! decoder; an encoder over raw, RLE and predefined-table compressed
//! blocks), the FastCDC cut with the format's GEAR table, and xxh64 for the
//! Zstandard content checksum. Nothing here is shared with the provider or
//! the loader; the conformance tests cross-read their output.

// ---------------------------------------------------------------------------
// LZ4 block format
// ---------------------------------------------------------------------------

pub mod lz4 {
    const MIN_MATCH: usize = 4;
    const LAST_LITERALS: usize = 5;
    const MF_LIMIT: usize = 12;

    /// Decode a block; every run and match is bounds-checked first.
    pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize, String> {
        let mut ip = 0usize;
        let mut op = 0usize;
        if input.is_empty() { return Err("empty LZ4 block".into()); }
        loop {
            let token = *input.get(ip).ok_or("LZ4 block truncated at token")?;
            ip += 1;
            let mut literal_len = (token >> 4) as usize;
            if literal_len == 15 {
                loop {
                    let b = *input.get(ip).ok_or("LZ4 literal length truncated")?;
                    ip += 1;
                    literal_len += b as usize;
                    if b != 255 { break; }
                }
            }
            if ip + literal_len > input.len() || op + literal_len > output.len() { return Err("LZ4 literal run out of bounds".into()); }
            output[op..op + literal_len].copy_from_slice(&input[ip..ip + literal_len]);
            op += literal_len;
            ip += literal_len;
            if ip == input.len() { return Ok(op); }
            if ip + 2 > input.len() { return Err("LZ4 offset truncated".into()); }
            let offset = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
            ip += 2;
            if offset == 0 || offset > op { return Err("LZ4 offset before output start".into()); }
            let mut match_len = (token & 0x0F) as usize;
            if match_len == 15 {
                loop {
                    let b = *input.get(ip).ok_or("LZ4 match length truncated")?;
                    ip += 1;
                    match_len += b as usize;
                    if b != 255 { break; }
                }
            }
            match_len += MIN_MATCH;
            if op + match_len > output.len() { return Err("LZ4 match overruns output".into()); }
            for k in 0..match_len { output[op + k] = output[op - offset + k]; }
            op += match_len;
        }
    }

    /// Decode a block whose stored form is padded with zeros to a block
    /// multiple: the block ends when the output is full, and the padding
    /// must be zero.
    pub fn decompress_padded(input: &[u8], output: &mut [u8]) -> Result<(), String> {
        // Decode with a bound: the standard decoder stops at the input end,
        // so find the shortest prefix that decodes to exactly the output.
        // The block is self-delimiting given the output length: decode while
        // the output is not full.
        let mut ip = 0usize;
        let mut op = 0usize;
        while op < output.len() {
            let token = *input.get(ip).ok_or("LZ4 block truncated")?;
            ip += 1;
            let mut literal_len = (token >> 4) as usize;
            if literal_len == 15 {
                loop { let b = *input.get(ip).ok_or("LZ4 length truncated")?; ip += 1; literal_len += b as usize; if b != 255 { break; } }
            }
            if ip + literal_len > input.len() || op + literal_len > output.len() { return Err("LZ4 literal run out of bounds".into()); }
            output[op..op + literal_len].copy_from_slice(&input[ip..ip + literal_len]);
            op += literal_len;
            ip += literal_len;
            if op == output.len() { break; }
            if ip + 2 > input.len() { return Err("LZ4 offset truncated".into()); }
            let offset = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
            ip += 2;
            if offset == 0 || offset > op { return Err("LZ4 offset before output start".into()); }
            let mut match_len = (token & 0x0F) as usize;
            if match_len == 15 {
                loop { let b = *input.get(ip).ok_or("LZ4 length truncated")?; ip += 1; match_len += b as usize; if b != 255 { break; } }
            }
            match_len += MIN_MATCH;
            if op + match_len > output.len() { return Err("LZ4 match overruns output".into()); }
            for k in 0..match_len { output[op + k] = output[op - offset + k]; }
            op += match_len;
        }
        if input[ip..].iter().any(|b| *b != 0) { return Err("LZ4 padding is not zero".into()); }
        Ok(())
    }

    fn write_length(out: &mut Vec<u8>, mut len: usize) {
        while len >= 255 { out.push(255); len -= 255; }
        out.push(len as u8);
    }

    fn emit(out: &mut Vec<u8>, literals: &[u8], match_len: usize, offset: usize) {
        let token_at = out.len();
        out.push(0);
        let lit_len = literals.len();
        let mut token = if lit_len >= 15 { 0xF0 } else { (lit_len as u8) << 4 };
        if lit_len >= 15 { write_length(out, lit_len - 15); }
        out.extend_from_slice(literals);
        if match_len != 0 {
            out.extend_from_slice(&(offset as u16).to_le_bytes());
            let ml = match_len - MIN_MATCH;
            if ml >= 15 { token |= 0x0F; write_length(out, ml - 15); } else { token |= ml as u8; }
        }
        out[token_at] = token;
    }

    /// Greedy hash-table encoder; offsets stay within 65535 bytes.
    pub fn compress(input: &[u8]) -> Vec<u8> {
        let n = input.len();
        let mut out = Vec::with_capacity(n + n / 255 + 16);
        if n < MF_LIMIT + 1 { emit(&mut out, input, 0, 0); return out; }
        let mut table = vec![u32::MAX; 1 << 12];
        let hash = |at: usize| -> usize {
            let v = u32::from_le_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]);
            (v.wrapping_mul(2_654_435_761) >> 20) as usize
        };
        let limit = n - LAST_LITERALS;
        let mut anchor = 0usize;
        let mut ip = 0usize;
        while ip + MIN_MATCH <= limit && ip + MF_LIMIT <= n {
            let h = hash(ip);
            let candidate = table[h];
            table[h] = ip as u32;
            let Some(candidate) = (candidate != u32::MAX).then_some(candidate as usize) else { ip += 1; continue };
            let offset = ip - candidate;
            if offset > 65535 || input[candidate..candidate + 4] != input[ip..ip + 4] { ip += 1; continue; }
            let mut match_len = MIN_MATCH;
            while ip + match_len < limit && input[candidate + match_len] == input[ip + match_len] { match_len += 1; }
            emit(&mut out, &input[anchor..ip], match_len, offset);
            ip += match_len;
            anchor = ip;
        }
        emit(&mut out, &input[anchor..], 0, 0);
        out
    }
}

// ---------------------------------------------------------------------------
// Zstandard
// ---------------------------------------------------------------------------

pub mod zstd {
    const MAGIC: u32 = 0xFD2F_B528;
    pub const BLOCK_MAX: usize = 128 * 1024;
    const LL_DEFAULT: [i16; 36] = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
    const ML_DEFAULT: [i16; 53] = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1];
    const OF_DEFAULT: [i16; 29] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];
    const LL_BASE: [u32; 36] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
        2048, 4096, 8192, 16384, 32768, 65536];
    const LL_BITS: [u8; 36] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const ML_BASE: [u32; 53] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
        34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539];
    const ML_BITS: [u8; 53] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3,
        4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    fn highbit(v: u32) -> u32 { 31 - v.leading_zeros() }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FrameHeader { pub content_size: Option<u64>, pub window_size: u64, pub single_segment: bool, pub checksum: bool, pub header_len: usize }

    pub fn frame_header(input: &[u8]) -> Result<FrameHeader, String> {
        if input.len() < 5 { return Err("zstd frame truncated".into()); }
        if u32::from_le_bytes([input[0], input[1], input[2], input[3]]) != MAGIC { return Err("zstd magic".into()); }
        let fhd = input[4];
        let fcs_flag = fhd >> 6;
        let single_segment = fhd & 0x20 != 0;
        if fhd & 0x18 != 0 { return Err("zstd frame header reserved bits".into()); }
        let checksum = fhd & 0x04 != 0;
        if fhd & 0x03 != 0 { return Err("zstd dictionary id".into()); }
        let mut at = 5usize;
        let mut window_size = 0u64;
        if !single_segment {
            let wd = *input.get(at).ok_or("zstd window descriptor")?;
            at += 1;
            let base = 1u64 << (10 + (wd >> 3) as u64);
            window_size = base + (base / 8) * (wd & 7) as u64;
        }
        let fcs_len = match fcs_flag { 0 => if single_segment { 1 } else { 0 }, 1 => 2, 2 => 4, _ => 8 };
        if input.len() < at + fcs_len { return Err("zstd frame content size truncated".into()); }
        let content_size = match fcs_len {
            0 => None,
            1 => Some(input[at] as u64),
            2 => Some(u16::from_le_bytes([input[at], input[at + 1]]) as u64 + 256),
            4 => Some(u32::from_le_bytes(input[at..at + 4].try_into().unwrap_or([0; 4])) as u64),
            _ => Some(u64::from_le_bytes(input[at..at + 8].try_into().unwrap_or([0; 8]))),
        };
        at += fcs_len;
        if single_segment { window_size = content_size.unwrap_or(0); }
        Ok(FrameHeader { content_size, window_size, single_segment, checksum, header_len: at })
    }

    struct Forward<'a> { data: &'a [u8], bit: usize }
    impl Forward<'_> {
        fn read(&mut self, n: u32) -> Result<u32, String> {
            let mut v = 0u32;
            for i in 0..n {
                let byte = *self.data.get(self.bit / 8).ok_or("FSE table truncated")?;
                v |= (((byte >> (self.bit % 8)) & 1) as u32) << i;
                self.bit += 1;
            }
            Ok(v)
        }
        fn peek(&self, n: u32) -> Result<u32, String> { Forward { data: self.data, bit: self.bit }.read(n) }
        fn skip(&mut self, n: u32) { self.bit += n as usize; }
        fn consumed(&self) -> usize { self.bit.div_ceil(8) }
    }

    struct Reverse<'a> { data: &'a [u8], bits_left: i64 }
    impl<'a> Reverse<'a> {
        fn new(data: &'a [u8]) -> Result<Self, String> {
            let last = *data.last().ok_or("empty bitstream")?;
            if last == 0 { return Err("bitstream padding".into()); }
            Ok(Self { data, bits_left: (data.len() as i64 - 1) * 8 + (7 - last.leading_zeros() as i64) })
        }
        fn read(&mut self, n: u32) -> u32 {
            let mut v = 0u32;
            for _ in 0..n {
                v <<= 1;
                self.bits_left -= 1;
                if self.bits_left >= 0 { v |= ((self.data[(self.bits_left / 8) as usize] >> (self.bits_left % 8)) & 1) as u32; }
            }
            v
        }
        fn peek(&self, n: u32) -> u32 { Reverse { data: self.data, bits_left: self.bits_left }.read(n) }
        fn skip(&mut self, n: u32) { self.bits_left -= n as i64; }
        fn exhausted(&self) -> bool { self.bits_left == 0 }
        fn overread(&self) -> bool { self.bits_left < 0 }
    }

    #[derive(Clone, Copy, Default)]
    struct FseEntry { symbol: u8, nb_bits: u8, base: u16 }

    #[derive(Clone)]
    struct FseTable { log: u8, entries: Vec<FseEntry> }

    impl FseTable {
        fn build(counts: &[i16], log: u8) -> Result<Self, String> {
            if log > 9 || counts.len() > 256 { return Err("FSE table log".into()); }
            let size = 1usize << log;
            let mask = size - 1;
            let mut entries = vec![FseEntry::default(); size];
            let mut symbol_next = [0u16; 256];
            let mut high = size - 1;
            for (s, &count) in counts.iter().enumerate() {
                if count == -1 { entries[high].symbol = s as u8; high = high.checked_sub(1).ok_or("FSE spread")?; symbol_next[s] = 1; }
                else { symbol_next[s] = count as u16; }
            }
            let step = (size >> 1) + (size >> 3) + 3;
            let mut position = 0usize;
            for (s, &count) in counts.iter().enumerate() {
                if count <= 0 { continue; }
                for _ in 0..count {
                    entries[position].symbol = s as u8;
                    position = (position + step) & mask;
                    while position > high { position = (position + step) & mask; }
                }
            }
            if position != 0 { return Err("FSE spread did not close".into()); }
            for u in 0..size {
                let s = entries[u].symbol as usize;
                let next = symbol_next[s];
                symbol_next[s] += 1;
                let nb_bits = log as u32 - highbit(next as u32);
                entries[u].nb_bits = nb_bits as u8;
                entries[u].base = (((next as u32) << nb_bits) as usize - size) as u16;
            }
            Ok(Self { log, entries })
        }
        fn rle(symbol: u8) -> Self { Self { log: 0, entries: vec![FseEntry { symbol, nb_bits: 0, base: 0 }] } }
        fn read(data: &[u8], max_symbol: usize, max_log: u8) -> Result<(Self, usize), String> {
            let mut bits = Forward { data, bit: 0 };
            let log = 5 + bits.read(4)? as u8;
            if log > max_log { return Err("FSE table log above the maximum".into()); }
            let size = 1i32 << log;
            let mut counts = [0i16; 256];
            let mut remaining = size + 1;
            let mut symbol = 0usize;
            while remaining > 1 && symbol <= max_symbol {
                let nb_bits = highbit(remaining as u32) + 1;
                let threshold = 1i32 << (nb_bits - 1);
                let max = 2 * threshold - 1 - remaining;
                let mut value = bits.peek(nb_bits - 1)? as i32;
                if value < max { bits.skip(nb_bits - 1); } else { value = bits.read(nb_bits)? as i32; if value >= threshold { value -= max; } }
                let count = value - 1;
                counts[symbol] = count as i16;
                remaining -= if count == -1 { 1 } else { count };
                symbol += 1;
                if count == 0 {
                    loop {
                        let repeat = bits.read(2)? as usize;
                        for _ in 0..repeat { if symbol > max_symbol { return Err("FSE repeat past the alphabet".into()); } counts[symbol] = 0; symbol += 1; }
                        if repeat < 3 { break; }
                    }
                }
            }
            if remaining != 1 { return Err("FSE counts do not sum to the table".into()); }
            Ok((Self::build(&counts[..symbol], log)?, bits.consumed()))
        }
    }

    struct FseState(usize);
    impl FseState {
        fn init(bits: &mut Reverse<'_>, table: &FseTable) -> Self { Self(bits.read(table.log as u32) as usize) }
        fn symbol(&self, table: &FseTable) -> u8 { table.entries[self.0].symbol }
        fn update(&mut self, bits: &mut Reverse<'_>, table: &FseTable) {
            let e = table.entries[self.0];
            self.0 = e.base as usize + bits.read(e.nb_bits as u32) as usize;
        }
    }

    #[derive(Clone, Copy, Default)]
    struct HufEntry { symbol: u8, nb_bits: u8 }
    struct HufTable { max_bits: u8, entries: Vec<HufEntry> }

    impl HufTable {
        fn from_weights(weights: &[u8]) -> Result<Self, String> {
            let mut sum = 0u32;
            for &w in weights { if w > 11 { return Err("Huffman weight".into()); } if w != 0 { sum += 1 << (w - 1); } }
            if sum == 0 { return Err("Huffman weights sum to zero".into()); }
            let max_bits = highbit(sum) + 1;
            if max_bits > 11 || (1u32 << max_bits) != sum { return Err("Huffman weights are not a power of two".into()); }
            let mut entries = vec![HufEntry::default(); 1 << max_bits];
            let mut position = 0usize;
            for w in 1..=max_bits as u8 {
                let nb_bits = max_bits as u8 + 1 - w;
                let run = 1usize << (w - 1);
                for (s, &weight) in weights.iter().enumerate() {
                    if weight != w { continue; }
                    for i in 0..run { entries[position + i] = HufEntry { symbol: s as u8, nb_bits }; }
                    position += run;
                }
            }
            Ok(Self { max_bits: max_bits as u8, entries })
        }
        fn read(data: &[u8]) -> Result<(Self, usize), String> {
            let header = *data.first().ok_or("Huffman header")?;
            let mut weights = [0u8; 256];
            let mut count;
            let consumed;
            if header < 128 {
                let stream = data.get(1..1 + header as usize).ok_or("Huffman stream truncated")?;
                let (table, used) = FseTable::read(stream, 255, 6)?;
                let mut bits = Reverse::new(&stream[used..])?;
                let mut a = FseState::init(&mut bits, &table);
                let mut b = FseState::init(&mut bits, &table);
                count = 0usize;
                loop {
                    if count >= 255 { return Err("Huffman weights overflow".into()); }
                    weights[count] = a.symbol(&table); count += 1;
                    a.update(&mut bits, &table);
                    if bits.overread() { if count >= 255 { return Err("Huffman weights overflow".into()); } weights[count] = b.symbol(&table); count += 1; break; }
                    if count >= 255 { return Err("Huffman weights overflow".into()); }
                    weights[count] = b.symbol(&table); count += 1;
                    b.update(&mut bits, &table);
                    if bits.overread() { if count >= 255 { return Err("Huffman weights overflow".into()); } weights[count] = a.symbol(&table); count += 1; break; }
                }
                consumed = 1 + header as usize;
            } else {
                count = (header - 127) as usize;
                let bytes = count.div_ceil(2);
                let stream = data.get(1..1 + bytes).ok_or("Huffman direct weights truncated")?;
                for i in 0..count { weights[i] = if i % 2 == 0 { stream[i / 2] >> 4 } else { stream[i / 2] & 0x0F }; }
                consumed = 1 + bytes;
            }
            let mut sum = 0u32;
            for &w in &weights[..count] { if w > 11 { return Err("Huffman weight".into()); } if w != 0 { sum += 1 << (w - 1); } }
            if sum == 0 { return Err("Huffman weights sum to zero".into()); }
            let max_bits = highbit(sum) + 1;
            let left = (1u32 << max_bits) - sum;
            if left == 0 || left & (left - 1) != 0 { return Err("Huffman last weight".into()); }
            weights[count] = highbit(left) as u8 + 1;
            count += 1;
            Ok((Self::from_weights(&weights[..count])?, consumed))
        }
        fn decode_stream(&self, stream: &[u8], out: &mut [u8]) -> Result<(), String> {
            let mut bits = Reverse::new(stream)?;
            for slot in out.iter_mut() {
                let e = self.entries[bits.peek(self.max_bits as u32) as usize];
                bits.skip(e.nb_bits as u32);
                *slot = e.symbol;
            }
            if bits.overread() || !bits.exhausted() { return Err("Huffman stream length".into()); }
            Ok(())
        }
    }

    /// Decode one frame; `output` receives the content.
    pub fn decompress(input: &[u8]) -> Result<Vec<u8>, String> {
        let header = frame_header(input)?;
        let mut at = header.header_len;
        let mut out: Vec<u8> = Vec::new();
        let mut reps = [1u32, 4, 8];
        let mut tables: [Option<FseTable>; 3] = [None, None, None];
        let mut huf: Option<HufTable> = None;
        loop {
            if input.len() < at + 3 { return Err("zstd block header truncated".into()); }
            let bh = u32::from_le_bytes([input[at], input[at + 1], input[at + 2], 0]);
            at += 3;
            let last = bh & 1 != 0;
            let kind = (bh >> 1) & 3;
            let size = (bh >> 3) as usize;
            match kind {
                0 => { out.extend_from_slice(input.get(at..at + size).ok_or("zstd raw block truncated")?); at += size; }
                1 => { if size > BLOCK_MAX { return Err("zstd RLE block too large".into()); } let byte = *input.get(at).ok_or("zstd RLE byte")?; out.resize(out.len() + size, byte); at += 1; }
                2 => {
                    if size > BLOCK_MAX { return Err("zstd block too large".into()); }
                    let block = input.get(at..at + size).ok_or("zstd compressed block truncated")?;
                    compressed_block(block, &mut out, &mut reps, &mut tables, &mut huf)?;
                    at += size;
                }
                _ => return Err("zstd reserved block".into()),
            }
            if last { break; }
        }
        if let Some(expected) = header.content_size { if expected != out.len() as u64 { return Err("zstd content size disagrees".into()); } }
        if header.checksum {
            let stored = input.get(at..at + 4).ok_or("zstd checksum truncated")?;
            if stored != (xxh64(&out, 0) as u32).to_le_bytes() { return Err("zstd checksum".into()); }
        }
        Ok(out)
    }

    fn compressed_block(block: &[u8], out: &mut Vec<u8>, reps: &mut [u32; 3], tables: &mut [Option<FseTable>; 3], huf: &mut Option<HufTable>) -> Result<(), String> {
        let b0 = *block.first().ok_or("literals header")?;
        let kind = b0 & 3;
        let size_format = (b0 >> 2) & 3;
        let get = |i: usize| -> Result<usize, String> { block.get(i).map(|b| *b as usize).ok_or_else(|| "literals header truncated".to_string()) };
        let (regenerated, compressed, streams, header_len) = if kind <= 1 {
            match size_format {
                0 | 2 => ((b0 >> 3) as usize, 0, 1, 1),
                1 => (((b0 >> 4) as usize) | (get(1)? << 4), 0, 1, 2),
                _ => (((b0 >> 4) as usize) | (get(1)? << 4) | (get(2)? << 12), 0, 1, 3),
            }
        } else {
            let (streams, bits, header_len) = match size_format { 0 => (1, 10, 3), 1 => (4, 10, 3), 2 => (4, 14, 4), _ => (4, 18, 5) };
            let mut value = 0u64;
            for i in 0..header_len { value |= (get(i)? as u64) << (8 * i); }
            value >>= 4;
            let mask = (1u64 << bits) - 1;
            ((value & mask) as usize, ((value >> bits) & mask) as usize, streams, header_len)
        };
        if regenerated > BLOCK_MAX { return Err("literals too large".into()); }
        let mut at = header_len;
        let mut literals = vec![0u8; regenerated];
        match kind {
            0 => { literals.copy_from_slice(block.get(at..at + regenerated).ok_or("raw literals truncated")?); at += regenerated; }
            1 => { literals.fill(*block.get(at).ok_or("RLE literal")?); at += 1; }
            _ => {
                let section = block.get(at..at + compressed).ok_or("literals section truncated")?;
                let mut offset = 0usize;
                if kind == 2 { let (table, used) = HufTable::read(section)?; *huf = Some(table); offset = used; }
                let table = huf.as_ref().ok_or("repeat Huffman table without one")?;
                let body = &section[offset..];
                if streams == 1 { table.decode_stream(body, &mut literals)?; } else {
                    if body.len() < 6 { return Err("four-stream literals header".into()); }
                    let s1 = u16::from_le_bytes([body[0], body[1]]) as usize;
                    let s2 = u16::from_le_bytes([body[2], body[3]]) as usize;
                    let s3 = u16::from_le_bytes([body[4], body[5]]) as usize;
                    let rest = &body[6..];
                    if s1 + s2 + s3 > rest.len() { return Err("four-stream literals sizes".into()); }
                    let each = (regenerated + 3) / 4;
                    if each * 3 > regenerated { return Err("four-stream literals split".into()); }
                    let parts = [&rest[..s1], &rest[s1..s1 + s2], &rest[s1 + s2..s1 + s2 + s3], &rest[s1 + s2 + s3..]];
                    let (head, tail) = literals.split_at_mut(each * 3);
                    for (i, chunk) in head.chunks_mut(each).enumerate() { table.decode_stream(parts[i], chunk)?; }
                    table.decode_stream(parts[3], tail)?;
                }
                at += compressed;
            }
        }
        let seq = block.get(at..).ok_or("sequences section")?;
        let b0 = *seq.first().ok_or("sequences header")?;
        let (nb_seq, mut sat) = if b0 == 0 { (0usize, 1usize) } else if b0 < 128 { (b0 as usize, 1) }
            else if b0 < 255 { (((b0 as usize - 128) << 8) + *seq.get(1).ok_or("sequences header")? as usize, 2) }
            else { (*seq.get(1).ok_or("sequences header")? as usize + ((*seq.get(2).ok_or("sequences header")? as usize) << 8) + 0x7F00, 3) };
        if nb_seq == 0 { out.extend_from_slice(&literals); return Ok(()); }
        let modes = *seq.get(sat).ok_or("sequence modes")?;
        sat += 1;
        if modes & 3 != 0 { return Err("sequence modes reserved bits".into()); }
        let specs: [(u8, &[i16], u8, usize, u8); 3] = [
            (modes >> 6, &LL_DEFAULT, 6, 35, 9), (((modes >> 4) & 3), &OF_DEFAULT, 5, 31, 8), (((modes >> 2) & 3), &ML_DEFAULT, 6, 52, 9),
        ];
        for (index, (mode, default, log, max_symbol, max_log)) in specs.iter().enumerate() {
            match mode {
                0 => { tables[index] = Some(FseTable::build(default, *log)?); }
                1 => { let symbol = *seq.get(sat).ok_or("RLE symbol")?; if symbol as usize > *max_symbol { return Err("RLE symbol".into()); } tables[index] = Some(FseTable::rle(symbol)); sat += 1; }
                2 => { let (table, used) = FseTable::read(&seq[sat..], *max_symbol, *max_log)?; tables[index] = Some(table); sat += used; }
                _ => { if tables[index].is_none() { return Err("repeat FSE table without one".into()); } }
            }
        }
        let (ll, of, ml) = (tables[0].as_ref().ok_or("ll table")?, tables[1].as_ref().ok_or("of table")?, tables[2].as_ref().ok_or("ml table")?);
        let mut bits = Reverse::new(&seq[sat..])?;
        let mut ll_state = FseState::init(&mut bits, ll);
        let mut of_state = FseState::init(&mut bits, of);
        let mut ml_state = FseState::init(&mut bits, ml);
        let mut lit_at = 0usize;
        for i in 0..nb_seq {
            let of_code = of_state.symbol(of) as u32;
            if of_code > 31 { return Err("offset code".into()); }
            let of_value = (1u32 << of_code) + bits.read(of_code);
            let ml_code = ml_state.symbol(ml) as usize;
            if ml_code > 52 { return Err("match length code".into()); }
            let match_len = ML_BASE[ml_code] + bits.read(ML_BITS[ml_code] as u32);
            let ll_code = ll_state.symbol(ll) as usize;
            if ll_code > 35 { return Err("literal length code".into()); }
            let lit_len = LL_BASE[ll_code] + bits.read(LL_BITS[ll_code] as u32);
            if i + 1 < nb_seq { ll_state.update(&mut bits, ll); ml_state.update(&mut bits, ml); of_state.update(&mut bits, of); }
            let offset = if of_value > 3 { let o = of_value - 3; *reps = [o, reps[0], reps[1]]; o } else {
                let index = if lit_len == 0 { of_value } else { of_value - 1 };
                let o = match index {
                    0 => reps[0],
                    1 => { let o = reps[1]; *reps = [o, reps[0], reps[2]]; o }
                    2 => { let o = reps[2]; *reps = [o, reps[0], reps[1]]; o }
                    _ => { let o = reps[0].checked_sub(1).ok_or("repeat offset underflow")?; *reps = [o, reps[0], reps[1]]; o }
                };
                if o == 0 { return Err("zero offset".into()); }
                o
            };
            let lit_len = lit_len as usize;
            out.extend_from_slice(literals.get(lit_at..lit_at + lit_len).ok_or("literals exhausted")?);
            lit_at += lit_len;
            let offset = offset as usize;
            if offset > out.len() { return Err("match before output start".into()); }
            let start = out.len() - offset;
            for k in 0..match_len as usize { let b = out[start + k]; out.push(b); }
        }
        if bits.overread() || !bits.exhausted() { return Err("sequence bitstream length".into()); }
        out.extend_from_slice(&literals[lit_at..]);
        Ok(())
    }

    // -- encoder -----------------------------------------------------------

    struct BitWriter { out: Vec<u8>, acc: u64, count: u32 }
    impl BitWriter {
        fn new() -> Self { Self { out: Vec::new(), acc: 0, count: 0 } }
        fn add(&mut self, value: u32, bits: u32) {
            if bits == 0 { return; }
            self.acc |= ((value as u64) & ((1u64 << bits) - 1)) << self.count;
            self.count += bits;
            while self.count >= 8 { self.out.push(self.acc as u8); self.acc >>= 8; self.count -= 8; }
        }
        fn close(mut self) -> Vec<u8> {
            self.add(1, 1);
            if self.count > 0 { self.out.push(self.acc as u8); }
            self.out
        }
    }

    struct FseEncoder { log: u8, next_state: Vec<u16>, delta_nb_bits: Vec<u32>, delta_find_state: Vec<i32> }
    impl FseEncoder {
        fn build(counts: &[i16], log: u8) -> Result<Self, String> {
            let size = 1usize << log;
            let table = FseTable::build(counts, log)?;
            let mut cumul = vec![0i32; counts.len() + 1];
            for s in 0..counts.len() { cumul[s + 1] = cumul[s] + counts[s].unsigned_abs() as i32; }
            let mut next_state = vec![0u16; size];
            let mut fill = cumul.clone();
            for (u, entry) in table.entries.iter().enumerate() {
                let s = entry.symbol as usize;
                next_state[fill[s] as usize] = (size + u) as u16;
                fill[s] += 1;
            }
            let mut delta_nb_bits = vec![0u32; counts.len()];
            let mut delta_find_state = vec![0i32; counts.len()];
            let mut total = 0i32;
            for (s, &count) in counts.iter().enumerate() {
                match count {
                    0 => { delta_nb_bits[s] = ((log as u32 + 1) << 16) - (1 << log); }
                    -1 | 1 => { delta_nb_bits[s] = ((log as u32) << 16) - (1 << log); delta_find_state[s] = total - 1; total += 1; }
                    c => {
                        let max_bits_out = log as u32 - highbit(c as u32 - 1);
                        let min_state_plus = (c as u32) << max_bits_out;
                        delta_nb_bits[s] = (max_bits_out << 16) - min_state_plus;
                        delta_find_state[s] = total - c as i32;
                        total += c as i32;
                    }
                }
            }
            Ok(Self { log, next_state, delta_nb_bits, delta_find_state })
        }
        fn init_state(&self, symbol: usize) -> u32 {
            let nb_bits = (self.delta_nb_bits[symbol] + (1 << 15)) >> 16;
            let state = (nb_bits << 16).wrapping_sub(self.delta_nb_bits[symbol]);
            self.next_state[((state >> nb_bits) as i32 + self.delta_find_state[symbol]) as usize] as u32
        }
        fn encode(&self, bits: &mut BitWriter, state: u32, symbol: usize) -> u32 {
            let nb_bits = state.wrapping_add(self.delta_nb_bits[symbol]) >> 16;
            bits.add(state, nb_bits);
            self.next_state[((state >> nb_bits) as i32 + self.delta_find_state[symbol]) as usize] as u32
        }
        fn flush(&self, bits: &mut BitWriter, state: u32) { bits.add(state, self.log as u32); }
    }

    fn ll_code_exact(v: u32) -> usize {
        // The literal-length code from the baselines table, searched directly.
        let mut code = 0usize;
        for (i, &base) in LL_BASE.iter().enumerate() { if v >= base { code = i; } }
        code
    }
    fn ml_code_exact(v: u32) -> usize {
        let mut code = 0usize;
        for (i, &base) in ML_BASE.iter().enumerate() { if v >= base { code = i; } }
        code
    }

    #[derive(Clone, Copy)]
    struct Sequence { lit_len: u32, offset: u32, match_len: u32 }

    fn find_sequences(input: &[u8]) -> (Vec<Sequence>, usize) {
        let n = input.len();
        let mut table = vec![u32::MAX; 1 << 12];
        let hash = |at: usize| -> usize {
            let v = u32::from_le_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]);
            (v.wrapping_mul(2_654_435_761) >> 20) as usize
        };
        let mut sequences = Vec::new();
        let mut anchor = 0usize;
        let mut ip = 0usize;
        while ip + 4 <= n {
            let h = hash(ip);
            let candidate = table[h];
            table[h] = ip as u32;
            if candidate == u32::MAX { ip += 1; continue; }
            let candidate = candidate as usize;
            if input[candidate..candidate + 4] != input[ip..ip + 4] { ip += 1; continue; }
            let mut match_len = 4usize;
            while ip + match_len < n && input[candidate + match_len] == input[ip + match_len] { match_len += 1; }
            sequences.push(Sequence { lit_len: (ip - anchor) as u32, offset: (ip - candidate) as u32, match_len: match_len as u32 });
            ip += match_len;
            anchor = ip;
        }
        (sequences, anchor)
    }

    fn compressed_sequences_block(chunk: &[u8]) -> Result<Vec<u8>, String> {
        let (sequences, anchor) = find_sequences(chunk);
        if sequences.is_empty() { return Err("no sequences".into()); }
        let mut out = Vec::new();
        let lit_total = chunk.len() - sequences.iter().map(|s| s.match_len as usize).sum::<usize>();
        if lit_total < 32 { out.push((lit_total as u8) << 3); }
        else if lit_total < 4096 { out.push(0x04 | ((lit_total as u8 & 0x0F) << 4)); out.push((lit_total >> 4) as u8); }
        else { out.push(0x0C | ((lit_total as u8 & 0x0F) << 4)); out.push((lit_total >> 4) as u8); out.push((lit_total >> 12) as u8); }
        let mut cursor = 0usize;
        for s in &sequences { out.extend_from_slice(&chunk[cursor..cursor + s.lit_len as usize]); cursor += (s.lit_len + s.match_len) as usize; }
        out.extend_from_slice(&chunk[anchor..]);
        let count = sequences.len();
        if count < 128 { out.push(count as u8); }
        else if count < 0x7F00 { out.push(((count >> 8) as u8) + 128); out.push(count as u8); }
        else { let v = count - 0x7F00; out.push(255); out.push(v as u8); out.push((v >> 8) as u8); }
        out.push(0);
        let ll = FseEncoder::build(&LL_DEFAULT, 6)?;
        let of = FseEncoder::build(&OF_DEFAULT, 5)?;
        let ml = FseEncoder::build(&ML_DEFAULT, 6)?;
        let mut bits = BitWriter::new();
        let codes = |s: &Sequence| (ll_code_exact(s.lit_len), highbit(s.offset + 3) as usize, ml_code_exact(s.match_len));
        let last = sequences[count - 1];
        let (llc, ofc, mlc) = codes(&last);
        if ofc >= 29 { return Err("offset code".into()); }
        let mut ml_state = ml.init_state(mlc);
        let mut of_state = of.init_state(ofc);
        let mut ll_state = ll.init_state(llc);
        bits.add(last.lit_len - LL_BASE[llc], LL_BITS[llc] as u32);
        bits.add(last.match_len - ML_BASE[mlc], ML_BITS[mlc] as u32);
        bits.add(last.offset + 3, ofc as u32);
        for i in (0..count - 1).rev() {
            let s = sequences[i];
            let (llc, ofc, mlc) = codes(&s);
            if ofc >= 29 { return Err("offset code".into()); }
            of_state = of.encode(&mut bits, of_state, ofc);
            ml_state = ml.encode(&mut bits, ml_state, mlc);
            ll_state = ll.encode(&mut bits, ll_state, llc);
            bits.add(s.lit_len - LL_BASE[llc], LL_BITS[llc] as u32);
            bits.add(s.match_len - ML_BASE[mlc], ML_BITS[mlc] as u32);
            bits.add(s.offset + 3, ofc as u32);
        }
        ml.flush(&mut bits, ml_state);
        of.flush(&mut bits, of_state);
        ll.flush(&mut bits, ll_state);
        out.extend_from_slice(&bits.close());
        Ok(out)
    }

    /// Encode `input` as one frame. `single_segment` declares the content
    /// size and no window (a chunk body); otherwise the window is the block
    /// size, at most 128 KiB.
    pub fn compress(input: &[u8], single_segment: bool) -> Vec<u8> {
        let mut out = MAGIC.to_le_bytes().to_vec();
        let len = input.len() as u64;
        if single_segment {
            if len < 256 { out.extend_from_slice(&[0x20, len as u8]); }
            else if len < 65_536 + 256 { out.push(0x60); out.extend_from_slice(&((len - 256) as u16).to_le_bytes()); }
            else if len <= u32::MAX as u64 { out.push(0xA0); out.extend_from_slice(&(len as u32).to_le_bytes()); }
            else { out.push(0xE0); out.extend_from_slice(&len.to_le_bytes()); }
        } else {
            let window = input.len().max(1024).next_power_of_two().min(BLOCK_MAX);
            out.extend_from_slice(&[0x00, ((window.trailing_zeros() - 10) as u8) << 3]);
        }
        if input.is_empty() { out.extend_from_slice(&[0x01, 0x00, 0x00]); return out; }
        let block_max = if single_segment { BLOCK_MAX } else { input.len().max(1024).next_power_of_two().min(BLOCK_MAX) };
        let mut chunks = input.chunks(block_max).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none() as u32;
            let header = |kind: u32, size: usize| (last | (kind << 1) | ((size as u32) << 3)).to_le_bytes()[..3].to_vec();
            if chunk.iter().all(|b| *b == chunk[0]) {
                out.extend_from_slice(&header(1, chunk.len()));
                out.push(chunk[0]);
                continue;
            }
            match compressed_sequences_block(chunk) {
                Ok(body) if body.len() < chunk.len() => { out.extend_from_slice(&header(2, body.len())); out.extend_from_slice(&body); }
                _ => { out.extend_from_slice(&header(0, chunk.len())); out.extend_from_slice(chunk); }
            }
        }
        out
    }

    const P1: u64 = 0x9E37_79B1_85EB_CA87;
    const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const P3: u64 = 0x1656_67B1_9E37_79F9;
    const P4: u64 = 0x85EB_CA77_C2B2_AE63;
    const P5: u64 = 0x27D4_EB2F_1656_67C5;

    fn round(acc: u64, input: u64) -> u64 { acc.wrapping_add(input.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1) }
    fn merge(acc: u64, v: u64) -> u64 { (acc ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4) }

    pub fn xxh64(data: &[u8], seed: u64) -> u64 {
        let mut at = 0usize;
        let mut h = if data.len() >= 32 {
            let mut v = [seed.wrapping_add(P1).wrapping_add(P2), seed.wrapping_add(P2), seed, seed.wrapping_sub(P1)];
            while at + 32 <= data.len() {
                for i in 0..4 { v[i] = round(v[i], u64::from_le_bytes(data[at + 8 * i..at + 8 * i + 8].try_into().unwrap_or([0; 8]))); }
                at += 32;
            }
            let mut h = v[0].rotate_left(1).wrapping_add(v[1].rotate_left(7)).wrapping_add(v[2].rotate_left(12)).wrapping_add(v[3].rotate_left(18));
            for x in v { h = merge(h, x); }
            h
        } else { seed.wrapping_add(P5) };
        h = h.wrapping_add(data.len() as u64);
        while at + 8 <= data.len() {
            let k = round(0, u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or([0; 8])));
            h = (h ^ k).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            at += 8;
        }
        if at + 4 <= data.len() {
            let k = u32::from_le_bytes(data[at..at + 4].try_into().unwrap_or([0; 4])) as u64;
            h = (h ^ k.wrapping_mul(P1)).rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
            at += 4;
        }
        while at < data.len() { h = (h ^ (data[at] as u64).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1); at += 1; }
        h ^= h >> 33; h = h.wrapping_mul(P2); h ^= h >> 29; h = h.wrapping_mul(P3); h ^= h >> 32;
        h
    }
}

// ---------------------------------------------------------------------------
// FastCDC
// ---------------------------------------------------------------------------

pub mod fastcdc {
    /// The format's GEAR table.
    pub const GEAR: [u64; 256] = [
        0x3b5d3c7d207e37dc, 0x784d68ba91123086, 0xcd52880f882e7298, 0xeacf8e4e19fdcca7, 0xc31f385dfbd1632b, 0x1d5f27001e25abe6, 0x83130bde3c9ad991, 0xc4b225676e9b7649,
        0xaa329b29e08eb499, 0xb67fcbd21e577d58, 0x0027baaada2acf6b, 0xe3ef2d5ac73c2226, 0x0890f24d6ed312b7, 0xa809e036851d7c7e, 0xf0a6fe5e0013d81b, 0x1d026304452cec14,
        0x03864632648e248f, 0xcdaacf3dcd92b9b4, 0xf5e012e63c187856, 0x8862f9d3821c00b6, 0xa82f7338750f6f8a, 0x1e583dc6c1cb0b6f, 0x7a3145b69743a7f1, 0xabb20fee404807eb,
        0xb14b3cfe07b83a5d, 0xb9dc27898adb9a0f, 0x3703f5e91baa62be, 0xcf0bb866815f7d98, 0x3d9867c41ea9dcd3, 0x1be1fa65442bf22c, 0x14300da4c55631d9, 0xe698e9cbc6545c99,
        0x4763107ec64e92a5, 0xc65821fc65696a24, 0x76196c064822f0b7, 0x485be841f3525e01, 0xf652bc9c85974ff5, 0xcad8352face9e3e9, 0x2a6ed1dceb35e98e, 0xc6f483badc11680f,
        0x3cfd8c17e9cf12f1, 0x89b83c5e2ea56471, 0xae665cfd24e392a9, 0xec33c4e504cb8915, 0x3fb9b15fc9fe7451, 0xd7fd1fd1945f2195, 0x31ade0853443efd8, 0x255efc9863e1e2d2,
        0x10eab6008d5642cf, 0x46f04863257ac804, 0xa52dc42a789a27d3, 0xdaaadf9ce77af565, 0x6b479cd53d87febb, 0x6309e2d3f93db72f, 0xc5738ffbaa1ff9d6, 0x6bd57f3f25af7968,
        0x67605486d90d0a4a, 0xe14d0b9663bfbdae, 0xb7bbd8d816eb0414, 0xdef8a4f16b35a116, 0xe7932d85aaaffed6, 0x08161cbae90cfd48, 0x855507beb294f08b, 0x91234ea6ffd399b2,
        0xad70cf4b2435f302, 0xd289a97565bc2d27, 0x8e558437ffca99de, 0x96d2704b7115c040, 0x0889bbcdfc660e41, 0x5e0d4e67dc92128d, 0x72a9f8917063ed97, 0x438b69d409e016e3,
        0xdf4fed8a5d8a4397, 0x00f41dcf41d403f7, 0x4814eb038e52603f, 0x9dafbacc58e2d651, 0xfe2f458e4be170af, 0x4457ec414df6a940, 0x06e62f1451123314, 0xbd1014d173ba92cc,
        0xdef318e25ed57760, 0x9fea0de9dfca8525, 0x459de1e76c20624b, 0xaeec189617e2d666, 0x126a2c06ab5a83cb, 0xb1321532360f6132, 0x65421503dbb40123, 0x2d67c287ea089ab3,
        0x6c93bff5a56bd6b6, 0x4ffb2036cab6d98d, 0xce7b785b1be7ad4f, 0xedb42ef6189fd163, 0xdc905288703988f6, 0x365f9c1d2c691884, 0xc640583680d99bfe, 0x3cd4624c07593ec6,
        0x7f1ea8d85d7c5805, 0x014842d480b57149, 0x0b649bcb5a828688, 0xbcd5708ed79b18f0, 0xe987c862fbd2f2f0, 0x982731671f0cd82c, 0xbaf13e8b16d8c063, 0x8ea3109cbd951bba,
        0xd141045bfb385cad, 0x2acbc1a0af1f7d30, 0xe6444d89df03bfdf, 0xa18cc771b8188ff9, 0x9834429db01c39bb, 0x214add07fe086a1f, 0x8f07c19b1f6b3ff9, 0x56a297b1bf4ffe55,
        0x94d558e493c54fc7, 0x40bfc24c764552cb, 0x931a706f8a8520cb, 0x32229d322935bd52, 0x2560d0f5dc4fefaf, 0x9dbcc48355969bb6, 0x0fd81c3985c0b56a, 0xe03817e1560f2bda,
        0xc1bb4f81d892b2d5, 0xb0c4864f4e28d2d7, 0x3ecc49f9d9d6c263, 0x51307e99b52ba65e, 0x8af2b688da84a752, 0xf5d72523b91b20b6, 0x6d95ff1ff4634806, 0x562f21555458339a,
        0xc0ce47f889336346, 0x487823e5089b40d8, 0xe4727c7ebc6d9592, 0x5a8f7277e94970ba, 0xfca2f406b1c8bb50, 0x5b1f8a95f1791070, 0xd304af9fc9028605, 0x5440ab7fc930e748,
        0x312d25fbca2ab5a1, 0x10f4a4b234a4d575, 0x90301d55047e7473, 0x3b6372886c61591e, 0x293402b77c444e06, 0x451f34a4d3e97dd7, 0x3158d814d81bc57b, 0x034942425b9bda69,
        0xe2032ff9e532d9bb, 0x62ae066b8b2179e5, 0x9545e10c2f8d71d8, 0x7ff7483eb2d23fc0, 0x00945fcebdc98d86, 0x8764bbbe99b26ca2, 0x1b1ec62284c0bfc3, 0x58e0fcc4f0aa362b,
        0x5f4abefa878d458d, 0xfd74ac2f9607c519, 0xa4e3fb37df8cbfa9, 0xbf697e43cac574e5, 0x86f14a3f68f4cd53, 0x24a23d076f1ce522, 0xe725cd8048868cc8, 0xbf3c729eb2464362,
        0xd8f6cd57b3cc1ed8, 0x6329e52425541577, 0x62aa688ad5ae1ac0, 0x0a242566269bf845, 0x168b1a4753aca74b, 0xf789afefff2e7e3c, 0x6c3362093b6fccdb, 0x4ce8f50bd28c09b2,
        0x006a2db95ae8aa93, 0x975b0d623c3d1a8c, 0x18605d3935338c5b, 0x5bb6f6136cad3c71, 0x0f53a20701f8d8a6, 0xab8c5ad2e7e93c67, 0x40b5ac5127acaa29, 0x8c7bf63c2075895f,
        0x78bd9f7e014a805c, 0xb2c9e9f4f9c8c032, 0xefd6049827eb91f3, 0x2be459f482c16fbd, 0xd92ce0c5745aaa8c, 0x0aaa8fb298d965b9, 0x2b37f92c6c803b15, 0x8c54a5e94e0f0e78,
        0x95f9b6e90c0a3032, 0xe7939faa436c7874, 0xd16bfe8f6a8a40c9, 0x44982b86263fd2fa, 0xe285fb39f984e583, 0x779a8df72d7619d3, 0xf2d79a8de8d5dd1e, 0xd1037354d66684e2,
        0x004c82a4e668a8e5, 0x31d40a7668b044e6, 0xd70578538bd02c11, 0xdb45431078c5f482, 0x977121bb7f6a51ad, 0x73d5ccbd34eff8dd, 0xe437a07d356e17cd, 0x47b2782043c95627,
        0x9fb251413e41d49a, 0xccd70b60652513d3, 0x1c95b31e8a1b49b2, 0xcae73dfd1bcb4c1b, 0x34d98331b1f5b70f, 0x784e39f22338d92f, 0x18613d4a064df420, 0xf1d8dae25f0bcebe,
        0x33f77c15ae855efc, 0x3c88b3b912eb109c, 0x956a2ec96bafeea5, 0x1aa005b5e0ad0e87, 0x5500d70527c4bb8e, 0xe36c57196421cc44, 0x13c4d286cc36ee39, 0x5654a23d818b2a81,
        0x77b1dc13d161abdc, 0x734f44de5f8d5eb5, 0x60717e174a6c89a2, 0xd47d9649266a211e, 0x5b13a4322bb69e90, 0xf7669609f8b5fc3c, 0x21e6ac55bedcdac9, 0x9b56b62b61166dea,
        0xf48f66b939797e9c, 0x35f332f9c0e6ae9a, 0xcc733f6a9a878db0, 0x3da161e41cc108c2, 0xb7d74ae535914d51, 0x4d493b0b11d36469, 0xce264d1dfba9741a, 0xa9d1f2dc7436dc06,
        0x70738016604c2a27, 0x231d36e96e93f3d5, 0x7666881197838d19, 0x4a2a83090aaad40c, 0xf1e761591668b35d, 0x7363236497f730a7, 0x301080e37379dd4d, 0x502dea2971827042,
        0xc2c5eb858f32625f, 0x786afb9edfafbdff, 0xdaee0d868490b2a4, 0x617366b3268609f6, 0xae0e35a0fe46173e, 0xd1a07de93e824f11, 0x079b8b115ea4cca8, 0x93a99274558faebb,
        0xfb1e6e22e08a03b3, 0xea635fdba3698dd0, 0xcf53659328503a5c, 0xcde3b31e6fd5d780, 0x8e3e4221d3614413, 0xef14d0d86bf1a22c, 0xe1d830d3f16c5ddb, 0xaabd2b2a451504e1,
    ];

    /// The chunker's parameters as the superblock records them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Params { pub min: u32, pub target: u32, pub max: u32, pub mask_s: u64, pub mask_l: u64 }

    impl Params {
        pub const DEFAULT: Self = Self { min: 65_536, target: 262_144, max: 1_048_576, mask_s: 0x0000_d917_0753_7000, mask_l: 0x0000_d907_0353_7000 };
        pub fn valid(&self) -> bool {
            0 < self.min && self.min < self.target && self.target < self.max && self.max as u64 <= 16 * 1024 * 1024 && self.mask_s != 0 && self.mask_l != 0
        }
    }

    /// The length of the next chunk of `data`, which is the whole rest of
    /// the file or holds at least `max` bytes.
    pub fn cut(data: &[u8], params: &Params) -> usize {
        let n = data.len();
        let min = params.min as usize;
        if n <= min { return n; }
        let limit = n.min(params.max as usize);
        let target = params.target as usize;
        let mut h = 0u64;
        for i in min..limit {
            h = (h << 1).wrapping_add(GEAR[data[i] as usize]);
            let mask = if i < target { params.mask_s } else { params.mask_l };
            if h & mask == 0 { return i; }
        }
        limit
    }

    /// Every chunk boundary of `data`: the chunk lengths in order.
    pub fn chunks(data: &[u8], params: &Params) -> Vec<usize> {
        let mut lengths = Vec::new();
        let mut at = 0usize;
        while at < data.len() {
            let len = cut(&data[at..], params);
            lengths.push(len);
            at += len;
        }
        lengths
    }
}
