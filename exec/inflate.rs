// SPDX-License-Identifier: GPL-2.0-only
//! Decodes gzip members as a bounded-memory byte stream.
//! This module owns RFC 1952 framing and RFC 1951 blocks; tar interpretation stays with untar.

use std::io::{self, Read};

fn invalid(offset: u64, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("gzip offset {offset}: {detail}"),
    )
}

struct Bits<R> {
    inner: R,
    bits: u32,
    count: u8,
    offset: u64,
}

impl<R: Read> Bits<R> {
    fn byte(&mut self) -> io::Result<Option<u8>> {
        let mut byte = [0];
        loop {
            match self.inner.read(&mut byte)? {
                0 => return Ok(None),
                1 => {
                    self.offset += 1;
                    return Ok(Some(byte[0]));
                }
                _ => return Err(invalid(self.offset, "reader returned too many bytes")),
            }
        }
    }

    fn take(&mut self, n: u8) -> io::Result<u32> {
        while self.count < n {
            let byte = self
                .byte()?
                .ok_or_else(|| invalid(self.offset, "truncated input"))?;
            self.bits |= (byte as u32) << self.count;
            self.count += 8;
        }
        let value = self.bits & ((1u32 << n) - 1);
        self.bits >>= n;
        self.count -= n;
        Ok(value)
    }

    fn align(&mut self) {
        let discard = self.count % 8;
        self.bits >>= discard;
        self.count -= discard;
    }

    fn aligned_byte(&mut self) -> io::Result<u8> {
        Ok(self.take(8)? as u8)
    }
}

struct Huffman {
    by_len: Vec<Vec<(u16, u16)>>,
    max: usize,
}

impl Huffman {
    fn new(lengths: &[u8], allow_empty: bool, offset: u64) -> io::Result<Self> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(invalid(offset, "Huffman code length exceeds 15"));
            }
            counts[len as usize] += 1;
        }
        let nonzero = lengths.len() - counts[0] as usize;
        if nonzero == 0 && !allow_empty {
            return Err(invalid(offset, "empty Huffman table"));
        }
        let mut left = 1i32;
        for count in counts.iter().skip(1) {
            left = (left << 1) - *count as i32;
            if left < 0 {
                return Err(invalid(offset, "over-subscribed Huffman table"));
            }
        }
        if left != 0 && (nonzero > 1 || (nonzero == 1 && lengths.iter().copied().max() != Some(1)))
        {
            return Err(invalid(offset, "incomplete Huffman table"));
        }
        let mut next = [0u16; 16];
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code + if len == 1 { 0 } else { counts[len - 1] }) << 1;
            next[len] = code;
        }
        let mut by_len = vec![Vec::new(); 16];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                by_len[len as usize].push((next[len as usize], symbol as u16));
                next[len as usize] += 1;
            }
        }
        let max = lengths.iter().copied().max().unwrap_or(0) as usize;
        Ok(Self { by_len, max })
    }

    fn decode<R: Read>(&self, bits: &mut Bits<R>) -> io::Result<u16> {
        let mut code = 0u16;
        for len in 1..=self.max {
            code = (code << 1) | bits.take(1)? as u16;
            if let Some((_, symbol)) = self.by_len[len].iter().find(|(value, _)| *value == code) {
                return Ok(*symbol);
            }
        }
        Err(invalid(bits.offset, "invalid Huffman code"))
    }
}

enum Block {
    New,
    Stored(usize),
    Codes(Huffman, Huffman),
}

/// A streaming gzip decoder with a 32 KiB history window.
pub(crate) struct Gzip<R> {
    bits: Bits<R>,
    window: [u8; 32768],
    produced: u64,
    crc: u32,
    block: Block,
    final_block: bool,
    copy_len: usize,
    copy_dist: usize,
    member: bool,
    done: bool,
}

impl<R: Read> Gzip<R> {
    /// Create a decoder. Validation occurs as bytes are read.
    pub(crate) fn new(inner: R) -> Self {
        Self {
            bits: Bits {
                inner,
                bits: 0,
                count: 0,
                offset: 0,
            },
            window: [0; 32768],
            produced: 0,
            crc: u32::MAX,
            block: Block::New,
            final_block: false,
            copy_len: 0,
            copy_dist: 0,
            member: false,
            done: false,
        }
    }

    fn header_byte(&mut self, crc: &mut u32) -> io::Result<u8> {
        let byte = self.bits.aligned_byte()?;
        *crc = crate::crypto::crc::crc32_byte(*crc, byte);
        Ok(byte)
    }

    fn start_member(&mut self) -> io::Result<()> {
        let Some(first) = self.bits.byte()? else {
            if self.member {
                self.done = true;
                return Ok(());
            }
            return Err(invalid(self.bits.offset, "empty gzip stream"));
        };
        if first != 0x1f {
            return Err(invalid(
                self.bits.offset - 1,
                "trailing data is not a gzip member",
            ));
        }
        let mut head_crc = crate::crypto::crc::crc32_byte(u32::MAX, first);
        if self.header_byte(&mut head_crc)? != 0x8b || self.header_byte(&mut head_crc)? != 8 {
            return Err(invalid(
                self.bits.offset,
                "invalid gzip magic or compression method",
            ));
        }
        let flags = self.header_byte(&mut head_crc)?;
        if flags & 0xe0 != 0 {
            return Err(invalid(self.bits.offset, "reserved gzip flags"));
        }
        for _ in 0..6 {
            self.header_byte(&mut head_crc)?;
        }
        if flags & 4 != 0 {
            let lo = self.header_byte(&mut head_crc)? as usize;
            let hi = self.header_byte(&mut head_crc)? as usize;
            for _ in 0..(lo | (hi << 8)) {
                self.header_byte(&mut head_crc)?;
            }
        }
        for flag in [8, 16] {
            if flags & flag != 0 {
                loop {
                    if self.header_byte(&mut head_crc)? == 0 {
                        break;
                    }
                }
            }
        }
        if flags & 2 != 0 {
            let declared =
                self.bits.aligned_byte()? as u16 | (self.bits.aligned_byte()? as u16) << 8;
            if declared != (head_crc ^ u32::MAX) as u16 {
                return Err(invalid(self.bits.offset, "header CRC16 mismatch"));
            }
        }
        self.member = true;
        self.produced = 0;
        self.crc = u32::MAX;
        self.block = Block::New;
        self.final_block = false;
        Ok(())
    }

    fn emit(&mut self, byte: u8) -> u8 {
        self.window[self.produced as usize % 32768] = byte;
        self.produced += 1;
        self.crc = crate::crypto::crc::crc32_byte(self.crc, byte);
        byte
    }

    fn codes(&mut self, kind: u32) -> io::Result<Block> {
        let offset = self.bits.offset;
        if kind == 1 {
            let mut lit = [0u8; 288];
            lit[..144].fill(8);
            lit[144..256].fill(9);
            lit[256..280].fill(7);
            lit[280..].fill(8);
            return Ok(Block::Codes(
                Huffman::new(&lit, false, offset)?,
                Huffman::new(&[5; 32], false, offset)?,
            ));
        }
        let hlit = self.bits.take(5)? as usize + 257;
        let hdist = self.bits.take(5)? as usize + 1;
        let hclen = self.bits.take(4)? as usize + 4;
        let order = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let mut clen = [0u8; 19];
        for &index in &order[..hclen] {
            clen[index] = self.bits.take(3)? as u8;
        }
        let cl = Huffman::new(&clen, false, self.bits.offset)?;
        if cl.by_len.iter().map(Vec::len).sum::<usize>() == 1 {
            return Err(invalid(self.bits.offset, "incomplete code-length table"));
        }
        let mut lengths = Vec::with_capacity(hlit + hdist);
        while lengths.len() < hlit + hdist {
            let symbol = cl.decode(&mut self.bits)?;
            let (length, repeat) = match symbol {
                0..=15 => (symbol as u8, 1),
                16 if !lengths.is_empty() => (
                    *lengths.last().unwrap_or(&0),
                    self.bits.take(2)? as usize + 3,
                ),
                17 => (0, self.bits.take(3)? as usize + 3),
                18 => (0, self.bits.take(7)? as usize + 11),
                _ => return Err(invalid(self.bits.offset, "invalid code-length repeat")),
            };
            if lengths.len() + repeat > hlit + hdist {
                return Err(invalid(self.bits.offset, "code lengths exceed table"));
            }
            lengths.extend(std::iter::repeat_n(length, repeat));
        }
        if lengths[256] == 0 {
            return Err(invalid(self.bits.offset, "missing end-of-block symbol"));
        }
        let lit = Huffman::new(&lengths[..hlit], false, self.bits.offset)?;
        let dist = Huffman::new(&lengths[hlit..], true, self.bits.offset)?;
        Ok(Block::Codes(lit, dist))
    }

    fn trailer(&mut self) -> io::Result<()> {
        self.bits.align();
        let mut bytes = [0u8; 8];
        for byte in &mut bytes {
            *byte = self.bits.aligned_byte()?;
        }
        if u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| invalid(self.bits.offset, "CRC trailer"))?,
        ) != self.crc ^ u32::MAX
        {
            return Err(invalid(self.bits.offset, "data CRC32 mismatch"));
        }
        if u32::from_le_bytes(
            bytes[4..]
                .try_into()
                .map_err(|_| invalid(self.bits.offset, "size trailer"))?,
        ) != self.produced as u32
        {
            return Err(invalid(self.bits.offset, "ISIZE mismatch"));
        }
        self.start_member()
    }

    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        const BASE: [usize; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const EXTRA: [u8; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DBASE: [usize; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        const DEXTRA: [u8; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];
        loop {
            if self.done {
                return Ok(None);
            }
            if !self.member {
                self.start_member()?;
                continue;
            }
            if self.copy_len > 0 {
                let index = (self.produced as usize - self.copy_dist) % 32768;
                self.copy_len -= 1;
                return Ok(Some(self.emit(self.window[index])));
            }
            match &mut self.block {
                Block::New => {
                    if self.final_block {
                        self.trailer()?;
                        continue;
                    }
                    self.final_block = self.bits.take(1)? != 0;
                    let kind = self.bits.take(2)?;
                    self.block = match kind {
                        0 => {
                            self.bits.align();
                            let len = self.bits.take(16)? as u16;
                            let check = self.bits.take(16)? as u16;
                            if len != !check {
                                return Err(invalid(
                                    self.bits.offset,
                                    "stored block LEN/NLEN mismatch",
                                ));
                            }
                            Block::Stored(len as usize)
                        }
                        1 | 2 => self.codes(kind)?,
                        _ => return Err(invalid(self.bits.offset, "reserved block type")),
                    };
                }
                Block::Stored(remaining) => {
                    if *remaining == 0 {
                        self.block = Block::New;
                        continue;
                    }
                    *remaining -= 1;
                    let byte = self.bits.aligned_byte()?;
                    return Ok(Some(self.emit(byte)));
                }
                Block::Codes(lit, dist) => {
                    let symbol = lit.decode(&mut self.bits)?;
                    match symbol {
                        0..=255 => return Ok(Some(self.emit(symbol as u8))),
                        256 => self.block = Block::New,
                        257..=285 => {
                            let index = (symbol - 257) as usize;
                            self.copy_len = BASE[index] + self.bits.take(EXTRA[index])? as usize;
                            let d = dist.decode(&mut self.bits)? as usize;
                            if d >= 30 {
                                return Err(invalid(self.bits.offset, "reserved distance code"));
                            }
                            self.copy_dist = DBASE[d] + self.bits.take(DEXTRA[d])? as usize;
                            if self.copy_dist > self.produced.min(32768) as usize {
                                return Err(invalid(self.bits.offset, "distance beyond output"));
                            }
                        }
                        _ => return Err(invalid(self.bits.offset, "reserved length code")),
                    }
                }
            }
        }
    }
}

impl<R: Read> Read for Gzip<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        for byte in out {
            match self.next_byte()? {
                Some(value) => {
                    *byte = value;
                    count += 1;
                }
                None => break,
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORED: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 1, 24, 0, 231, 255, 97, 108, 112, 104, 97, 32, 97, 108,
        112, 104, 97, 32, 97, 108, 112, 104, 97, 32, 97, 108, 112, 104, 97, 10, 243, 241, 178, 39,
        24, 0, 0, 0,
    ];
    const FIXED: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 75, 204, 41, 200, 72, 84, 72, 68, 39, 185, 0, 243, 241,
        178, 39, 24, 0, 0, 0,
    ];
    const DYNAMIC: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 237, 207, 11, 22, 64, 32, 16, 0, 192, 179, 133, 104,
        253, 21, 197, 222, 255, 32, 168, 84, 219, 13, 122, 207, 220, 96, 88, 69, 212, 65, 99, 113,
        222, 82, 93, 36, 28, 0, 232, 51, 67, 98, 244, 166, 199, 156, 91, 82, 235, 103, 123, 73, 69,
        236, 193, 97, 105, 109, 168, 51, 186, 28, 68, 100, 255, 174, 216, 221, 13, 100, 182, 220,
        200, 154, 2, 0, 0,
    ];
    const OPTIONAL_HEADER: &[u8] = &[
        31, 139, 8, 31, 0, 0, 0, 0, 0, 255, 2, 0, 1, 2, 110, 97, 109, 101, 0, 110, 111, 116, 101,
        0, 255, 147, 75, 204, 41, 200, 72, 84, 72, 68, 39, 185, 0, 243, 241, 178, 39, 24, 0, 0, 0,
    ];

    fn decode(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Gzip::new(bytes).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn stored_fixed_and_dynamic_blocks() {
        for input in [STORED, FIXED] {
            assert_eq!(decode(input).unwrap(), b"alpha alpha alpha alpha\n");
        }
        let pattern: Vec<u8> = (0..26)
            .flat_map(|i| std::iter::repeat_n(b'A' + i, (i as usize * 13) % 17 + 1))
            .collect();
        assert_eq!(pattern.len(), 222);
        let decoded = decode(DYNAMIC).unwrap();
        assert_eq!(decoded.len(), 666);
        assert_eq!(decoded, pattern.repeat(3));
    }

    #[test]
    fn concatenated_members_and_invalid_trailers() {
        let mut pair = STORED.to_vec();
        pair.extend_from_slice(FIXED);
        assert_eq!(
            decode(&pair).unwrap(),
            b"alpha alpha alpha alpha\n".repeat(2)
        );
        let mut bad_crc = FIXED.to_vec();
        let crc = bad_crc.len() - 8;
        bad_crc[crc] ^= 1;
        assert!(decode(&bad_crc).unwrap_err().to_string().contains("CRC32"));
        let mut bad_size = FIXED.to_vec();
        let size = bad_size.len() - 4;
        bad_size[size] ^= 1;
        assert!(decode(&bad_size).unwrap_err().to_string().contains("ISIZE"));
        assert!(decode(&FIXED[..FIXED.len() - 1]).is_err());
        pair.push(0);
        assert!(decode(&pair).is_err());
    }

    #[test]
    fn optional_header_and_crc16() {
        assert_eq!(
            decode(OPTIONAL_HEADER).unwrap(),
            b"alpha alpha alpha alpha\n"
        );
        let mut bad = OPTIONAL_HEADER.to_vec();
        bad[24] ^= 1;
        assert!(decode(&bad).unwrap_err().to_string().contains("CRC16"));
        let mut reserved = FIXED.to_vec();
        reserved[3] = 0x20;
        assert!(decode(&reserved).is_err());
    }

    #[test]
    fn rejects_oversubscribed_code_lengths() {
        let stream = [31, 139, 8, 0, 0, 0, 0, 0, 0, 0, 5, 0, 146, 4];
        assert!(
            decode(&stream)
                .unwrap_err()
                .to_string()
                .contains("over-subscribed")
        );
    }
}
