//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — Ed25519 signatures
//!
//! Store-output signing for substitution. Hand-written like the crate's
//! hash primitives: field elements are five 51-bit limbs over
//! 2^255 - 19, points use extended homogeneous coordinates, scalars
//! reduce mod the group order L via the 64-byte Barrett-free schoolbook
//! path. Verified against the RFC 8032 test vectors.
//!
//! This signs/verifies build artifacts — timing side channels are not in
//! the threat model (the signer runs offline over public data).

use crate::crypto::sha512;

const D: Fe = Fe([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);
const D2: Fe = Fe([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);
/// sqrt(-1) mod p.
const SQRT_M1: Fe = Fe([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

/// The group order L = 2^252 + 27742317777372353535851937790883648493.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const MASK51: u64 = (1 << 51) - 1;

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn add(&self, other: &Fe) -> Fe {
        let mut out = [0u64; 5];
        for i in 0..5 {
            out[i] = self.0[i] + other.0[i];
        }
        Fe(out)
    }

    fn sub(&self, other: &Fe) -> Fe {
        // Add 2p before subtracting so limbs stay non-negative.
        let mut out = [0u64; 5];
        out[0] = self.0[0] + 0xFFFFFFFFFFFDA_u64.wrapping_mul(16) - other.0[0];
        for i in 1..5 {
            out[i] = self.0[i] + 0xFFFFFFFFFFFFE_u64.wrapping_mul(16) - other.0[i];
        }
        Fe(out).weak_reduce()
    }

    fn weak_reduce(&self) -> Fe {
        let mut l = self.0;
        let c = l[4] >> 51;
        l[4] &= MASK51;
        l[0] += c * 19;
        let c = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c;
        let c = l[1] >> 51;
        l[1] &= MASK51;
        l[2] += c;
        let c = l[2] >> 51;
        l[2] &= MASK51;
        l[3] += c;
        let c = l[3] >> 51;
        l[3] &= MASK51;
        l[4] += c;
        Fe(l)
    }

    fn mul(&self, other: &Fe) -> Fe {
        let a = &self.0;
        let b = &other.0;
        let a1_19 = a[1] * 19;
        let a2_19 = a[2] * 19;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;
        let m = |x: u64, y: u64| x as u128 * y as u128;
        let t0 = m(a[0], b[0]) + m(a1_19, b[4]) + m(a2_19, b[3]) + m(a3_19, b[2]) + m(a4_19, b[1]);
        let mut t1 =
            m(a[0], b[1]) + m(a[1], b[0]) + m(a2_19, b[4]) + m(a3_19, b[3]) + m(a4_19, b[2]);
        let mut t2 =
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a3_19, b[4]) + m(a4_19, b[3]);
        let mut t3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a4_19, b[4]);
        let mut t4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

        let mut out = [0u64; 5];
        let c = (t0 >> 51) as u64;
        out[0] = t0 as u64 & MASK51;
        t1 += c as u128;
        let c = (t1 >> 51) as u64;
        out[1] = t1 as u64 & MASK51;
        t2 += c as u128;
        let c = (t2 >> 51) as u64;
        out[2] = t2 as u64 & MASK51;
        t3 += c as u128;
        let c = (t3 >> 51) as u64;
        out[3] = t3 as u64 & MASK51;
        t4 += c as u128;
        let c = (t4 >> 51) as u64;
        out[4] = t4 as u64 & MASK51;
        out[0] += c * 19;
        let c = out[0] >> 51;
        out[0] &= MASK51;
        out[1] += c;
        Fe(out)
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    fn pow2k(&self, k: u32) -> Fe {
        let mut out = *self;
        for _ in 0..k {
            out = out.square();
        }
        out
    }

    /// Fermat inversion: a^(p-2).
    fn invert(&self) -> Fe {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.pow2k(2);
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = z_5_0.pow2k(5);
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = z_10_0.pow2k(10);
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = z_20_0.pow2k(20);
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = z_40_0.pow2k(10);
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = z_50_0.pow2k(50);
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = z_100_0.pow2k(100);
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = z_200_0.pow2k(50);
        let z_250_0 = z_250_50.mul(&z_50_0);
        let z_255_5 = z_250_0.pow2k(5);
        z_255_5.mul(&z11)
    }

    /// a^((p-5)/8), the core of the combined sqrt used in decompression.
    fn pow_p58(&self) -> Fe {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.pow2k(2);
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = z_5_0.pow2k(5);
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = z_10_0.pow2k(10);
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = z_20_0.pow2k(20);
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = z_40_0.pow2k(10);
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = z_50_0.pow2k(50);
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = z_100_0.pow2k(100);
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = z_200_0.pow2k(50);
        let z_250_0 = z_250_50.mul(&z_50_0);
        let z_252_2 = z_250_0.pow2k(2);
        z_252_2.mul(&z1)
    }

    fn to_bytes(self) -> [u8; 32] {
        // Full canonical reduction.
        let mut l = self.weak_reduce().0;
        // Now l < 2^52 per limb; run the carry once more then subtract p
        // if needed.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        let c = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c;
        let c = l[1] >> 51;
        l[1] &= MASK51;
        l[2] += c;
        let c = l[2] >> 51;
        l[2] &= MASK51;
        l[3] += c;
        let c = l[3] >> 51;
        l[3] &= MASK51;
        l[4] += c;
        l[4] &= MASK51;

        let mut out = [0u8; 32];
        let words = [
            l[0] | (l[1] << 51),
            (l[1] >> 13) | (l[2] << 38),
            (l[2] >> 26) | (l[3] << 25),
            (l[3] >> 39) | (l[4] << 12),
        ];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |b: &[u8]| u64::from_le_bytes(b.try_into().expect("8 bytes"));
        Fe([
            load(&bytes[0..8]) & MASK51,
            (load(&bytes[6..14]) >> 3) & MASK51,
            (load(&bytes[12..20]) >> 6) & MASK51,
            (load(&bytes[19..27]) >> 1) & MASK51,
            (load(&bytes[24..32]) >> 12) & MASK51,
        ])
    }

    fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn is_zero(&self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }
}

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    fn base() -> Point {
        // The standard base point: y = 4/5, x recovered with sign 0.
        let mut y_bytes = [0u8; 32];
        let four_fifths = Fe([4, 0, 0, 0, 0]).mul(&Fe([5, 0, 0, 0, 0]).invert());
        y_bytes.copy_from_slice(&four_fifths.to_bytes());
        Point::decompress(&y_bytes).expect("base point decompresses")
    }

    fn add(&self, other: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let d = self.z.mul(&other.z);
        let d = d.add(&d);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let h = a.add(&b);
        let e = h.sub(&self.x.add(&self.y).square());
        let g = a.sub(&b);
        let f = c.add(&g);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn scalar_mul(&self, scalar: &[u8; 32]) -> Point {
        let mut out = Point::IDENTITY;
        for i in (0..256).rev() {
            out = out.double();
            if (scalar[i / 8] >> (i % 8)) & 1 == 1 {
                out = out.add(self);
            }
        }
        out
    }

    fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut out = y.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        }
        out
    }

    fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let mut y_bytes = *bytes;
        let sign = y_bytes[31] >> 7;
        y_bytes[31] &= 0x7f;
        // Reject non-canonical y (>= p).
        let y = Fe::from_bytes(&y_bytes);
        if y.to_bytes() != y_bytes {
            return None;
        }

        // x^2 = (y^2 - 1) / (d y^2 + 1)
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&D).add(&Fe::ONE);
        // Combined sqrt: x = u v^3 (u v^7)^((p-5)/8)
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let vxx = v.mul(&x.square());
        if !vxx.sub(&u).is_zero() {
            if !vxx.add(&u).is_zero() {
                return None;
            }
            x = x.mul(&SQRT_M1);
        }
        if x.is_zero() && sign == 1 {
            return None;
        }
        if x.is_negative() != (sign == 1) {
            x = x.neg();
        }
        let t = x.mul(&y);
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t,
        })
    }
}

/// Reduce a 64-byte little-endian value mod L (schoolbook, byte digits).
fn reduce_mod_l(wide: &[u8; 64]) -> [u8; 32] {
    // Work in u16 digits to keep the borrow/carry logic simple; the
    // signer runs offline so speed is irrelevant.
    let mut r = [0u16; 64];
    for (i, b) in wide.iter().enumerate() {
        r[i] = *b as u16;
    }
    // Repeatedly fold the high bytes down: 2^256 ≡ (2^256 - 16*L') where
    // simple long division is clearer — divide r by L via binary shifts.
    // Convert to a big integer as u32 limbs for schoolbook mod.
    let mut num = [0u32; 16];
    for i in 0..16 {
        num[i] = u32::from_le_bytes([
            wide[i * 4],
            wide[i * 4 + 1],
            wide[i * 4 + 2],
            wide[i * 4 + 3],
        ]);
    }
    let _ = r;
    let mut l = [0u32; 16];
    for i in 0..8 {
        l[i] = u32::from_le_bytes([L[i * 4], L[i * 4 + 1], L[i * 4 + 2], L[i * 4 + 3]]);
    }

    // Binary long division: for bit positions from high to low, if
    // num >= L << k, subtract.
    let ge = |a: &[u32; 16], b: &[u32; 16]| -> bool {
        for i in (0..16).rev() {
            if a[i] != b[i] {
                return a[i] > b[i];
            }
        }
        true
    };
    let shl = |a: &[u32; 16], k: usize| -> [u32; 16] {
        let word = k / 32;
        let bit = k % 32;
        let mut out = [0u32; 16];
        for i in (0..16).rev() {
            let mut v = 0u64;
            if i >= word {
                v = (a[i - word] as u64) << bit;
                if bit > 0 && i > word {
                    v |= (a[i - word - 1] as u64) >> (32 - bit);
                }
            }
            out[i] = v as u32;
        }
        out
    };
    let sub = |a: &mut [u32; 16], b: &[u32; 16]| {
        let mut borrow = 0i64;
        for i in 0..16 {
            let v = a[i] as i64 - b[i] as i64 - borrow;
            if v < 0 {
                a[i] = (v + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                a[i] = v as u32;
                borrow = 0;
            }
        }
    };

    // L is 253 bits; num is at most 512 bits → shift up to 259.
    for k in (0..=259).rev() {
        let shifted = shl(&l, k);
        // Skip shifts that overflowed to zero (k too large drops bits) —
        // detect by checking the shift preserved the top bit.
        if k + 253 > 512 {
            continue;
        }
        if ge(&num, &shifted) && shifted.iter().any(|&w| w != 0) {
            sub(&mut num, &shifted);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&num[i].to_le_bytes());
    }
    out
}

/// a*b + c mod L over 32-byte scalars.
fn muladd_mod_l(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut wide = [0u8; 64];
    let mut t = [0u128; 17];
    for i in 0..8 {
        for j in 0..8 {
            let x = u32::from_le_bytes(a[i * 4..i * 4 + 4].try_into().expect("4")) as u128;
            let y = u32::from_le_bytes(b[j * 4..j * 4 + 4].try_into().expect("4")) as u128;
            t[i + j] += x * y;
        }
    }
    for i in 0..8 {
        let x = u32::from_le_bytes(c[i * 4..i * 4 + 4].try_into().expect("4")) as u128;
        t[i] += x;
    }
    let mut carry: u128 = 0;
    for i in 0..16 {
        let v = t[i] + carry;
        wide[i * 4..i * 4 + 4].copy_from_slice(&(v as u32).to_le_bytes());
        carry = v >> 32;
    }
    reduce_mod_l(&wide)
}

fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Derive the public key from a 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let h = sha512::hash(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    clamp(&mut a);
    Point::base().scalar_mul(&a).compress()
}

/// RFC 8032 Ed25519 signature.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let h = sha512::hash(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    clamp(&mut a);
    let public = Point::base().scalar_mul(&a).compress();

    let mut hasher = sha512::Sha512::new();
    hasher.update(&h[32..]);
    hasher.update(message);
    let r_wide = hasher.finalize();
    let r = reduce_mod_l(&r_wide);
    let r_point = Point::base().scalar_mul(&r).compress();

    let mut hasher = sha512::Sha512::new();
    hasher.update(&r_point);
    hasher.update(&public);
    hasher.update(message);
    let k = reduce_mod_l(&hasher.finalize());

    let s = muladd_mod_l(&k, &a, &r);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_point);
    out[32..].copy_from_slice(&s);
    out
}

/// RFC 8032 verification (cofactorless: [S]B == R + [k]A).
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(a_point) = Point::decompress(public) else {
        return false;
    };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..]);
    // Reject non-canonical S (>= L).
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&s);
    if reduce_mod_l(&wide) != s {
        return false;
    }
    let Some(r_point) = Point::decompress(&r_bytes) else {
        return false;
    };

    let mut hasher = sha512::Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public);
    hasher.update(message);
    let k = reduce_mod_l(&hasher.finalize());

    // [S]B == R + [k]A
    let sb = Point::base().scalar_mul(&s);
    let ka = a_point.scalar_mul(&k);
    let rhs = r_point.add(&ka);
    sb.compress() == rhs.compress()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("malformed hex".to_string());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digits"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(hex_str: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&from_hex(hex_str).unwrap());
        out
    }

    #[test]
    fn rfc8032_test_1_empty_message() {
        let sk = seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk = public_key(&sk);
        assert_eq!(
            hex(&pk),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sign(&sk, b"");
        assert_eq!(
            hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify(&pk, b"", &sig));
        assert!(!verify(&pk, b"x", &sig));
    }

    #[test]
    fn rfc8032_test_2_one_byte() {
        let sk = seed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let pk = public_key(&sk);
        assert_eq!(
            hex(&pk),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let sig = sign(&sk, &[0x72]);
        assert_eq!(
            hex(&sig),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        assert!(verify(&pk, &[0x72], &sig));
    }

    #[test]
    fn rfc8032_test_3_two_bytes() {
        let sk = seed("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let pk = public_key(&sk);
        assert_eq!(
            hex(&pk),
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        );
        let sig = sign(&sk, &[0xaf, 0x82]);
        assert_eq!(
            hex(&sig),
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        );
        assert!(verify(&pk, &[0xaf, 0x82], &sig));
        // Flipped signature bit fails.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&pk, &[0xaf, 0x82], &bad));
    }
}
