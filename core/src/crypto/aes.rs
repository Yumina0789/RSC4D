

const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

const INV_SBOX: [u8; 256] = build_inv_sbox();

const fn build_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

const RCON: [u32; 11] = [
    0x0000_0000,
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1B00_0000,
    0x3600_0000,
];

fn sub_dword(v: u32) -> u32 {
    let b = v.to_le_bytes().map(|x| SBOX[x as usize]);
    u32::from_le_bytes(b)
}

#[derive(Clone)]
pub struct AesCtx {
    rk: [u32; 48],
    rounds: usize,
}

impl AesCtx {

    pub fn new(key: &[u8], is_v6: bool) -> Self {
        assert!(
            key.len() == 16 || key.len() == 20,
            "AES key must be 16 or 20 bytes, got {}",
            key.len()
        );

        let dwords = key.len() / 4;
        let rounds = dwords + 6;
        let mut rk = [0u32; 48];

        for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
            rk[i] = u32::from_le_bytes(*chunk);
        }

        for i in dwords..(rounds + 1) * 4 {
            let mut temp = rk[i - 1];
            if i % dwords == 0 {

                temp =
                    (sub_dword(temp.swap_bytes().rotate_right(24)) ^ RCON[i / dwords]).swap_bytes();
            }
            rk[i] = rk[i - dwords] ^ temp;
        }

        if is_v6 {
            let mut bytes = [0u8; 192];
            for (i, w) in rk.iter().enumerate() {
                bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
            }

            bytes[4 * 16] ^= 0x73;
            bytes[6 * 16] ^= 0x09;
            bytes[8 * 16] ^= 0xE4;
            for i in 0..48 {
                rk[i] = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
            }
        }

        Self { rk, rounds }
    }

    fn add_round_key(s: &mut [u8; 16], rk: &[u32]) {
        for i in 0..4 {
            let w = rk[i].to_le_bytes();
            s[4 * i] ^= w[0];
            s[4 * i + 1] ^= w[1];
            s[4 * i + 2] ^= w[2];
            s[4 * i + 3] ^= w[3];
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut s = *block;
        Self::add_round_key(&mut s, &self.rk[0..4]);

        for r in 1..self.rounds {
            sub_bytes(&mut s);
            shift_rows(&mut s);
            mix_columns(&mut s);
            Self::add_round_key(&mut s, &self.rk[4 * r..4 * r + 4]);
        }

        sub_bytes(&mut s);
        shift_rows(&mut s);
        Self::add_round_key(&mut s, &self.rk[4 * self.rounds..4 * self.rounds + 4]);

        *block = s;
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut s = *block;
        Self::add_round_key(&mut s, &self.rk[4 * self.rounds..4 * self.rounds + 4]);

        for r in (1..self.rounds).rev() {
            inv_shift_rows(&mut s);
            inv_sub_bytes(&mut s);
            Self::add_round_key(&mut s, &self.rk[4 * r..4 * r + 4]);
            inv_mix_columns(&mut s);
        }

        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        Self::add_round_key(&mut s, &self.rk[0..4]);

        *block = s;
    }
}

fn sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    let old = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * c + r] = old[4 * ((c + r) % 4) + r];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let old = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * ((c + r) % 4) + r] = old[4 * c + r];
        }
    }
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ (if b & 0x80 != 0 { 0x1B } else { 0 })
}

fn mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    result
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        s[4 * c] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
        s[4 * c + 1] = xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3] ^ a[0];
        s[4 * c + 2] = xtime(a[2]) ^ (xtime(a[3]) ^ a[3]) ^ a[0] ^ a[1];
        s[4 * c + 3] = xtime(a[3]) ^ (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2];
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        s[4 * c] = mul(a[0], 0x0E) ^ mul(a[1], 0x0B) ^ mul(a[2], 0x0D) ^ mul(a[3], 0x09);
        s[4 * c + 1] = mul(a[0], 0x09) ^ mul(a[1], 0x0E) ^ mul(a[2], 0x0B) ^ mul(a[3], 0x0D);
        s[4 * c + 2] = mul(a[0], 0x0D) ^ mul(a[1], 0x09) ^ mul(a[2], 0x0E) ^ mul(a[3], 0x0B);
        s[4 * c + 3] = mul(a[0], 0x0B) ^ mul(a[1], 0x0D) ^ mul(a[2], 0x09) ^ mul(a[3], 0x0E);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aes128_fips197_vector() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let ctx = AesCtx::new(&key, false);
        let mut block: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        ctx.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));

        ctx.decrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn v6_round_key_patch_changes_output() {
        let key = crate::crypto::AES_KEY_V6;
        let mut plain: [u8; 16] = [0u8; 16];
        plain.copy_from_slice(&crate::crypto::AES_KEY_V5);

        let mut a = plain;
        AesCtx::new(&key, false).encrypt_block(&mut a);
        let mut b = plain;
        AesCtx::new(&key, true).encrypt_block(&mut b);

        assert_ne!(a, b, "is_v6 的 round key 魔改没有生效");
    }

    #[test]
    fn aes160_roundtrip() {
        let ctx = AesCtx::new(&crate::crypto::AES_KEY_V4, false);
        let original: [u8; 16] = [0x11; 16];
        let mut block = original;
        ctx.encrypt_block(&mut block);
        assert_ne!(block, original);
        ctx.decrypt_block(&mut block);
        assert_eq!(block, original);
    }
}
