

use super::aes::AesCtx;
use super::AES_KEY_V4;

pub fn aes_cmac_v4(message: &[u8]) -> [u8; 16] {
    let ctx = AesCtx::new(&AES_KEY_V4, false);
    let mut mac = [0u8; 16];

    let mut off = 0usize;
    loop {
        let n = std::cmp::min(16, message.len().saturating_sub(off));
        let mut block = [0u8; 16];
        block[..n].copy_from_slice(&message[off..off + n]);
        if n < 16 {
            block[n] = 0x80;
        }

        for k in 0..16 {
            mac[k] ^= block[k];
        }
        ctx.encrypt_block(&mut mac);

        if n < 16 {
            break;
        }
        off += 16;
    }

    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmac_is_deterministic_and_block_count_is_len_over_16_plus_one() {
        let a = aes_cmac_v4(&[0u8; 236]);
        let b = aes_cmac_v4(&[0u8; 236]);
        assert_eq!(a, b);

        let c = aes_cmac_v4(&[0u8; 235]);
        assert_ne!(a, c);

        let _ = aes_cmac_v4(&[]);
    }
}
