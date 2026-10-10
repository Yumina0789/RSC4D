

use super::aes::AesCtx;

pub fn encrypt_cbc(ctx: &AesCtx, iv: Option<&[u8; 16]>, data: &mut Vec<u8>) {

    let pad = (16 - (data.len() % 16)) as u8;
    data.extend(std::iter::repeat_n(pad, pad as usize));

    let blocks = data.len() / 16;
    for b in 0..blocks {
        let off = b * 16;
        if b == 0 {
            if let Some(iv) = iv {
                for k in 0..16 {
                    data[off + k] ^= iv[k];
                }
            }
        } else {
            for k in 0..16 {
                data[off + k] ^= data[off - 16 + k];
            }
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        ctx.encrypt_block(&mut block);
        data[off..off + 16].copy_from_slice(&block);
    }
}

pub fn decrypt_cbc(ctx: &AesCtx, iv: Option<&[u8; 16]>, data: &mut [u8]) {
    assert!(
        data.len().is_multiple_of(16),
        "CBC 数据长度必须是 16 的倍数"
    );
    let blocks = data.len() / 16;
    if blocks == 0 {
        return;
    }

    for b in (0..blocks).rev() {
        let off = b * 16;
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        ctx.decrypt_block(&mut block);
        data[off..off + 16].copy_from_slice(&block);

        if b == 0 {
            if let Some(iv) = iv {
                for k in 0..16 {
                    data[k] ^= iv[k];
                }
            }
        } else {
            let prev = (b - 1) * 16;
            for k in 0..16 {
                data[off + k] ^= data[prev + k];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AES_KEY_V5;

    #[test]
    fn pkcs7_pads_to_next_block() {
        let ctx = AesCtx::new(&AES_KEY_V5, false);
        for len in [0usize, 1, 15, 16, 17, 32] {
            let mut data = vec![0xABu8; len];
            encrypt_cbc(&ctx, None, &mut data);
            assert_eq!(data.len() % 16, 0);
            assert!(data.len() > len || len == 0);
            assert_eq!(data.len(), ((len / 16) + 1) * 16);
        }
    }

    #[test]
    fn cbc_roundtrip_null_iv() {
        let ctx = AesCtx::new(&AES_KEY_V5, false);
        let original: Vec<u8> = (0..48u8).collect();
        let mut data = original.clone();
        encrypt_cbc(&ctx, None, &mut data);
        decrypt_cbc(&ctx, None, &mut data);

        assert_eq!(&data[..original.len()], &original[..]);
        let pad = data[data.len() - 1] as usize;
        assert!((1..=16).contains(&pad));
        assert!(data[data.len() - pad..].iter().all(|&b| b as usize == pad));
    }

    #[test]
    fn cbc_roundtrip_with_iv() {
        let ctx = AesCtx::new(&AES_KEY_V6_KEY, true);
        let iv = [0x5Au8; 16];
        let mut data = vec![7u8; 32];
        encrypt_cbc(&ctx, Some(&iv), &mut data);
        decrypt_cbc(&ctx, Some(&iv), &mut data);
        assert_eq!(&data[..32], &[7u8; 32][..]);
    }

    const AES_KEY_V6_KEY: [u8; 16] = crate::crypto::AES_KEY_V6;
}
