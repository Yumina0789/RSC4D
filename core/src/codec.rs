

use crate::crypto::{
    self, aes::AesCtx, cbc, sha, AES_KEY_V5, AES_KEY_V6, HWID, TIME_C1, TIME_C2, TIME_C3,
};
use crate::kms::{self, Config};
use crate::kmsdata;

pub const VERSION_SIZE: usize = 4;
pub const IV_SIZE: usize = 16;

pub const V6_DECRYPT_SIZE: usize = IV_SIZE + kms::REQUEST_SIZE + 4;

pub const V6_UNENCRYPTED_SIZE: usize = VERSION_SIZE + IV_SIZE;

pub const V4_PRE_EPID_SIZE: usize = VERSION_SIZE + 4;

pub const V4_POST_EPID_SIZE: usize = 16 + 8 + 4 + 4 + 4;

pub const V5_POST_EPID_SIZE: usize = V4_POST_EPID_SIZE + 16 + 32;

pub const V6_POST_EPID_SIZE: usize = V5_POST_EPID_SIZE + 8 + 16 + 16;

pub const HMAC_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V4,
    V5,
    V6,
}

impl ProtocolVersion {
    fn is_v6(self) -> bool {
        matches!(self, ProtocolVersion::V6)
    }

    pub fn min_request_len(self) -> usize {
        match self {
            ProtocolVersion::V4 => kms::REQUEST_SIZE + 16,
            ProtocolVersion::V5 | ProtocolVersion::V6 => VERSION_SIZE + V6_DECRYPT_SIZE,
        }
    }
}

pub fn protocol_version(request: &[u8]) -> Option<ProtocolVersion> {
    if request.len() < VERSION_SIZE {
        return None;
    }
    match u16::from_le_bytes([request[2], request[3]]) {
        4 => Some(ProtocolVersion::V4),
        5 => Some(ProtocolVersion::V5),
        6 => Some(ProtocolVersion::V6),
        _ => None,
    }
}

pub fn build_response(request: &[u8], cfg: &Config, now_unix: i64) -> Result<Vec<u8>, u32> {
    match protocol_version(request) {
        Some(ProtocolVersion::V4) => build_response_v4(request, cfg, now_unix),
        Some(v5_or_v6) => build_response_v5_v6(request, v5_or_v6, cfg, now_unix),
        None => Err(kms::HRESULT_INVALID_DATA),
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub version: ProtocolVersion,
    pub kms_id: [u8; 16],
    pub cmid: [u8; 16],
    pub count: u32,

    pub product: Option<&'static str>,
}

pub fn inspect_request(request: &[u8], cfg: &Config, now_unix: i64) -> Option<RequestInfo> {
    let version = protocol_version(request)?;
    if request.len() < version.min_request_len() {
        return None;
    }

    let base = match version {
        ProtocolVersion::V4 => request[..kms::REQUEST_SIZE].to_vec(),
        _ => {
            let v6 = version.is_v6();
            let ctx = AesCtx::new(if v6 { &AES_KEY_V6 } else { &AES_KEY_V5 }, v6);
            let mut dec = request[VERSION_SIZE..VERSION_SIZE + V6_DECRYPT_SIZE].to_vec();
            cbc::decrypt_cbc(&ctx, None, &mut dec);
            dec[IV_SIZE..IV_SIZE + kms::REQUEST_SIZE].to_vec()
        }
    };

    let req = kms::Request::parse(&base)?;
    let response = kms::create_response_base(&req, cfg, now_unix).ok()?;
    Some(RequestInfo {
        version,
        kms_id: req.kms_id,
        cmid: req.cmid,
        count: response.count,
        product: kmsdata::find_product_by_kms_id(&req.kms_id).map(|(_, p)| p.name),
    })
}

pub fn build_response_v4(request: &[u8], cfg: &Config, now_unix: i64) -> Result<Vec<u8>, u32> {
    if request.len() < ProtocolVersion::V4.min_request_len() {
        return Err(kms::HRESULT_INVALID_DATA);
    }

    let base = kms::create_response_base(&kms::Request::parse(request).unwrap(), cfg, now_unix)?;
    let pid_size = base.pid_size as usize;

    let mut out = Vec::with_capacity(V4_PRE_EPID_SIZE + pid_size + V4_POST_EPID_SIZE + 16);
    out.extend_from_slice(&base.version);
    out.extend_from_slice(&base.pid_size.to_le_bytes());
    for w in &base.pid {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&base.cmid);
    out.extend_from_slice(&base.client_time.to_le_bytes());
    out.extend_from_slice(&base.count.to_le_bytes());
    out.extend_from_slice(&base.vl_activation_interval.to_le_bytes());
    out.extend_from_slice(&base.vl_renewal_interval.to_le_bytes());

    let mac = crypto::cmac::aes_cmac_v4(&out);
    out.extend_from_slice(&mac);
    Ok(out)
}

pub fn build_response_v5_v6(
    request: &[u8],
    version: ProtocolVersion,
    cfg: &Config,
    now_unix: i64,
) -> Result<Vec<u8>, u32> {
    if request.len() < version.min_request_len() {
        return Err(kms::HRESULT_INVALID_DATA);
    }
    let v6 = version.is_v6();
    let ctx = AesCtx::new(if v6 { &AES_KEY_V6 } else { &AES_KEY_V5 }, v6);

    let mut decrypted = request[VERSION_SIZE..VERSION_SIZE + V6_DECRYPT_SIZE].to_vec();
    cbc::decrypt_cbc(&ctx, None, &mut decrypted);

    let request_iv: [u8; 16] = decrypted[0..16].try_into().unwrap();
    let request_base = &decrypted[IV_SIZE..IV_SIZE + kms::REQUEST_SIZE];
    let base = kms::create_response_base(
        &kms::Request::parse(request_base).ok_or(kms::HRESULT_INVALID_DATA)?,
        cfg,
        now_unix,
    )?;

    let random = crypto::random16();
    let hash = sha::sha256(&random);

    let outer_version = &request[0..VERSION_SIZE];
    let outer_iv: [u8; 16] = if v6 {
        crypto::random16()
    } else {
        request_iv
    };

    let mut random_xored = random;
    for k in 0..16 {
        random_xored[k] ^= request_iv[k];
    }

    let mut enc = Vec::with_capacity(24 + base.pid.len() * 2 + V6_POST_EPID_SIZE);
    enc.extend_from_slice(&outer_iv);
    enc.extend_from_slice(&base.version);
    enc.extend_from_slice(&base.pid_size.to_le_bytes());
    for w in &base.pid {
        enc.extend_from_slice(&w.to_le_bytes());
    }
    enc.extend_from_slice(&base.cmid);
    enc.extend_from_slice(&base.client_time.to_le_bytes());
    enc.extend_from_slice(&base.count.to_le_bytes());
    enc.extend_from_slice(&base.vl_activation_interval.to_le_bytes());
    enc.extend_from_slice(&base.vl_renewal_interval.to_le_bytes());
    enc.extend_from_slice(&random_xored);
    enc.extend_from_slice(&hash);
    if v6 {
        enc.extend_from_slice(&HWID);
        enc.extend_from_slice(&request_iv);
        enc.extend_from_slice(&[0u8; HMAC_SIZE]);
    }

    if v6 {
        let hmac = create_v6_hmac(base.client_time, &enc, 0);
        let off = enc.len() - HMAC_SIZE;
        enc[off..].copy_from_slice(&hmac);
    }

    cbc::encrypt_cbc(&ctx, None, &mut enc);

    let mut out = Vec::with_capacity(VERSION_SIZE + enc.len());
    out.extend_from_slice(outer_version);
    out.extend_from_slice(&enc);
    Ok(out)
}

pub fn create_v6_hmac(client_time: u64, enc: &[u8], tolerance: i64) -> [u8; HMAC_SIZE] {
    let time_slot = (client_time / TIME_C1)
        .wrapping_mul(TIME_C2)
        .wrapping_add(TIME_C3)
        .wrapping_add((tolerance as u64).wrapping_mul(TIME_C1));

    let key_hash = sha::sha256(&time_slot.to_le_bytes());
    let key: [u8; 16] = key_hash[16..32].try_into().unwrap();

    let covered = enc.len() - HMAC_SIZE;
    let mac = sha::hmac_sha256(&key, &enc[..covered]);
    mac[16..32].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AES_KEY_V5;

    #[test]
    fn protocol_version_reads_major_from_offset_2() {
        let mut req = vec![0u8; 8];
        req[2] = 6;
        assert_eq!(protocol_version(&req), Some(ProtocolVersion::V6));
        req[2] = 5;
        assert_eq!(protocol_version(&req), Some(ProtocolVersion::V5));
        req[2] = 4;
        assert_eq!(protocol_version(&req), Some(ProtocolVersion::V4));
        req[2] = 7;
        assert_eq!(protocol_version(&req), None);
        assert_eq!(protocol_version(&[0u8; 3]), None);
    }

    #[test]
    fn short_request_is_rejected_per_version() {
        let cfg = Config::default();

        let mut req = vec![0u8; 100];
        req[2] = 6;
        assert_eq!(
            build_response(&req, &cfg, 0).unwrap_err(),
            kms::HRESULT_INVALID_DATA
        );

        let mut req = vec![0u8; 100];
        req[2] = 4;
        assert_eq!(
            build_response(&req, &cfg, 0).unwrap_err(),
            kms::HRESULT_INVALID_DATA
        );
    }

    #[test]
    fn hmac_tolerance_moves_the_slot() {
        let enc = vec![0u8; 128];
        let t = crypto::unix_to_filetime(1_700_000_000);
        assert_ne!(
            create_v6_hmac(t, &enc, 0),
            create_v6_hmac(t, &enc, 1),
            "±1 time slot must produce a different HMAC"
        );
        assert_eq!(
            create_v6_hmac(t, &enc, 0),
            create_v6_hmac(t, &enc, 0),
            "the same time slot must be stable"
        );
    }

    #[test]
    fn v5_and_v6_use_different_keys() {

        let plain = vec![0x11u8; 32];
        let mut a = plain.clone();
        cbc::encrypt_cbc(&AesCtx::new(&AES_KEY_V5, false), None, &mut a);
        let mut b = plain;
        cbc::encrypt_cbc(&AesCtx::new(&AES_KEY_V6, true), None, &mut b);
        assert_ne!(a, b);
    }
}
