

use crate::crypto::filetime_to_unix;
use crate::kmsdata;

pub const REQUEST_SIZE: usize = 236;

pub const VL_ACTIVATION_INTERVAL: u32 = 120;

pub const VLR_RENEWAL_INTERVAL: u32 = 10080;

pub const MAX_REQUIRED_CLIENTS: u32 = 2000;

pub const MAX_CLOCK_SKEW_SECS: i64 = 4 * 60 * 60;

pub const HRESULT_INVALID_DATA: u32 = 0x8007_000D;
pub const HRESULT_UNKNOWN_PRODUCT: u32 = 0xC004_F042;
pub const HRESULT_CLOCK_SKEW: u32 = 0xC004_F06C;

#[derive(Debug, Clone, Copy, Default)]
pub struct Config {

    pub strict_products: bool,

    pub check_client_time: bool,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Debug, Clone)]
pub struct Request {

    pub version: [u8; 4],
    pub major: u16,
    pub minor: u16,
    pub app_id: [u8; 16],
    pub sku_id: [u8; 16],
    pub kms_id: [u8; 16],
    pub cmid: [u8; 16],
    pub n_policy: u32,
    pub client_time: u64,
}

impl Request {

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < REQUEST_SIZE {
            return None;
        }
        Some(Self {
            version: data[0..4].try_into().unwrap(),
            minor: u16le(data, 0),
            major: u16le(data, 2),
            app_id: data[16..32].try_into().unwrap(),
            sku_id: data[32..48].try_into().unwrap(),
            kms_id: data[48..64].try_into().unwrap(),
            cmid: data[64..80].try_into().unwrap(),
            n_policy: u32le(data, 80),
            client_time: u64::from_le_bytes(data[84..92].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResponseBase {
    pub version: [u8; 4],

    pub pid: Vec<u16>,
    pub pid_size: u32,
    pub cmid: [u8; 16],
    pub client_time: u64,
    pub count: u32,
    pub vl_activation_interval: u32,
    pub vl_renewal_interval: u32,
}

pub fn create_response_base(
    req: &Request,
    cfg: &Config,
    now_unix: i64,
) -> Result<ResponseBase, u32> {

    let required_clients = if req.n_policy < 1 {
        1
    } else {
        req.n_policy << 1
    };

    if required_clients > MAX_REQUIRED_CLIENTS {
        return Err(HRESULT_INVALID_DATA);
    }

    if cfg.check_client_time {
        let request_time = filetime_to_unix(req.client_time);
        if (request_time - now_unix).abs() > MAX_CLOCK_SKEW_SECS {
            return Err(HRESULT_CLOCK_SKEW);
        }
    }

    let product_index = kmsdata::find_product_by_kms_id(&req.kms_id).map(|(i, _)| i);

    if cfg.strict_products && product_index.is_none() {
        return Err(HRESULT_UNKNOWN_PRODUCT);
    }

    let csvlk = kmsdata::csvlk_for(product_index);

    let count = required_clients.max(csvlk.min_active_clients as u32);

    let pid: Vec<u16> = csvlk
        .epid
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();
    let pid_size = (pid.len() * 2) as u32;

    Ok(ResponseBase {

        version: req.version,
        pid,
        pid_size,

        cmid: req.cmid,
        client_time: req.client_time,
        count,

        vl_activation_interval: VL_ACTIVATION_INTERVAL,
        vl_renewal_interval: VLR_RENEWAL_INTERVAL,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::unix_to_filetime;

    fn make_request(kms_id: [u8; 16], n_policy: u32) -> Request {
        Request {
            version: [0u8, 0, 6, 0],
            major: 6,
            minor: 0,
            app_id: [0u8; 16],
            sku_id: [0u8; 16],
            kms_id,
            cmid: [0x11u8; 16],
            n_policy,
            client_time: unix_to_filetime(1_700_000_000),
        }
    }

    #[test]
    fn count_is_twice_policy_with_min_active_clients_floor() {
        let cfg = Config::default();

        let floor = crate::kmsdata::CSVLK[0].min_active_clients as u32;

        for (policy, required) in [(0u32, 1u32), (2, 4), (10, 20)] {
            let r = create_response_base(&make_request([0u8; 16], policy), &cfg, 1_700_000_000)
                .unwrap();
            assert_eq!(r.count, required.max(floor), "N_Policy={}", policy);
        }
    }

    #[test]
    fn policy_above_1000_is_rejected() {
        let cfg = Config::default();

        assert_eq!(
            create_response_base(&make_request([0u8; 16], 1001), &cfg, 1_700_000_000).unwrap_err(),
            HRESULT_INVALID_DATA
        );
        assert!(create_response_base(&make_request([0u8; 16], 1000), &cfg, 1_700_000_000).is_ok());
    }

    #[test]
    fn unknown_product_falls_back_or_is_rejected() {
        let req = make_request([0xABu8; 16], 5);

        let lenient = Config {
            strict_products: false,
            check_client_time: false,
        };
        let r = create_response_base(&req, &lenient, 1_700_000_000).unwrap();
        assert_eq!(
            r.pid_size as usize,
            (crate::kmsdata::CSVLK[0].epid.len() + 1) * 2
        );

        let strict = Config {
            strict_products: true,
            check_client_time: false,
        };
        assert_eq!(
            create_response_base(&req, &strict, 1_700_000_000).unwrap_err(),
            HRESULT_UNKNOWN_PRODUCT
        );
    }

    #[test]
    fn response_echoes_cmid_time_and_version() {
        let cfg = Config::default();
        let req = make_request([0u8; 16], 3);
        let r = create_response_base(&req, &cfg, 1_700_000_000).unwrap();
        assert_eq!(r.cmid, req.cmid);
        assert_eq!(r.client_time, req.client_time);
        assert_eq!(r.version, req.version);
        assert_eq!(r.vl_activation_interval, 120);
        assert_eq!(r.vl_renewal_interval, 10080);

        assert_eq!(*r.pid.last().unwrap(), 0u16);
        assert_eq!(
            String::from_utf16(&r.pid[..r.pid.len() - 1]).unwrap(),
            crate::kmsdata::CSVLK[0].epid
        );
    }

    #[test]
    fn client_time_check_is_opt_in() {
        let req = make_request([0u8; 16], 5);

        let lenient = Config::default();
        assert!(create_response_base(&req, &lenient, 1_700_000_000 + 36_000).is_ok());

        let strict = Config {
            strict_products: false,
            check_client_time: true,
        };
        assert_eq!(
            create_response_base(&req, &strict, 1_700_000_000 + 36_000).unwrap_err(),
            HRESULT_CLOCK_SKEW
        );
        assert!(create_response_base(&req, &strict, 1_700_000_000 + 3600).is_ok());
    }
}
