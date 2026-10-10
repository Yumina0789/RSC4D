

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use rs_c4d::codec;
use rs_c4d::crypto;
use rs_c4d::crypto::aes::AesCtx;
use rs_c4d::crypto::cbc::decrypt_cbc;
use rs_c4d::rpc;
use rs_c4d::transport::{self, ServerConfig};

const HEADER: usize = rpc::RPC_HEADER_SIZE;

const STUB_START: usize = 8;

const NDR_HEADER: usize = 12;

const PAYLOAD_LEN: usize = 8;

const POST_EPID: usize = 16 + 8 + 4 + 4 + 4;
const HASH_SIZE: usize = 32;
const HWID_SIZE: usize = 8;
const HMAC_SIZE: usize = 16;

fn read_case(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/cases/{name}");
    std::fs::read(&path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn start_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local address").port();
    std::thread::spawn(move || {
        let _ = transport::serve_on(listener, ServerConfig::default());
    });
    port
}

fn exchange(port: u16, recorded: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("connect to the server");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set a read timeout");
    socket.write_all(recorded).expect("send the recording");
    socket.flush().expect("flush");

    let _bind_ack = rpc::read_frame(&mut socket)
        .expect("read the bind acknowledgement")
        .expect("the server closed early");
    let (header, body) = rpc::read_frame(&mut socket)
        .expect("read the response")
        .expect("the server closed early");
    assert_eq!(
        header.packet_type,
        rpc::PT_RESPONSE,
        "expected a response PDU"
    );
    payload_of_body(&body).to_vec()
}

fn payload_of_body(body: &[u8]) -> &[u8] {
    let stub = &body[STUB_START..];
    assert!(
        stub.len() >= NDR_HEADER,
        "stub of {} bytes is too short for an NDR header",
        stub.len()
    );
    let length =
        u32::from_le_bytes(stub[PAYLOAD_LEN..PAYLOAD_LEN + 4].try_into().unwrap()) as usize;
    let end = NDR_HEADER + length;
    assert!(
        end <= stub.len(),
        "declared payload of {length} bytes exceeds the {} byte stub",
        stub.len()
    );
    &stub[NDR_HEADER..end]
}

fn payload_of_frame(frame: &[u8], packet_type: u8) -> &[u8] {
    let mut start = 0usize;
    while start + HEADER <= frame.len() {
        let current = frame[start + 2];
        let fragment = u16::from_le_bytes([frame[start + 8], frame[start + 9]]) as usize;
        assert!(
            fragment >= HEADER && start + fragment <= frame.len(),
            "truncated PDU at offset {start}"
        );
        if current == packet_type {
            return payload_of_body(&frame[start + HEADER..start + fragment]);
        }
        start += fragment;
    }
    panic!(
        "no PDU of type {packet_type} in a {} byte frame",
        frame.len()
    );
}

fn decrypt_region(payload: &[u8], is_v6: bool) -> Vec<u8> {
    let key: &[u8] = if is_v6 {
        &crypto::AES_KEY_V6
    } else {
        &crypto::AES_KEY_V5
    };
    let mut region = payload[codec::VERSION_SIZE..].to_vec();
    assert_eq!(
        region.len() % 16,
        0,
        "encrypted region of {} bytes is not block aligned",
        region.len()
    );
    let context = AesCtx::new(key, is_v6);
    decrypt_cbc(&context, None, &mut region);
    region
}

struct V5V6 {
    version: u32,
    iv: [u8; 16],
    inner_version: u32,
    pid_size: u32,
    epid: Vec<u8>,
    cmid: [u8; 16],
    client_time: u64,
    count: u32,
    activation_interval: u32,
    renewal_interval: u32,
    random_xored_ivs: [u8; 16],
    hash: [u8; 32],
    hwid: Option<[u8; 8]>,
    xored_ivs: Option<[u8; 16]>,
    hmac: Option<[u8; 16]>,
    plaintext: Vec<u8>,
}

fn parse_v5_v6(payload: &[u8], is_v6: bool) -> V5V6 {
    let version = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let plaintext = decrypt_region(payload, is_v6);
    let mut offset = 0usize;

    let iv: [u8; 16] = plaintext[offset..offset + 16].try_into().unwrap();
    offset += 16;
    let inner_version = u32::from_le_bytes(plaintext[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let pid_size = u32::from_le_bytes(plaintext[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let epid = plaintext[offset..offset + pid_size as usize].to_vec();
    offset += pid_size as usize;

    let cmid: [u8; 16] = plaintext[offset..offset + 16].try_into().unwrap();
    offset += 16;
    let client_time = u64::from_le_bytes(plaintext[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let count = u32::from_le_bytes(plaintext[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let activation_interval = u32::from_le_bytes(plaintext[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let renewal_interval = u32::from_le_bytes(plaintext[offset..offset + 4].try_into().unwrap());
    offset += 4;
    assert_eq!(
        offset,
        16 + 4 + 4 + pid_size as usize + POST_EPID,
        "post-ePID parse drifted"
    );

    let random_xored_ivs: [u8; 16] = plaintext[offset..offset + 16].try_into().unwrap();
    offset += 16;
    let hash: [u8; 32] = plaintext[offset..offset + HASH_SIZE].try_into().unwrap();
    offset += HASH_SIZE;

    let (hwid, xored_ivs, hmac) = if is_v6 {
        let hwid: [u8; 8] = plaintext[offset..offset + HWID_SIZE].try_into().unwrap();
        offset += HWID_SIZE;
        let xored_ivs: [u8; 16] = plaintext[offset..offset + 16].try_into().unwrap();
        offset += 16;
        let hmac: [u8; 16] = plaintext[offset..offset + HMAC_SIZE].try_into().unwrap();
        offset += HMAC_SIZE;
        (Some(hwid), Some(xored_ivs), Some(hmac))
    } else {
        (None, None, None)
    };

    let padding = &plaintext[offset..];
    assert!(
        !padding.is_empty() && padding.len() <= 16,
        "padding of {} bytes is out of range",
        padding.len()
    );
    let pad = padding[0] as usize;
    assert_eq!(pad, padding.len(), "inconsistent PKCS#7 padding");
    assert!(
        padding.iter().all(|byte| *byte as usize == pad),
        "PKCS#7 padding bytes differ"
    );
    assert_eq!(
        offset + padding.len(),
        plaintext.len(),
        "tail parse drifted"
    );

    V5V6 {
        version,
        iv,
        inner_version,
        pid_size,
        epid,
        cmid,
        client_time,
        count,
        activation_interval,
        renewal_interval,
        random_xored_ivs,
        hash,
        hwid,
        xored_ivs,
        hmac,
        plaintext,
    }
}

fn assert_common_fields_match(mine: &V5V6, reference: &V5V6, protocol: &str) {
    assert_eq!(mine.version, reference.version, "{protocol}: outer Version");
    assert_eq!(
        mine.inner_version, reference.inner_version,
        "{protocol}: inner Version"
    );
    assert_eq!(mine.pid_size, reference.pid_size, "{protocol}: PIDSize");
    assert_eq!(
        mine.epid.len(),
        reference.epid.len(),
        "{protocol}: ePID length"
    );
    assert_eq!(mine.cmid, reference.cmid, "{protocol}: CMID echo");
    assert_eq!(
        mine.client_time, reference.client_time,
        "{protocol}: ClientTime echo"
    );
    assert_eq!(mine.count, reference.count, "{protocol}: Count");
    assert_eq!(
        mine.activation_interval, reference.activation_interval,
        "{protocol}: activation interval"
    );
    assert_eq!(
        mine.renewal_interval, reference.renewal_interval,
        "{protocol}: renewal interval"
    );
}

#[test]
fn v4_matches_the_reference_except_the_epid_and_its_mac() {
    let recorded = read_case("c1-c2s.bin");
    let reference = payload_of_frame(&read_case("c1-s2c.bin"), rpc::PT_RESPONSE).to_vec();
    let mine = exchange(start_server(), &recorded);

    assert_eq!(
        mine.len(),
        reference.len(),
        "v4 response payload length differs"
    );
    let pid_size = u32::from_le_bytes(reference[4..8].try_into().unwrap()) as usize;
    let epid = codec::V4_PRE_EPID_SIZE..codec::V4_PRE_EPID_SIZE + pid_size;
    let mac = mine.len() - codec::HMAC_SIZE..mine.len();

    let differing: Vec<usize> = (0..mine.len())
        .filter(|index| mine[*index] != reference[*index])
        .collect();
    let unexpected: Vec<usize> = differing
        .iter()
        .copied()
        .filter(|index| !epid.contains(index) && !mac.contains(index))
        .collect();

    assert!(
        unexpected.is_empty(),
        "v4 differs outside the ePID and MAC at offsets {unexpected:?}"
    );

    assert_eq!(
        &mine[..codec::V4_PRE_EPID_SIZE],
        &reference[..codec::V4_PRE_EPID_SIZE],
        "v4 Version/PIDSize must match"
    );
}

#[test]
fn v5_matches_the_reference_and_reuses_the_request_iv() {
    let recorded = read_case("c2-c2s.bin");
    let reference = parse_v5_v6(
        payload_of_frame(&read_case("c2-s2c.bin"), rpc::PT_RESPONSE),
        false,
    );
    let mine = parse_v5_v6(&exchange(start_server(), &recorded), false);

    assert_common_fields_match(&mine, &reference, "v5");

    assert_eq!(
        mine.iv, reference.iv,
        "v5 response IV must equal the request IV"
    );

    for (label, side) in [("rs-c4d", &mine), ("reference", &reference)] {

        let salt: [u8; 16] =
            std::array::from_fn(|index| side.random_xored_ivs[index] ^ side.iv[index]);
        assert_eq!(
            side.hash,
            crypto::sha::sha256(&salt),
            "{label}: Hash must be SHA256(salt)"
        );
    }

    assert!(mine.hwid.is_none() && mine.xored_ivs.is_none() && mine.hmac.is_none());
}

#[test]
fn v6_matches_the_reference_and_verifies_its_hmac() {
    let recorded = read_case("c3-c2s.bin");
    let reference = parse_v5_v6(
        payload_of_frame(&read_case("c3-s2c.bin"), rpc::PT_RESPONSE),
        true,
    );
    let mine = parse_v5_v6(&exchange(start_server(), &recorded), true);

    assert_common_fields_match(&mine, &reference, "v6");
    assert_eq!(mine.hwid, reference.hwid, "v6: HwId");

    assert_eq!(
        mine.xored_ivs, reference.xored_ivs,
        "v6: XoredIVs must be the decrypted request IV on both sides"
    );
    let request_iv = mine.xored_ivs.expect("v6 has XoredIVs");
    assert_ne!(
        mine.iv, request_iv,
        "v6 response IV must not equal the request IV"
    );
    assert_eq!(
        mine.hwid,
        Some(crypto::HWID),
        "v6: HwId is a protocol constant"
    );

    let mut failures = Vec::new();
    for (label, side) in [("rs-c4d", &mine), ("reference", &reference)] {

        let salt: [u8; 16] =
            std::array::from_fn(|index| side.random_xored_ivs[index] ^ request_iv[index]);
        if side.hash != crypto::sha::sha256(&salt) {
            failures.push(format!("{label}: Hash is not SHA256(salt)"));
        }

        let pad = *side.plaintext.last().expect("a non-empty plaintext") as usize;
        let covered = side.plaintext.len() - pad - HMAC_SIZE;

        let time_slot = (side.client_time / crypto::TIME_C1)
            .wrapping_mul(crypto::TIME_C2)
            .wrapping_add(crypto::TIME_C3);
        let key_hash = crypto::sha::sha256(&time_slot.to_le_bytes());
        let mac = crypto::sha::hmac_sha256(&key_hash[16..], &side.plaintext[..covered]);
        let expected: [u8; 16] = mac[16..].try_into().unwrap();
        if side.hmac.expect("v6 has an HMAC") != expected {
            failures.push(format!(
                "{label}: HMAC mismatch over {} unpadded bytes ({}); got {} want {}",
                covered,
                side.plaintext.len(),
                hex(&side.hmac.expect("v6 has an HMAC")),
                hex(&expected)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "v6 HMAC verification failed: {failures:?}"
    );
}
