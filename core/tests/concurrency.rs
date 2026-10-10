

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use rs_c4d::codec;
use rs_c4d::crypto::{self, aes::AesCtx, cbc, AES_KEY_V6};
use rs_c4d::kms::{self, Config};
use rs_c4d::rpc;
use rs_c4d::transport::{self, ServerConfig};

const CONNS: usize = 8;
const CLIENT_TIME_UNIX: i64 = 1_700_000_000;

const READ_TIMEOUT: Duration = Duration::from_secs(5);

const V6_VERSION: [u8; 4] = [0, 0, 6, 0];

fn make_request(cmid: [u8; 16], n_policy: u32) -> kms::Request {
    kms::Request {
        version: V6_VERSION,
        major: 6,
        minor: 0,
        app_id: [0xAAu8; 16],
        sku_id: [0xBBu8; 16],
        kms_id: [0xCCu8; 16],
        cmid,
        n_policy,
        client_time: crypto::unix_to_filetime(CLIENT_TIME_UNIX),
    }
}

fn serialize_request(req: &kms::Request) -> Vec<u8> {
    let mut v = vec![0u8; kms::REQUEST_SIZE];
    v[0..4].copy_from_slice(&req.version);
    v[16..32].copy_from_slice(&req.app_id);
    v[32..48].copy_from_slice(&req.sku_id);
    v[48..64].copy_from_slice(&req.kms_id);
    v[64..80].copy_from_slice(&req.cmid);
    v[80..84].copy_from_slice(&req.n_policy.to_le_bytes());
    v[84..92].copy_from_slice(&req.client_time.to_le_bytes());
    v
}

fn build_v6_request(req: &kms::Request, iv: [u8; 16]) -> Vec<u8> {
    let mut body = serialize_request(req);
    cbc::encrypt_cbc(&AesCtx::new(&AES_KEY_V6, true), Some(&iv), &mut body);
    assert_eq!(body.len(), kms::REQUEST_SIZE + 4);

    let mut out = req.version.to_vec();
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    out
}

fn client_bind_frame(call_id: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0xFFFFu16.to_le_bytes());
    body.extend_from_slice(&0xFFFFu16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&3u32.to_le_bytes());

    let item = |body: &mut Vec<u8>, ctx: u16, syntax: [u8; 16], ver: u32| {
        body.extend_from_slice(&ctx.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&rpc::INTERFACE_UUID);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&syntax);
        body.extend_from_slice(&ver.to_le_bytes());
    };
    item(&mut body, 0, rpc::TRANSFER_SYNTAX_NDR32, 2);
    item(&mut body, 1, rpc::TRANSFER_SYNTAX_NDR64, 1);
    item(&mut body, 2, rpc::BIND_TIME_FEATURE_NEGOTIATION, 1);

    let frag_length = (rpc::RPC_HEADER_SIZE + body.len()) as u16;
    let mut frame = rpc::RpcHeader::encode(
        rpc::PT_BIND_REQ,
        rpc::PF_FIRST | rpc::PF_LAST,
        call_id,
        frag_length,
    )
    .to_vec();
    frame.extend_from_slice(&body);
    frame
}

fn client_request_frame(
    call_id: u32,
    context_id: u16,
    is_ndr64: bool,
    kms_request: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&context_id.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    if is_ndr64 {
        body.extend_from_slice(&(kms_request.len() as u64).to_le_bytes());
        body.extend_from_slice(&(kms_request.len() as u64).to_le_bytes());
    } else {
        body.extend_from_slice(&(kms_request.len() as u32).to_le_bytes());
        body.extend_from_slice(&(kms_request.len() as u32).to_le_bytes());
    }
    body.extend_from_slice(kms_request);

    let frag_length = (rpc::RPC_HEADER_SIZE + body.len()) as u16;
    let mut frame = rpc::RpcHeader::encode(
        rpc::PT_REQUEST,
        rpc::PF_FIRST | rpc::PF_LAST,
        call_id,
        frag_length,
    )
    .to_vec();
    frame.extend_from_slice(&body);
    frame
}

fn extract_kms_payload(body: &[u8], is_ndr64: bool) -> Vec<u8> {
    let prefix = if is_ndr64 { 8usize } else { 4usize };
    let data_off = 8 + 3 * prefix;
    let data_len = if is_ndr64 {
        u64::from_le_bytes(body[8..16].try_into().unwrap()) as usize
    } else {
        u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize
    };

    let status = u32::from_le_bytes(
        body[data_off + data_len..data_off + data_len + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(status, 0, "RPC 返回码应为成功");
    body[data_off..data_off + data_len].to_vec()
}

fn decrypt_v6_echo(payload: &[u8]) -> ([u8; 16], u64) {
    assert_eq!(&payload[0..4], &V6_VERSION, "外层 Version 必须回显");

    let mut enc = payload[4..].to_vec();
    assert_eq!(enc.len() % 16, 0, "加密区必须块对齐");
    cbc::decrypt_cbc(&AesCtx::new(&AES_KEY_V6, true), None, &mut enc);

    let pad = *enc.last().unwrap() as usize;
    assert!((1..=16).contains(&pad), "PKCS#7 填充非法");
    assert!(enc[enc.len() - pad..].iter().all(|&b| b as usize == pad));
    let plain = &enc[..enc.len() - pad];

    assert_eq!(&plain[16..20], &V6_VERSION, "内层 Version 必须回显");
    let pid_size = u32::from_le_bytes(plain[20..24].try_into().unwrap()) as usize;
    assert_eq!(plain.len(), 24 + pid_size + codec::V6_POST_EPID_SIZE);

    let rest = &plain[24 + pid_size..];
    (
        rest[0..16].try_into().unwrap(),
        u64::from_le_bytes(rest[16..24].try_into().unwrap()),
    )
}

#[test]
fn concurrent_connections_keep_their_own_cmid() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定随机端口");
    let port = listener.local_addr().unwrap().port();

    let cfg = ServerConfig {
        listen: "127.0.0.1".to_string(),
        port,
        max_tasks: CONNS,
        verbose: false,
        kms: Config::default(),
    };
    let _server = std::thread::spawn(move || transport::serve_on(listener, cfg));

    let gate = Arc::new(Barrier::new(CONNS));
    let handles: Vec<_> = (0..CONNS)
        .map(|i| {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || one_connection(port, i, &gate))
        })
        .collect();

    for h in handles {
        h.join().expect("连接线程失败");
    }
}

fn one_connection(port: u16, i: usize, gate: &Barrier) {

    let cmid = [i as u8 + 1; 16];
    let iv = [(i as u8).wrapping_mul(17).wrapping_add(3); 16];
    let call_id = 0x1000 + i as u32;
    let req = make_request(cmid, 1 + i as u32);
    let kms_request = build_v6_request(&req, iv);

    gate.wait();

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连接服务端");
    stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    stream.write_all(&client_bind_frame(call_id - 1)).unwrap();
    let (hdr, body) = rpc::read_frame(&mut stream)
        .unwrap()
        .expect("应收到 bind ack");
    assert_eq!(hdr.packet_type, rpc::PT_BIND_ACK);
    assert_eq!(
        u16::from_le_bytes(body[44..46].try_into().unwrap()),
        rpc::RPC_BIND_ACCEPT,
        "连接 {} 的 NDR64 上下文应被接受",
        i
    );

    stream
        .write_all(&client_request_frame(call_id, 1, true, &kms_request))
        .unwrap();
    let (hdr, body) = rpc::read_frame(&mut stream).unwrap().expect("应收到响应");
    assert_eq!(hdr.packet_type, rpc::PT_RESPONSE, "连接 {}", i);
    assert_eq!(hdr.call_id, call_id, "CallId 必须回显本连接的请求");

    let (got_cmid, got_time) = decrypt_v6_echo(&extract_kms_payload(&body, true));
    assert_eq!(got_cmid, cmid, "连接 {} 拿到了别的连接的 CMID（串包）", i);
    assert_eq!(
        got_time, req.client_time,
        "连接 {} 的 ClientTime 必须回显",
        i
    );
}
