

use std::io::Write;
use std::net::{TcpListener, TcpStream};

use rs_c4d::codec::{self, ProtocolVersion};
use rs_c4d::crypto::{self, aes::AesCtx, cbc, cmac, sha, AES_KEY_V5, AES_KEY_V6, HWID};
use rs_c4d::kms::{self, Config};
use rs_c4d::rpc;
use rs_c4d::transport::{self, ServerConfig};

const CLIENT_TIME_UNIX: i64 = 1_700_000_000;

fn make_request(version: ProtocolVersion, n_policy: u32) -> kms::Request {
    let major: u16 = match version {
        ProtocolVersion::V4 => 4,
        ProtocolVersion::V5 => 5,
        ProtocolVersion::V6 => 6,
    };
    let mut ver = [0u8; 4];
    ver[2..4].copy_from_slice(&major.to_le_bytes());

    kms::Request {
        version: ver,
        major,
        minor: 0,
        app_id: [0xAAu8; 16],
        sku_id: [0xBBu8; 16],
        kms_id: [0xCCu8; 16],
        cmid: [0x11u8; 16],
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

fn build_v4_request(req: &kms::Request) -> Vec<u8> {
    let body = serialize_request(req);
    let mut out = body.clone();
    out.extend_from_slice(&cmac::aes_cmac_v4(&body));
    out
}

fn build_v5_v6_request(req: &kms::Request, request_iv: [u8; 16]) -> Vec<u8> {
    let v6 = req.major > 5;
    let ctx = AesCtx::new(if v6 { &AES_KEY_V6 } else { &AES_KEY_V5 }, v6);
    let mut body = serialize_request(req);
    cbc::encrypt_cbc(&ctx, Some(&request_iv), &mut body);
    assert_eq!(body.len(), kms::REQUEST_SIZE + 4);

    let mut out = Vec::new();
    out.extend_from_slice(&req.version);
    out.extend_from_slice(&request_iv);
    out.extend_from_slice(&body);
    out
}

fn effective_request_iv(request_iv: &[u8; 16], v6: bool) -> [u8; 16] {
    let ctx = AesCtx::new(if v6 { &AES_KEY_V6 } else { &AES_KEY_V5 }, v6);
    let mut b = *request_iv;
    ctx.decrypt_block(&mut b);
    b
}

fn verify_v4_response(resp: &[u8], req: &kms::Request) {
    assert!(resp.len() >= codec::V4_PRE_EPID_SIZE + codec::V4_POST_EPID_SIZE + 16);

    let pid_size = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;

    assert!(
        rs_c4d::validate::check_pid_length(resp),
        "PIDSize/KmsPID 必须通过 checkPidLength"
    );

    let tail = &resp[8 + pid_size..8 + pid_size + codec::V4_POST_EPID_SIZE];
    assert_eq!(&tail[0..16], &req.cmid);
    assert_eq!(
        u64::from_le_bytes(tail[16..24].try_into().unwrap()),
        req.client_time
    );

    let message = &resp[..8 + pid_size + codec::V4_POST_EPID_SIZE];
    let mac = cmac::aes_cmac_v4(message);
    assert_eq!(
        &resp[8 + pid_size + codec::V4_POST_EPID_SIZE..][..16],
        &mac[..]
    );

    assert_eq!(&resp[0..4], &req.version);
}

fn verify_v5_v6_response(resp: &[u8], req: &kms::Request, request_iv: &[u8; 16]) {
    let v6 = req.major > 5;
    let ctx = AesCtx::new(if v6 { &AES_KEY_V6 } else { &AES_KEY_V5 }, v6);

    assert_eq!(&resp[0..4], &req.version, "外层 Version 必须回显");

    let mut enc = resp[4..].to_vec();
    assert_eq!(enc.len() % 16, 0, "加密区必须是块对齐的");
    cbc::decrypt_cbc(&ctx, None, &mut enc);

    let pad = *enc.last().unwrap() as usize;
    assert!((1..=16).contains(&pad), "PKCS#7 填充非法");
    assert!(enc[enc.len() - pad..].iter().all(|&b| b as usize == pad));
    let plain = &enc[..enc.len() - pad];

    let post = if v6 {
        codec::V6_POST_EPID_SIZE
    } else {
        codec::V5_POST_EPID_SIZE
    };
    assert_eq!(plain.len(), 24 + post + pid_len(plain));

    let response_iv = &plain[0..16];
    let inner_version = &plain[16..20];
    let pid_size = u32::from_le_bytes(plain[20..24].try_into().unwrap()) as usize;
    let rest = &plain[24 + pid_size..];

    assert_eq!(inner_version, &req.version, "内层 Version 必须回显");
    assert_eq!(&rest[0..16], &req.cmid, "CMID 必须回显");
    assert_eq!(
        u64::from_le_bytes(rest[16..24].try_into().unwrap()),
        req.client_time,
        "ClientTime 必须回显"
    );

    let random_xored = &rest[36..52];
    let hash = &rest[52..84];

    let eff_iv = effective_request_iv(request_iv, v6);

    let mut random = [0u8; 16];
    for k in 0..16 {
        random[k] = random_xored[k] ^ eff_iv[k];
    }
    assert_eq!(
        &sha::sha256(&random)[..],
        hash,
        "Hash 必须是 SHA256(random)"
    );

    if v6 {
        let hwid = &rest[84..92];
        let xored_ivs = &rest[92..108];
        let hmac = &rest[108..124];

        assert_eq!(hwid, &HWID[..], "HwId 必须是协议常量");
        assert_eq!(xored_ivs, &eff_iv[..], "XoredIVs 必须是解密后的请求 IV");
        assert_ne!(
            response_iv,
            &request_iv[..],
            "v6 响应 IV 应随机，不能等于请求 IV"
        );

        let client_time = u64::from_le_bytes(rest[16..24].try_into().unwrap());
        let candidates: Vec<[u8; 16]> = (-1i64..=1)
            .map(|tol| codec::create_v6_hmac(client_time, plain, tol))
            .collect();
        assert!(
            candidates.iter().any(|c| c[..] == hmac[..]),
            "v6 HMAC 校验失败（含 ±1 时隙容差）\n  plain.len()={} pid_size={} covered={}\n  client_time={:#018x}\n  got ={:02x?}\n  t-1 ={:02x?}\n  t0  ={:02x?}\n  t+1 ={:02x?}",
            plain.len(),
            pid_size,
            plain.len() - 16,
            client_time,
            hmac,
            candidates[0],
            candidates[1],
            candidates[2],
        );
    } else {

        assert_eq!(
            response_iv,
            &eff_iv[..],
            "v5 响应 IV 必须等于解密后的请求 IV"
        );
    }
}

fn pid_len(plain: &[u8]) -> usize {
    u32::from_le_bytes(plain[20..24].try_into().unwrap()) as usize
}

#[test]
fn v4_roundtrip() {
    let cfg = Config::default();
    let req = make_request(ProtocolVersion::V4, 10);
    let request = build_v4_request(&req);
    let resp = codec::build_response(&request, &cfg, CLIENT_TIME_UNIX).unwrap();
    verify_v4_response(&resp, &req);
}

#[test]
fn v5_roundtrip() {
    let cfg = Config::default();
    let req = make_request(ProtocolVersion::V5, 10);
    let iv = [0x5Au8; 16];
    let request = build_v5_v6_request(&req, iv);
    let resp = codec::build_response(&request, &cfg, CLIENT_TIME_UNIX).unwrap();
    verify_v5_v6_response(&resp, &req, &iv);
}

#[test]
fn v6_roundtrip() {
    let cfg = Config::default();
    let req = make_request(ProtocolVersion::V6, 10);
    let iv = [0x77u8; 16];
    let request = build_v5_v6_request(&req, iv);
    let resp = codec::build_response(&request, &cfg, CLIENT_TIME_UNIX).unwrap();
    verify_v5_v6_response(&resp, &req, &iv);
}

#[test]
fn v4_length_regressions_are_rejected_not_ub() {
    let cfg = Config::default();
    let req = make_request(ProtocolVersion::V4, 10);

    for len in [0usize, 8, 100, kms::REQUEST_SIZE] {
        let mut request = build_v4_request(&req);
        request.truncate(len);
        assert!(codec::build_response(&request, &cfg, CLIENT_TIME_UNIX).is_err());
    }

    let mut request = build_v4_request(&req);
    request.extend_from_slice(&[0u8; 64]);
    assert!(codec::build_response(&request, &cfg, CLIENT_TIME_UNIX).is_ok());
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

#[test]
fn tcp_end_to_end_bind_and_two_v6_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定随机端口");
    let port = listener.local_addr().unwrap().port();

    let cfg = ServerConfig {
        listen: "127.0.0.1".to_string(),
        port,
        max_tasks: 4,
        verbose: false,
        kms: Config::default(),
    };
    let server = std::thread::spawn(move || transport::serve_on(listener, cfg));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连接服务端");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    stream.write_all(&client_bind_frame(2)).unwrap();
    let (hdr, body) = rpc::read_frame(&mut stream)
        .unwrap()
        .expect("应收到 bind ack");
    assert_eq!(hdr.packet_type, rpc::PT_BIND_ACK);
    assert_eq!(
        u32::from_le_bytes(body[16..20].try_into().unwrap()),
        3,
        "三个上下文都有结果"
    );

    assert_eq!(
        u16::from_le_bytes(body[20..22].try_into().unwrap()),
        rpc::RPC_BIND_NACK
    );
    assert_eq!(
        u16::from_le_bytes(body[44..46].try_into().unwrap()),
        rpc::RPC_BIND_ACCEPT
    );

    for (i, iv_byte) in [0x31u8, 0x32].iter().enumerate() {
        let req = make_request(ProtocolVersion::V6, 5 + i as u32);
        let iv = [*iv_byte; 16];
        let kms_request = build_v5_v6_request(&req, iv);

        stream
            .write_all(&client_request_frame(3 + i as u32, 1, true, &kms_request))
            .unwrap();
        let (hdr, body) = rpc::read_frame(&mut stream).unwrap().expect("应收到响应");
        assert_eq!(hdr.packet_type, rpc::PT_RESPONSE);
        assert_eq!(hdr.call_id, 3 + i as u32);

        let payload = extract_kms_payload(&body, true);
        verify_v5_v6_response(&payload, &req, &iv);
    }

    drop(stream);

    let _ = server;
}

#[test]
fn tcp_end_to_end_v4_over_ndr32() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定随机端口");
    let port = listener.local_addr().unwrap().port();

    let cfg = ServerConfig {
        listen: "127.0.0.1".to_string(),
        port,
        max_tasks: 4,
        verbose: false,
        kms: Config::default(),
    };
    let _server = std::thread::spawn(move || transport::serve_on(listener, cfg));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连接服务端");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    stream.write_all(&client_bind_frame(2)).unwrap();
    let (hdr, _body) = rpc::read_frame(&mut stream)
        .unwrap()
        .expect("应收到 bind ack");
    assert_eq!(hdr.packet_type, rpc::PT_BIND_ACK);

    let req = make_request(ProtocolVersion::V4, 10);
    let kms_request = build_v4_request(&req);
    stream
        .write_all(&client_request_frame(3, 0, false, &kms_request))
        .unwrap();

    let (hdr, body) = rpc::read_frame(&mut stream).unwrap().expect("应收到响应");
    assert_eq!(hdr.packet_type, rpc::PT_RESPONSE);

    let payload = extract_kms_payload(&body, false);
    verify_v4_response(&payload, &req);
}
