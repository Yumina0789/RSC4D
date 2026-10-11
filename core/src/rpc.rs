

use std::io::{self, Read};

pub const RPC_HEADER_SIZE: usize = 16;

pub const BIND_REQUEST_FIXED: usize = 12;

pub const BIND_RESPONSE_FIXED: usize = 20;

pub const CTX_ITEM_SIZE: usize = 44;

pub const CTX_RESULT_SIZE: usize = 24;

pub const RPC_INVALID_CTX: u16 = 0xFFFF;

pub const MAX_BIND_CTX_ITEMS: u32 = 8;

pub const MAX_FRAME_BODY: usize = 4096;

pub const PT_REQUEST: u8 = 0;
pub const PT_RESPONSE: u8 = 2;
pub const PT_FAULT: u8 = 3;
pub const PT_BIND_REQ: u8 = 11;
pub const PT_BIND_ACK: u8 = 12;
pub const PT_ALTERCONTEXT_REQ: u8 = 14;
pub const PT_ALTERCONTEXT_ACK: u8 = 15;

pub const PF_FIRST: u8 = 1;
pub const PF_LAST: u8 = 2;
pub const PF_NOT_EXEC: u8 = 32;

pub const RPC_BIND_ACCEPT: u16 = 0;
pub const RPC_BIND_NACK: u16 = 2;
pub const RPC_BIND_ACK: u16 = 3;
pub const RPC_SYNTAX_UNSUPPORTED: u16 = 2;
pub const RPC_ABSTRACTSYNTAX_UNSUPPORTED: u16 = 1;

pub const RPC_NCA_UNK_IF: u32 = 0x1c01_0003;

pub const RPC_NCA_PROTO_ERROR: u32 = 0x1c01_000b;

pub const RPC_DATA_SIZE_MAX: u32 = 0x0002_0000;

pub const TRANSFER_SYNTAX_NDR32: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
pub const INTERFACE_UUID: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];
pub const TRANSFER_SYNTAX_NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49, 0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36,
];
pub const BIND_TIME_FEATURE_NEGOTIATION: [u8; 16] = [
    0x2C, 0x1C, 0xB7, 0x6C, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub const RPC_BTFN_SEC_CONTEXT_MULTIPLEX: u16 = 1;
pub const RPC_BTFN_KEEP_ORPHAN: u16 = 2;

pub const DATA_REPRESENTATION: u32 = 0x1000_0000;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub packet_type: u8,
    pub packet_flags: u8,

    pub data_representation: u32,
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl RpcHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < RPC_HEADER_SIZE {
            return None;
        }
        Some(Self {
            version_major: buf[0],
            version_minor: buf[1],
            packet_type: buf[2],
            packet_flags: buf[3],

            data_representation: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            frag_length: u16le(buf, 8),
            auth_length: u16le(buf, 10),
            call_id: u32le(buf, 12),
        })
    }

    pub fn validate(&self, desired_packet_type: u8) -> Result<(), &'static str> {
        if self.version_major != 5 || self.version_minor != 0 {
            return Err("RPC version is not 5.0");
        }
        if self.packet_type != desired_packet_type {
            return Err("RPC packet type mismatch");
        }
        if self.data_representation != DATA_REPRESENTATION {
            return Err("RPC DataRepresentation is not little-endian/ASCII/IEEE");
        }
        if self.auth_length != 0 {
            return Err("RPC request carries authentication, which is not supported");
        }
        if self.packet_flags & (PF_FIRST | PF_LAST) != (PF_FIRST | PF_LAST) {
            return Err("RPC fragment flags are not FIRST|LAST, multi-fragment is not supported");
        }
        Ok(())
    }

    pub fn encode(
        packet_type: u8,
        packet_flags: u8,
        call_id: u32,
        frag_length: u16,
    ) -> [u8; RPC_HEADER_SIZE] {
        let mut h = [0u8; RPC_HEADER_SIZE];
        h[0] = 5;
        h[1] = 0;
        h[2] = packet_type;
        h[3] = packet_flags;
        h[4..8].copy_from_slice(&DATA_REPRESENTATION.to_be_bytes());
        h[8..10].copy_from_slice(&frag_length.to_le_bytes());
        h[10..12].copy_from_slice(&0u16.to_le_bytes());
        h[12..16].copy_from_slice(&call_id.to_le_bytes());
        h
    }
}

pub fn read_frame<R: Read>(stream: &mut R) -> io::Result<Option<(RpcHeader, Vec<u8>)>> {
    let mut head = [0u8; RPC_HEADER_SIZE];
    let mut filled = 0;
    while filled < RPC_HEADER_SIZE {
        let n = stream.read(&mut head[filled..])?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "RPC header truncated"))
            };
        }
        filled += n;
    }

    let header = RpcHeader::parse(&head)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RPC header too short"))?;

    let body_len = header.frag_length as usize;
    if body_len < RPC_HEADER_SIZE || body_len - RPC_HEADER_SIZE > MAX_FRAME_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unreasonable RPC FragLength: {}", header.frag_length),
        ));
    }

    let mut body = vec![0u8; body_len - RPC_HEADER_SIZE];
    stream.read_exact(&mut body)?;
    Ok(Some((header, body)))
}

#[derive(Debug, Clone)]
pub struct CtxItem {
    pub context_id: u16,
    pub num_trans_items: u16,
    pub interface_uuid: [u8; 16],
    pub interface_ver_major: u16,
    pub interface_ver_minor: u16,
    pub transfer_syntax: [u8; 16],
    pub syntax_version: u32,
}

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
    pub ctx_items: Vec<CtxItem>,
}

pub fn parse_bind_request(body: &[u8]) -> Option<BindRequest> {
    if body.len() < BIND_REQUEST_FIXED {
        return None;
    }

    let num_ctx_items = u32le(body, 8);
    if num_ctx_items > MAX_BIND_CTX_ITEMS {
        return None;
    }

    let required = BIND_REQUEST_FIXED + num_ctx_items as usize * CTX_ITEM_SIZE;
    if body.len() < required {
        return None;
    }

    let mut ctx_items = Vec::with_capacity(num_ctx_items as usize);
    for i in 0..num_ctx_items as usize {
        let o = BIND_REQUEST_FIXED + i * CTX_ITEM_SIZE;
        ctx_items.push(CtxItem {
            context_id: u16le(body, o),
            num_trans_items: u16le(body, o + 2),
            interface_uuid: body[o + 4..o + 20].try_into().unwrap(),
            interface_ver_major: u16le(body, o + 20),
            interface_ver_minor: u16le(body, o + 22),
            transfer_syntax: body[o + 24..o + 40].try_into().unwrap(),
            syntax_version: u32le(body, o + 40),
        });
    }

    Some(BindRequest {
        max_xmit_frag: u16le(body, 0),
        max_recv_frag: u16le(body, 2),
        assoc_group: u32le(body, 4),
        ctx_items,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct BindState {
    pub ndr32_ctx: u16,
    pub ndr64_ctx: u16,
}

impl Default for BindState {
    fn default() -> Self {
        Self {
            ndr32_ctx: RPC_INVALID_CTX,
            ndr64_ctx: RPC_INVALID_CTX,
        }
    }
}

pub struct BindResponse {
    pub frame: Vec<u8>,
    pub state: BindState,
}

pub fn build_bind_response(
    header: &RpcHeader,
    req: &BindRequest,
    packet_type: u8,
    assoc_group: u32,
    port: u16,
    use_ndr64: bool,
    use_btfn: bool,
) -> BindResponse {
    let mut state = BindState::default();

    let is_ndr64_possible = use_ndr64
        && req
            .ctx_items
            .iter()
            .any(|c| c.transfer_syntax == TRANSFER_SYNTAX_NDR64);
    for item in &req.ctx_items {
        if item.transfer_syntax == TRANSFER_SYNTAX_NDR32 {
            state.ndr32_ctx = item.context_id;
        }
        if use_ndr64 && item.transfer_syntax == TRANSFER_SYNTAX_NDR64 {
            state.ndr64_ctx = item.context_id;
        }
    }

    let mut results: Vec<[u8; CTX_RESULT_SIZE]> = Vec::with_capacity(req.ctx_items.len());
    for item in &req.ctx_items {
        let is_interface_uuid = item.interface_uuid == INTERFACE_UUID;
        let mut nack_reason = RPC_ABSTRACTSYNTAX_UNSUPPORTED;
        if is_interface_uuid {
            nack_reason = RPC_SYNTAX_UNSUPPORTED;
        }

        let mut result = [0u8; CTX_RESULT_SIZE];

        if is_interface_uuid && !is_ndr64_possible && item.transfer_syntax == TRANSFER_SYNTAX_NDR32
        {
            result[0..2].copy_from_slice(&RPC_BIND_ACCEPT.to_le_bytes());
            result[2..4].copy_from_slice(&RPC_BIND_ACCEPT.to_le_bytes());
            result[4..20].copy_from_slice(&TRANSFER_SYNTAX_NDR32);
            result[20..24].copy_from_slice(&2u32.to_le_bytes());
            results.push(result);
            continue;
        }

        if item.transfer_syntax == TRANSFER_SYNTAX_NDR64 {
            if !use_ndr64 {
                nack_reason = RPC_SYNTAX_UNSUPPORTED;
            }
            if is_interface_uuid && is_ndr64_possible {
                result[0..2].copy_from_slice(&RPC_BIND_ACCEPT.to_le_bytes());
                result[2..4].copy_from_slice(&RPC_BIND_ACCEPT.to_le_bytes());
                result[4..20].copy_from_slice(&TRANSFER_SYNTAX_NDR64);
                result[20..24].copy_from_slice(&1u32.to_le_bytes());
                results.push(result);
                continue;
            }
        }

        if item.transfer_syntax[..8] == BIND_TIME_FEATURE_NEGOTIATION[..8] {
            nack_reason = RPC_SYNTAX_UNSUPPORTED;
            if use_btfn {
                let features = u16le(&item.transfer_syntax, 8)
                    & (RPC_BTFN_SEC_CONTEXT_MULTIPLEX | RPC_BTFN_KEEP_ORPHAN);
                result[0..2].copy_from_slice(&RPC_BIND_ACK.to_le_bytes());
                result[2..4].copy_from_slice(&features.to_le_bytes());
                result[20..24].copy_from_slice(&0u32.to_le_bytes());
                results.push(result);
                continue;
            }
        }

        result[0..2].copy_from_slice(&RPC_BIND_NACK.to_le_bytes());
        result[2..4].copy_from_slice(&nack_reason.to_le_bytes());
        result[20..24].copy_from_slice(&0u32.to_le_bytes());
        results.push(result);
    }

    let mut body = Vec::with_capacity(BIND_RESPONSE_FIXED + results.len() * CTX_RESULT_SIZE);
    body.extend_from_slice(&req.max_xmit_frag.to_le_bytes());
    body.extend_from_slice(&req.max_recv_frag.to_le_bytes());
    body.extend_from_slice(&assoc_group.to_le_bytes());

    let addr = if packet_type == PT_ALTERCONTEXT_REQ {
        String::new()
    } else {
        port.to_string()
    };
    body.extend_from_slice(&((addr.len() + 1) as u16).to_le_bytes());
    let mut addr_buf = [0u8; 6];
    addr_buf[..addr.len()].copy_from_slice(addr.as_bytes());
    body.extend_from_slice(&addr_buf);

    body.extend_from_slice(&(results.len() as u32).to_le_bytes());
    for r in &results {
        body.extend_from_slice(r);
    }

    let frag_length = (RPC_HEADER_SIZE + body.len()) as u16;
    let head = RpcHeader::encode(packet_type, PF_FIRST | PF_LAST, header.call_id, frag_length);

    let mut frame = Vec::with_capacity(frag_length as usize);
    frame.extend_from_slice(&head);
    frame.extend_from_slice(&body);

    BindResponse { frame, state }
}

#[derive(Debug)]
pub struct RequestPayload {
    pub context_id: u16,
    pub opnum: u16,
    pub is_ndr64: bool,
    pub data: Vec<u8>,
}

pub fn parse_request(body: &[u8], state: BindState) -> Result<RequestPayload, u32> {
    if body.len() < 8 {
        return Err(RPC_NCA_PROTO_ERROR);
    }
    let context_id = u16le(body, 4);
    let opnum = u16le(body, 6);

    if context_id == state.ndr64_ctx {
        if body.len() < 24 {
            return Err(RPC_NCA_PROTO_ERROR);
        }
        Ok(RequestPayload {
            context_id,
            opnum,
            is_ndr64: true,
            data: body[24..].to_vec(),
        })
    } else if context_id == state.ndr32_ctx {
        if body.len() < 16 {
            return Err(RPC_NCA_PROTO_ERROR);
        }
        Ok(RequestPayload {
            context_id,
            opnum,
            is_ndr64: false,
            data: body[16..].to_vec(),
        })
    } else {
        Err(RPC_NCA_UNK_IF)
    }
}

pub fn build_response(
    header: &RpcHeader,
    context_id: u16,
    is_ndr64: bool,
    kms_response: &[u8],
    status: u32,
) -> Vec<u8> {
    let ndr_size = if is_ndr64 { 24 } else { 12 };
    let prefix = if is_ndr64 { 8usize } else { 4usize };

    let mut body = if status == 0 {
        let mut body = vec![0u8; 8 + ndr_size + kms_response.len()];
        let len64 = kms_response.len() as u64;
        body[8..8 + prefix].copy_from_slice(&len64.to_le_bytes()[..prefix]);

        body[8 + prefix..8 + 2 * prefix]
            .copy_from_slice(&(RPC_DATA_SIZE_MAX as u64).to_le_bytes()[..prefix]);

        body[8 + 2 * prefix..8 + 3 * prefix].copy_from_slice(&len64.to_le_bytes()[..prefix]);
        body[8 + ndr_size..8 + ndr_size + kms_response.len()].copy_from_slice(kms_response);
        body.extend_from_slice(&0u32.to_le_bytes());
        body
    } else {

        let mut body = vec![0u8; 8 + (ndr_size - prefix) + 4];
        let off = 8 + (ndr_size - prefix);
        body[off..off + 4].copy_from_slice(&status.to_le_bytes());
        body
    };

    let pad = (4 - (body.len() % 4)) % 4;
    body.extend(std::iter::repeat_n(0u8, pad));

    let alloc_hint = (body.len() - 8) as u32;
    body[0..4].copy_from_slice(&alloc_hint.to_le_bytes());
    body[4..6].copy_from_slice(&context_id.to_le_bytes());

    let frag_length = (RPC_HEADER_SIZE + body.len()) as u16;
    let head = RpcHeader::encode(PT_RESPONSE, PF_FIRST | PF_LAST, header.call_id, frag_length);

    let mut frame = Vec::with_capacity(frag_length as usize);
    frame.extend_from_slice(&head);
    frame.extend_from_slice(&body);
    frame
}

pub fn build_fault(header: &RpcHeader, nca_error: u32) -> Vec<u8> {

    let frag_length = 32u16;
    let head = RpcHeader::encode(
        PT_FAULT,
        PF_FIRST | PF_LAST | PF_NOT_EXEC,
        header.call_id,
        frag_length,
    );

    let mut frame = Vec::with_capacity(frag_length as usize);
    frame.extend_from_slice(&head);
    frame.extend_from_slice(&nca_error.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&[0u8; 8]);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx_item(context_id: u16, syntax: [u8; 16], syntax_version: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&context_id.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&INTERFACE_UUID);
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&syntax);
        v.extend_from_slice(&syntax_version.to_le_bytes());
        v
    }

    fn make_bind(items: &[([u8; 16], u32)]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xFFFFu16.to_le_bytes());
        v.extend_from_slice(&0xFFFFu16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for (i, (syntax, ver)) in items.iter().enumerate() {
            v.extend_from_slice(&make_ctx_item(i as u16, *syntax, *ver));
        }
        v
    }

    #[test]
    fn bind_with_ndr32_ndr64_btfn_picks_ndr64() {
        let body = make_bind(&[
            (TRANSFER_SYNTAX_NDR32, 2),
            (TRANSFER_SYNTAX_NDR64, 1),
            (BIND_TIME_FEATURE_NEGOTIATION, 1),
        ]);
        let req = parse_bind_request(&body).expect("bind should parse");
        assert_eq!(req.ctx_items.len(), 3);

        let header =
            RpcHeader::parse(&RpcHeader::encode(PT_BIND_REQ, PF_FIRST | PF_LAST, 2, 0)).unwrap();
        let resp = build_bind_response(&header, &req, PT_BIND_ACK, 0x1234, 1688, true, true);

        assert_eq!(resp.state.ndr32_ctx, 0);
        assert_eq!(resp.state.ndr64_ctx, 1);

        let body = &resp.frame[RPC_HEADER_SIZE..];
        assert_eq!(u32le(body, 16), 3);

        let results = &body[BIND_RESPONSE_FIXED..];

        assert_eq!(u16le(results, 0), RPC_BIND_NACK);

        assert_eq!(u16le(results, CTX_RESULT_SIZE), RPC_BIND_ACCEPT);
        assert_eq!(
            &results[CTX_RESULT_SIZE + 4..CTX_RESULT_SIZE + 20],
            &TRANSFER_SYNTAX_NDR64[..]
        );

        assert_eq!(u16le(results, 2 * CTX_RESULT_SIZE), RPC_BIND_ACK);
        assert_eq!(u16le(results, 2 * CTX_RESULT_SIZE + 2), 3);

        assert_eq!(u16le(body, 8), 5);
        assert_eq!(&body[10..15], &b"1688\0"[..]);
    }

    #[test]
    fn bind_request_with_too_many_ctx_items_is_rejected() {
        let mut body = make_bind(&[(TRANSFER_SYNTAX_NDR32, 2)]);
        body[8..12].copy_from_slice(&9u32.to_le_bytes());
        assert!(parse_bind_request(&body).is_none());
    }

    #[test]
    fn bind_request_with_truncated_ctx_item_is_rejected() {
        let mut body = make_bind(&[(TRANSFER_SYNTAX_NDR32, 2)]);
        body.truncate(body.len() - 1);
        assert!(parse_bind_request(&body).is_none());
    }

    #[test]
    fn request_roundtrip_ndr32_and_ndr64() {
        let state = BindState {
            ndr32_ctx: 0,
            ndr64_ctx: 1,
        };

        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&260u32.to_le_bytes());
        body.extend_from_slice(&260u32.to_le_bytes());
        body.extend_from_slice(&[0xAAu8; 260]);
        let p = parse_request(&body, state).unwrap();
        assert!(!p.is_ndr64);
        assert_eq!(p.data.len(), 260);
        assert_eq!(p.opnum, 0);

        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&260u64.to_le_bytes());
        body.extend_from_slice(&260u64.to_le_bytes());
        body.extend_from_slice(&[0xBBu8; 260]);
        let p = parse_request(&body, state).unwrap();
        assert!(p.is_ndr64);
        assert_eq!(p.data.len(), 260);

        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&7u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 32]);
        assert_eq!(parse_request(&body, state).unwrap_err(), RPC_NCA_UNK_IF);
    }

    #[test]
    fn response_frame_layout_ndr32() {
        let header =
            RpcHeader::parse(&RpcHeader::encode(PT_REQUEST, PF_FIRST | PF_LAST, 7, 0)).unwrap();
        let kms = vec![0x5Au8; 100];
        let frame = build_response(&header, 0, false, &kms, 0);

        let h = RpcHeader::parse(&frame).unwrap();
        assert_eq!(h.packet_type, PT_RESPONSE);
        assert_eq!(h.call_id, 7);
        assert_eq!(h.frag_length as usize, frame.len());
        assert_eq!(frame.len() % 4, 0, "response length must be 4-byte aligned");

        let body = &frame[RPC_HEADER_SIZE..];
        assert_eq!(
            u32le(body, 0) as usize,
            body.len() - 8,
            "AllocHint excludes the 8-byte prefix"
        );
        assert_eq!(u16le(body, 4), 0);
        assert_eq!(u32le(body, 8), 100);
        assert_eq!(u32le(body, 12), RPC_DATA_SIZE_MAX);
        assert_eq!(u32le(body, 16), 100);
        assert_eq!(&body[20..20 + 100], &kms[..]);

        assert_eq!(u32le(body, 20 + 100), 0);
    }
}
