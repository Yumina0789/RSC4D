

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::codec;
use crate::kms::Config;
use crate::rpc;

pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub port: u16,

    pub max_tasks: usize,
    pub verbose: bool,
    pub kms: Config,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_string(),
            port: 1688,
            max_tasks: 64,
            verbose: false,
            kms: Config::default(),
        }
    }
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    fn new(n: usize) -> Self {
        Self {
            permits: Mutex::new(n.max(1)),
            cv: Condvar::new(),
        }
    }

    fn acquire(&self) {
        let mut p = self.permits.lock().unwrap();
        while *p == 0 {
            p = self.cv.wait(p).unwrap();
        }
        *p -= 1;
    }

    fn release(&self) {
        let mut p = self.permits.lock().unwrap();
        *p += 1;
        self.cv.notify_one();
    }
}

pub fn serve(cfg: ServerConfig) -> io::Result<()> {
    let listener = TcpListener::bind((cfg.listen.as_str(), cfg.port))?;
    serve_on(listener, cfg)
}

pub fn serve_on(listener: TcpListener, cfg: ServerConfig) -> io::Result<()> {
    let local = listener.local_addr()?;
    eprintln!(
        "rsc4d listening on {} (concurrency limit {}, strict product mode {}, client time check {})",
        local, cfg.max_tasks, cfg.kms.strict_products, cfg.kms.check_client_time
    );

    let assoc_group = u32::from_le_bytes(crate::crypto::random16()[0..4].try_into().unwrap());
    let sem = Arc::new(Semaphore::new(cfg.max_tasks));

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept failed: {}", e);
                continue;
            }
        };

        let cfg = cfg.clone();
        let sem = Arc::clone(&sem);
        sem.acquire();
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, &cfg, assoc_group) {
                if cfg.verbose {
                    eprintln!("connection finished ({})", e);
                }
            }
            sem.release();
        });
    }

    Ok(())
}

pub fn handle_connection(
    mut stream: TcpStream,
    cfg: &ServerConfig,
    assoc_group: u32,
) -> io::Result<()> {
    stream.set_read_timeout(Some(DEFAULT_READ_TIMEOUT))?;
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());

    let mut bind_state = rpc::BindState::default();

    loop {
        let Some((header, body)) = rpc::read_frame(&mut stream)? else {
            return Ok(());
        };

        match header.packet_type {
            rpc::PT_BIND_REQ | rpc::PT_ALTERCONTEXT_REQ => {
                if header.validate(header.packet_type).is_err() {
                    return Ok(());
                }
                let Some(req) = rpc::parse_bind_request(&body) else {

                    return Ok(());
                };

                let ack_type = if header.packet_type == rpc::PT_BIND_REQ {
                    rpc::PT_BIND_ACK
                } else {
                    rpc::PT_ALTERCONTEXT_ACK
                };
                let resp = rpc::build_bind_response(
                    &header,
                    &req,
                    ack_type,
                    assoc_group,
                    cfg.port,
                    true,
                    true,
                );
                if cfg.verbose {
                    eprintln!(
                        "[{}] {} {} (NDR32 ctx={} / NDR64 ctx={})",
                        peer,
                        if ack_type == rpc::PT_BIND_ACK {
                            "bind"
                        } else {
                            "alter-context"
                        },
                        if resp.state.ndr64_ctx != rpc::RPC_INVALID_CTX {
                            "accepting NDR64"
                        } else {
                            "accepting NDR32"
                        },
                        resp.state.ndr32_ctx,
                        resp.state.ndr64_ctx
                    );
                }
                bind_state = resp.state;
                stream.write_all(&resp.frame)?;
            }

            rpc::PT_REQUEST => {
                let payload = match rpc::parse_request(&body, bind_state) {
                    Ok(p) => p,
                    Err(nca) => {
                        stream.write_all(&rpc::build_fault(&header, nca))?;
                        continue;
                    }
                };

                let now = unix_now();
                let built = codec::build_response(&payload.data, &cfg.kms, now);

                let frame = match &built {
                    Ok(kms_response) => rpc::build_response(
                        &header,
                        payload.context_id,
                        payload.is_ndr64,
                        kms_response,
                        0,
                    ),
                    Err(hresult) => rpc::build_response(
                        &header,
                        payload.context_id,
                        payload.is_ndr64,
                        &[],
                        *hresult,
                    ),
                };

                if cfg.verbose {
                    match &built {
                        Ok(kms_response) => log_request(
                            &peer,
                            codec::inspect_request(&payload.data, &cfg.kms, now),
                            kms_response.len(),
                        ),
                        Err(hresult) => eprintln!(
                            "[{}] KMS request rejected: HRESULT 0x{:08X} ({} bytes)",
                            peer,
                            hresult,
                            payload.data.len()
                        ),
                    }
                }

                stream.write_all(&frame)?;
            }

            _ => return Ok(()),
        }
    }
}

fn log_request(peer: &str, info: Option<codec::RequestInfo>, response_len: usize) {
    match info {
        Some(i) => eprintln!(
            "[{}] KMS {} KMSID={:02x?} CMID={:02x?} Count={} product={} → response {} bytes",
            peer,
            match i.version {
                codec::ProtocolVersion::V4 => "v4",
                codec::ProtocolVersion::V5 => "v5",
                codec::ProtocolVersion::V6 => "v6",
            },
            i.kms_id,
            i.cmid,
            i.count,
            i.product.unwrap_or("(no match, falling back to the first CSVLK)"),
            response_len
        ),
        None => eprintln!("[{}] KMS request could not be parsed → response {} bytes", peer, response_len),
    }
}
