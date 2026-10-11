

use std::process::ExitCode;

use rsc4d::kms::Config;
use rsc4d::transport::{serve, ServerConfig};

const USAGE: &str = "\
rsc4d — minimal KMS server (protocol v4 / v5 / v6)

Usage:
  rsc4d [options]

Options:
  --listen <addr>
  --port <port>
  --pids <n>
  --verbose
  --strict-products
  --check-client-time
  -h, --help

";

fn main() -> ExitCode {
    let mut cfg = ServerConfig::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;

    while i < args.len() {
        let arg = args[i].as_str();
        let mut next_value = |name: &str| -> Option<String> {
            i += 1;
            match args.get(i) {
                Some(v) => Some(v.clone()),
                None => {
                    eprintln!("missing value for argument {}", name);
                    None
                }
            }
        };

        match arg {
            "--listen" => match next_value("--listen") {
                Some(v) => cfg.listen = v,
                None => return ExitCode::FAILURE,
            },
            "--port" => match next_value("--port").and_then(|v| v.parse::<u16>().ok()) {
                Some(v) => cfg.port = v,
                None => {
                    eprintln!("--port requires an integer in 0-65535");
                    return ExitCode::FAILURE;
                }
            },
            "--pids" => match next_value("--pids").and_then(|v| v.parse::<usize>().ok()) {
                Some(v) if v > 0 => cfg.max_tasks = v,
                _ => {
                    eprintln!("--pids requires a positive integer");
                    return ExitCode::FAILURE;
                }
            },
            "--verbose" => cfg.verbose = true,
            "--strict-products" => cfg.kms.strict_products = true,
            "--check-client-time" => cfg.kms.check_client_time = true,
            "-h" | "--help" => {
                print!("{}", USAGE);
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {} (use --help for usage)", other);
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let _ = Config::default();

    match serve(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("startup failed: {}", e);
            ExitCode::FAILURE
        }
    }
}
