

use std::process::ExitCode;

use rs_c4d::kms::Config;
use rs_c4d::transport::{serve, ServerConfig};

const USAGE: &str = "\
rs-c4d —— 最小 KMS 服务端（协议 v4 / v5 / v6）

用法：
  rs-c4d [选项]

选项：
  --listen <addr>          监听地址（默认 0.0.0.0）
  --port <port>            监听端口（默认 1688）
  --pids <n>               同时处理的连接上限（默认 64）
  --verbose                逐请求日志
  --strict-products        未知 KMSID 直接拒绝（默认：回退首条 CSVLK）
  --check-client-time      校验客户端时钟是否在 ±4 小时内（默认关）
  -h, --help               显示本帮助

说明：
  客户端侧需要 GVLK 与 KMS 主机地址；本程序不附带任何产品密钥。
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
                    eprintln!("参数 {} 缺少取值", name);
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
                    eprintln!("--port 需要一个 0-65535 的整数");
                    return ExitCode::FAILURE;
                }
            },
            "--pids" => match next_value("--pids").and_then(|v| v.parse::<usize>().ok()) {
                Some(v) if v > 0 => cfg.max_tasks = v,
                _ => {
                    eprintln!("--pids 需要一个正整数");
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
                eprintln!("未知参数：{}（用 --help 看用法）", other);
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let _ = Config::default();

    match serve(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("启动失败：{}", e);
            ExitCode::FAILURE
        }
    }
}
