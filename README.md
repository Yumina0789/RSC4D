# RSC4D

用 Rust 写的**最小服务端**：实现一套 wire 格式（协议 **v4 / v5 / v6**），只走
`RequestActivation` 一条链路。一个静态二进制，无运行时依赖。

> ⚠️ **仅供学习与协议研究。** 本项目与任何厂商无隶属关系；作者不参与部署，也不对使用后果负责。

## 构建与测试

```sh
cargo test
cargo build --release -p rs-c4d
```

## 验收

- 46 项测试全绿（录制报文重放、真 TCP 端到端、并发不串包）；`cargo fmt --all --check`、
  `cargo clippy --workspace --all-targets -D warnings` 干净。
- 静态 musl 产物无动态解释器；已在真实客户端上完成一次端到端验证。

## 许可

GPL-3.0-or-later，见 [`LICENSE`](LICENSE)。
