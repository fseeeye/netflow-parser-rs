# Parsing-RS

## Project Structure
* [parsing_parser](crates/parsing_parser/) : 协议解析核心代码
* [parsing_rule](crates/parsing_rule/) : 规则解析与检测的基础 crate
* [parsing_icsrule](crates/parsing_icsrule/) : 工控规则解析与检测
* [parsing_suricata](crates/parsing_suricata/) : Suricata 黑名单规则解析与检测
* [adapter_clang](crates/adapter_clang/) : FFI (Rust -> C)

## Getting Started
* 依照官方文档安装 Rust，并切换至 nightly 分支。
* 运行测试：`cargo test --workspace`
* 运行示例程序：`cargo run --example parsing_pcap -- -p ../pcap/ICS/iec61850/sv.pcap ../pcap/ICS/iec61850/goose.pcap` , 可在其中修改代码测试某 pcap 的协议解析和规则匹配正确性。

## Documents
* [FFI 编写文档](docs/FFI/usage.md)
* [Benchmark 文档](docs/benches/performance.md)
* [项目接口文档](docs/project-doc/parser_rs/index.html)
