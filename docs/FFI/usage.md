# FFI 使用说明

## Call Parsing-RS from C
本章适用于从C语言项目调用本协议解析引擎FFI接口。
对C语言的FFI适配部分集成于 adapter_clang crate 中，具体使用方法如下：
1. `$ cargo install --force cbindgen`
2. `$ cd /path/to/parsing-rs/crates/adapter_clang` : 进入适配器目录。
3. `$ cargo build --release` : 编译适配器，在`/root-of-project/target/release/`目录生成 .a 和 .so文件，可以按需取用。
4. `$ cbindgen --config cbindgen.toml --crate adapter_clang --output output/parsing_rs.h` : 会在`./output`目录生成 .h 头文件。
5. 至此，获得了 system library 和 C header file，将它们移动至合适路径即可。比如 Unix 系统下可执行：
    * `sudo cp ~/parsing-rs/target/release/libparser_rs.so /usr/local/lib/`
    * `cp ~/parsing-rs/crates/adapter_clang/output/parser_rs.h ~/firewall-core/vpp-plugins/utils/`