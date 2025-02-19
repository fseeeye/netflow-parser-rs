# How to Contribute?

## git commit
* git commit请遵守Angular风格！
* 为规范提交和节省编写时间，推荐使用[commitizen  -  npm](https://www.npmjs.com/package/commitizen)工具，以`git cz`替换`git commit`。具体安装说明请参考官方文档。

## git branch
* 实现新功能、新协议时，请从合适的分支处新建分支，完成后及时提交PR合并。

## code
* 变量、函数、方法请采用下划线命名法。
* trait、struct、enum请采用帕斯卡(大驼峰)命名法。
* 协议名的命名方式请保持一致，如：`ModbusReq` <-> `modbus_req`

## Rust
* 项目使用了Rust部分最新特性，请切换Rust版本为Nightly进行开发。

## Usage
```bash
# 测试
cargo run --example parsing_pcap
cargo run --example parsing_rules
# 生成静态库和c语言头文件
cargo build
```