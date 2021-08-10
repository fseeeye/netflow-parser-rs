# Benchmark Result

## Test Env
* os: darwin
* arch: amd64
* cpu: Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz

## Reproduction
### Parsing-rs & pypkt
```bash
# install libpcap-dev by yourself
brew install libpcap # MacOS
# install pypkt (https://gitee.com/bolean-tech/bolean-pypkt-c/)
git clone https://gitee.com/bolean-tech/bolean-pypkt-c.git
cd bolean-pypkt-c
mkdir build && cd build
cmake ..
make
sudo make install
# install cargo-criterion (https://github.com/bheisler/cargo-criterion)
cargo install cargo-criterion
# download parsing-rs
git clone https://gitee.com/BoleanTech/parsing-rs.git
# into ./benches dir and do benchmarking
cd ./benches
cargo criterion --bench parsing --all-features
```

### gopacket
* `$ git clone https://github.com/google/gopacket.git && cd gopacket/pcap/gopacket_benchmark`
* 修改 benchmark.go 文件 main() 函数下`filename := os.TempDir() + string(os.PathSeparator) + "gopacket_benchmark.pcap"`，变更为`modbus_test.pcap`所在路径
* 修改 benchmark.go 文件 benchmarkLayerDecode() 函数下`var icmp layers.ICMPv4`，变更为`var modbus layers.ModbusTCP`
* 修改 benchmark.go 文件 benchmarkLayerDecode() 函数下`&eth, &ip, &icmp, &tcp, &udp, &payload)`，变更为`&eth, &ip, &modbus, &tcp, &udp, &payload)`
* `$ go run benchmark.go`

## Pcap 10000 (Modbus)
测试用例采用应用层协议以ModbusTcp为主的Pcap进行测试。
* Parsing-rs(QuinPacket): about 2.5 ms (含读取pcap的损耗)
* Parsing-rs(VecPacket): about 6.5 ms (含读取pcap的损耗)
* [gopacket](https://github.com/google/gopacket)(PacketDecode): about 10.2ms (不含读取pcap的损耗)
* [gopacket](https://github.com/google/gopacket)(LayerDecode): about 2.7ms (不含读取pcap的损耗)

## Packet 1 (Modbus)
测试用例采用硬编码u8 slice的Modbus Packet。
* QuinPacket: about 180 ns
* VecPacket: about 640 ns
* [pypkt](https://gitee.com/bolean-tech/bolean-pypkt-c/): about 2.0 µs