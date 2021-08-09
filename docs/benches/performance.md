# Benchmark Result

## Env
* os: darwin
* arch: amd64
* cpu: Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz

## Pcap 1000 (Modbus)
* QuinPacket: about 250 us
* VecPacket: about 650 us
* [gopacket](https://github.com/google/gopacket): about 1660 us

## Packet 1 (Modbus)
* QuinPacket: about 180 ns
* VecPacket: about 640 ns
* [gopacket](https://github.com/google/gopacket): about 980 ns