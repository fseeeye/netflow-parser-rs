use crate::parsers::*;
use crate::layer_type::LayerType;

#[derive(Debug, PartialEq, Clone)]
pub enum Layer<'a> {
    Eof(EofHeader),
    Ethernet(EthernetHeader),
    Ipv4(Ipv4Header<'a>),
    Ipv6(Ipv6Header<'a>),
    ModbusReq(ModbusReqHeader<'a>),
    ModbusRsp(ModbusRspHeader<'a>),
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader),
    Error(&'a [u8]),
}

#[derive(Debug, PartialEq, Clone)]
pub struct FatLayer<'a> {
    ltype: LayerType,
    nlayer: Layer<'a>,
}

impl<'a> FatLayer<'a> {
    pub fn new(layer_type: LayerType, naive_layer: Layer<'a>) -> Self {
        Self {
            ltype: layer_type,
            nlayer: naive_layer,
        }
    }

    pub fn get_type(&self) -> LayerType {
        return self.ltype
    }

    pub fn get_layer(&self) -> &Layer {
        return &self.nlayer
    }
}

/// LinkLayer是表示link层各类协议信息的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum LinkLayer {
    Ethernet(EthernetHeader),
}

/// NetworkLayer是表示network层各类协议信息的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4Header<'a>),
    Ipv6(Ipv6Header<'a>),
}

/// TransportLayer是表示transport层各类协议新的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader),
}

/// ApplicationLayer是表示application层各类协议新的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum ApplicationLayer<'a> {
    ModbusReq(ModbusReqHeader<'a>),
    ModbusRsp(ModbusRspHeader<'a>),
}
