use super::super::modbus;
use super::L3Payload;

#[derive(Debug, PartialEq)]
pub enum Error {
    Modbus,
}

#[derive(Debug, PartialEq)]
pub enum L4Payload<'a> {
    Modbus(modbus::ModbusPacket<'a>),
    Unknown,
    Error(Error),
}
