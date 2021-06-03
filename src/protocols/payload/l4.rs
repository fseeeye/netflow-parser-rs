use super::super::modbus;

#[derive(Debug, PartialEq)]
pub enum L4Payload<'a> {
    Modbus(modbus::ModbusPacket<'a>),
    Unknown(&'a [u8]),
}
