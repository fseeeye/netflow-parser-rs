/// Usage: 
/// ```
/// impl<'a> PacketTrait<'a> for xxxPacket<'a> {
///     type Header = xxxHeader<'a>;
///     type Payload = xxxPayload<'a>;
///     type PayloadError = xxxPayloadError;
/// 
///     fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {}
/// 
///     fn parse_payload(input: &'a [u8], _header: &Self::Header) -> nom::IResult<&'a [u8], Self::Payload> {}
/// 
///     fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
///         let (input, header) = Self::parse_header(input)?;
///         let (input, payload) = Self::parse_payload(input, &header)?;
///         Ok((input, Self { header, payload }))
///     }
/// }
/// ```
pub trait PacketTrait<'a>: Sized {
    type Header;
    type Payload;
    type PayloadError;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header>;
    fn parse_payload(input: &'a [u8], header: &Self::Header) -> nom::IResult<&'a [u8], Self::Payload>;
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self>;
}