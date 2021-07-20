use crate::types::LayerType;

/// Package Trait Usage:
/// ```
/// impl<'a> Packet<'a> for xxxPacket<'a> {
///     type Header = xxxHeader<'a>;
///     type Payload = xxxPayload<'a>;
///     
///     fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
///         let (input, header) = Self::Header::parse(input)?;
///         let (input, payload) = Self::Payload::parse(input, &header)?;
///         Ok((input, Self { header, payload }))
///     }
/// }
/// ```
pub trait PacketTrait<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> where Self: Sized;
}

/// Header Trait Usage:
/// ```
/// impl<'a> Header<'a> for xxxHeader<'a> {
///     fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
///         // ...
///     }
/// }
/// ```
pub trait HeaderTrait<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> where Self: Sized;
    fn get_type(&self) -> LayerType;
}

/// Payload Trait Usage:
/// ```
/// impl<'a> Payload<'a> for xxxPayload<'a> {
///     type Header = xxxHeader<'a>;
///     type PayloadError = xxxPayloadError<'a>;
/// 
///     fn parse(
///         input: &'a [u8],
///         _header: &Self::Header,
///     ) -> nom::IResult<&'a [u8], Self> {
///         // ...
///     }
/// }
/// ```
pub trait PayloadTrait<'a>
{
    // "associated type defaults are unstable": https://github.com/rust-lang/rust/issues/29661
    type Header;

    fn parse(
        input: &'a [u8],
        header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self>
    where
        Self: Sized;
}