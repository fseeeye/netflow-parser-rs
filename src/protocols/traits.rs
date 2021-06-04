pub trait PacketTrait<'a>: Sized {
    type Header;
    type Payload;

    fn parse_payload(input: &'a [u8], header: &Self::Header) -> (&'a [u8], Self::Payload);
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self>;
}
