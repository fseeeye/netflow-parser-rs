use nom::error::ErrorKind;
use nom::Err;

fn main() {
    use nom::number::complete::be_u16;

    let parser = |s| be_u16(s);

    assert_eq!(parser(&b"\x00\x00"[..]), Ok((&b""[..], 0x0000)));
    assert_eq!(
        parser(&b"\x01"[..]),
        Err(Err::Error((&[0x01][..], ErrorKind::Eof)))
    );

    use nom::number::complete::be_u8;

    let parser = |s| be_u8(s);

    assert_eq!(
        parser(&b"\x40\x03abcefg"[..]),
        Ok((&b"\x03abcefg"[..], 0x40))
    );
    assert_eq!(parser(&b""[..]), Err(Err::Error((&[][..], ErrorKind::Eof))));
}
