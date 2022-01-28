use crate::{QuinPacket, QuinPacketOptions, ProtocolType, ApplicationProtocol, LinkLayer, NetworkLayer, TransportLayer, L4Packet, ParseError, ApplicationLayer, L5Packet};

use super::parse_l5_eof_layer;


#[derive(Debug, PartialEq, Clone, Copy)]
pub struct HttpHeader {
    
}

pub fn parse_http_header(input: &[u8]) -> nom::IResult<&[u8], HttpHeader> {
    let mut headers = [httparse::EMPTY_HEADER; 16];

    let (_, rsp_opt) = nom::combinator::opt(nom::bytes::complete::tag(b"HTTP/"))(input)?;
    if rsp_opt.is_none() {
        let mut req = httparse::Request::new(&mut headers);
        if let Ok(status) = req.parse(input) {
            match status {
                httparse::Status::Complete(offset) => {
                    let content = &input[offset..];
                    
                },
                httparse::Status::Partial => {
                    // http isn't complete
                    // TODO: http flow
                }
            }
            let method = req.method;
            let path = req.path;
            let version = req.version;
        } else {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        
    } else {
        let mut rsp = httparse::Response::new(&mut headers);
        if let Ok(status) = rsp.parse(input) {
            match status {
                httparse::Status::Complete(offset) => {
                    let content = &input[offset..];
                },
                httparse::Status::Partial => {
                    // http isn't complete
                    // TODO: http flow
                }
            }
            let version = rsp.version;
            let code = rsp.code;
            let reason = rsp.reason;
        } else {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
    }

    Ok((
        input,
        HttpHeader {
            
        },
    ))
}

pub fn parse_http_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Application(ApplicationProtocol::Http);

    let (input, http_header) = match parse_http_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L4(L4Packet {
                link_layer,
                network_layer,
                transport_layer,
                error: Some(ParseError::ParsingHeader),
                remain: input,
            })
        }
    };

    if Some(current_prototype) == options.stop {
        let application_layer = ApplicationLayer::Http(http_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    }

    let application_layer = ApplicationLayer::Http(http_header);
    return parse_l5_eof_layer(
        input,
        link_layer,
        network_layer,
        transport_layer,
        application_layer,
        options,
    );
}