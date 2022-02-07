use crate::{QuinPacket, QuinPacketOptions, ProtocolType, ApplicationProtocol, LinkLayer, NetworkLayer, TransportLayer, L4Packet, ParseError, ApplicationLayer, L5Packet};
use super::parse_l5_eof_layer;


#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HttpHeader<'a> {
    Request {
        method: &'a str,
        path: &'a str,
        version: u8,
        headers: [httparse::Header<'a>; 16],
        content: &'a [u8]
    },
    Response {
        version: u8,
        code: u16,
        reason: &'a str,
        headers: [httparse::Header<'a>; 16],
        content: &'a [u8]
    }
}

pub fn parse_http_header(input: &[u8]) -> nom::IResult<&[u8], HttpHeader> {
    let verify_error = Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Verify,
    )));

    let mut headers = [httparse::EMPTY_HEADER; 16];

    let (_, rsp_opt) = nom::combinator::opt(nom::bytes::complete::tag(b"HTTP/"))(input)?;
    if rsp_opt.is_none() { // HTTP Request
        let method;
        let path;
        let version;
        let content;

        let mut req = httparse::Request::new(&mut headers);
        if let Ok(status) = req.parse(input) {
            match status {
                httparse::Status::Complete(offset) => {
                    content = &input[offset..];
                },
                httparse::Status::Partial => {
                    // http isn't complete
                    // TODO: http flow
                    tracing::debug!(target: "PARSER(http::parse_http_header)", "don't support partial yet.");
                    return verify_error;
                }
            }

            if let Some(m) = req.method {
                method = m;
            } else {
                tracing::debug!(target: "PARSER(http::parse_http_header)", "request method error.");
                return verify_error;
            }

            if let Some(p) = req.path {
                path = p;
            } else {
                tracing::debug!(target: "PARSER(http::parse_http_header)", "request path error.");
                return verify_error;
            }

            if let Some(v) = req.version {
                version = v;
            } else {
                tracing::debug!(target: "PARSER(http::parse_http_header)", "request version error.");
                return verify_error;
            }

            tracing::debug!("{:?}", HttpHeader::Request {
                method,
                path,
                version,
                headers,
                content
            });

            Ok((
                input,
                HttpHeader::Request {
                    method,
                    path,
                    version,
                    headers,
                    content
                },
            ))
        } else {
            tracing::debug!(target: "PARSER(http::parse_http_header)", "request version error.");
            return verify_error;
        }
    } else { // HTTP Response
        let version;
        let code;
        let reason;
        let content;

        let mut rsp = httparse::Response::new(&mut headers);
        if let Ok(status) = rsp.parse(input) {
            match status {
                httparse::Status::Complete(offset) => {
                    content = &input[offset..];
                },
                httparse::Status::Partial => {
                    // http isn't complete
                    // TODO: http flow
                    tracing::debug!(target: "PARSER(http::parse_http_header)", "don't support partial yet.");
                    return verify_error;
                }
            }
            if let Some(v) = rsp.version {
                version = v;
            } else {
                tracing::debug!(target: "PARSER(http::parse_http_header)", "response version error.");
                return verify_error;
            }

            if let Some(c) = rsp.code {
                code = c;
            } else {
                tracing::debug!(target: "PARSER(http::parse_http_header)", "response code error.");
                return verify_error;
            }

            if let Some(r) = rsp.reason {
                reason = r;
            } else {
                tracing::debug!(target: "PARSER(http::parse_http_header)", "response reason error.");
                return verify_error;
            }

            tracing::debug!("{:?}", HttpHeader::Response {
                version,
                code,
                reason,
                headers,
                content
            });

            Ok((
                input,
                HttpHeader::Response {
                    version,
                    code,
                    reason,
                    headers,
                    content
                },
            ))
        } else {
            tracing::debug!(target: "PARSER(http::parse_http_header)", "response parse error.");
            return verify_error;
        }
    }
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
        Err(e) => {
            tracing::error!(
                target: "PARSER(http::parse_http_layer)",
                error = ?e
            );
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