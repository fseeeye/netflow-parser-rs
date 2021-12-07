//! Body Option Element 的解析函数，用于将字符串解析成 Option Element
use anyhow::Result;
use ipnet::Ipv4Net;

use std::net::Ipv4Addr;
use std::str::FromStr;

use super::types::{FlowbitCommand, IpAddress, Port};
use super::util_parsers::{handle_value, take_until_whitespace};
use super::{ByteJump, CountOrName, Endian, Flow, FlowMatcher, Flowbits};
use crate::surule::SuruleParseError;

/// 解析数字 u64
#[inline(always)]
pub(crate) fn parse_u64(input: &str) -> Result<u64, nom::Err<SuruleParseError>> {
    let u64_str = handle_value(input)?;

    u64_str
        .parse::<u64>()
        .map_err(|_| SuruleParseError::IntegerParseError(input.to_string()).into())
}

/// 由字符串解析 IpAddress
impl FromStr for IpAddress {
    // Use nom::Err to satisfy ? in parser.
    type Err = nom::Err<SuruleParseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let make_err = |reason| SuruleParseError::InvalidIpAddr(reason).into();

        let ip_addr_str = handle_value(s).map_err(|_| make_err("empty value.".to_string()))?;

        match ip_addr_str.parse::<Ipv4Addr>() {
            Ok(single_addr) => Ok(IpAddress::V4Addr(single_addr)),
            Err(_) => {
                // maybe it's a range
                let single_range = ip_addr_str
                    .parse::<Ipv4Net>()
                    .map_err(|_| make_err(ip_addr_str.to_string()))?;
                Ok(IpAddress::V4Range(single_range))
            }
        }
    }
}

/// 由字符串解析 Port
impl FromStr for Port {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let make_err = || SuruleParseError::InvalidPort(s.to_string()).into();

        if let Some((min_str, max_str)) = s.split_once(':') {
            // range
            let min = min_str.parse().map_err(|_| make_err())?;
            let max = max_str
                .trim()
                .parse()
                .or_else(|e| {
                    if max_str.trim().is_empty() {
                        return Ok(u16::MAX);
                    } else {
                        return Err(e);
                    }
                })
                .map_err(|_| make_err())?;
            Ok(Self::new_range(min, max).map_err(|e| e.into())?)
        } else {
            // single
            Ok(Self::Single(s.parse().map_err(|_| make_err())?))
        }
    }
}

/// 由字符串解析 FlowbitCommand
impl FromStr for FlowbitCommand {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "noalert" => Ok(Self::NoAlert),
            "set" => Ok(Self::Set),
            "isset" => Ok(Self::IsSet),
            "toggle" => Ok(Self::Toggle),
            "unset" => Ok(Self::Unset),
            "isnotset" => Ok(Self::IsNotSet),
            _ => Err(nom::Err::Error(SuruleParseError::Flowbit(format!(
                "unknown command: {}",
                s
            )))),
        }
    }
}

/// 由字符串解析 Flow
impl FromStr for Flow {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let values = s.split(",");
        let mut flow_commands = vec![];
        for value in values {
            flow_commands.push(FlowMatcher::from_str(value.trim())?);
        }
        Ok(Flow(flow_commands))
    }
}

impl FromStr for FlowMatcher {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "to_client" => Self::ToClient,
            "to_server" => Self::ToServer,
            "from_client" => Self::FromClient,
            "from_server" => Self::FromServer,
            "established" => Self::Established,
            "not_established" => Self::NotEstablished,
            "stateless" => Self::Stateless,
            "only_stream" => Self::OnlyStream,
            "no_stream" => Self::NoStream,
            "only_frag" => Self::OnlyFrag,
            "no_frag" => Self::NoFrag,
            _ => {
                return Err(nom::Err::Error(SuruleParseError::UnknownFlowOption(
                    s.to_string(),
                )));
            }
        };
        Ok(v)
    }
}

/// 由字符串解析 Flowbits
impl FromStr for Flowbits {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // 内部工具函数：创建解析错误
        let make_err = |reason| SuruleParseError::Flowbit(reason).into();

        let input = handle_value(input)?;

        let command_parser = nom::sequence::preceded(
            nom::character::complete::multispace0,
            nom::character::complete::alphanumeric1,
        );
        let name_parser = nom::sequence::preceded(
            nom::bytes::complete::tag(","),
            nom::sequence::preceded(nom::character::complete::multispace0, nom::combinator::rest),
        );

        let (_, (command, names)) =
            nom::sequence::tuple((command_parser, nom::combinator::opt(name_parser)))(input)?;
        let command = FlowbitCommand::from_str(command)?;

        match command {
            FlowbitCommand::IsNotSet
            | FlowbitCommand::Unset
            | FlowbitCommand::Toggle
            | FlowbitCommand::IsSet
            | FlowbitCommand::Set => {
                let names = names
                    .ok_or_else(|| make_err(format!("{} requires argument", command)))?
                    .split('|')
                    .map(|s| s.trim().to_string())
                    .collect();
                Ok(Flowbits { command, names })
            }
            FlowbitCommand::NoAlert => {
                if names.is_some() {
                    Err(make_err("noalert don't need any arguments".to_string()))
                } else {
                    Ok(Flowbits {
                        command,
                        names: vec![],
                    })
                }
            }
        }
    }
}

/// 由字符串解析 ByteJump
impl FromStr for ByteJump {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // 内部工具函数：创建解析错误
        let make_err = |reason| SuruleParseError::InvalidByteJump(reason).into();

        let input = handle_value(input)?;
        // step1: 逗号分割字符串
        let (_, values) = nom::multi::separated_list1::<_, _, _, nom::error::Error<&str>, _, _>(
            nom::bytes::complete::tag(","),
            nom::sequence::preceded(
                nom::character::complete::multispace0,
                nom::bytes::complete::is_not(","),
            ),
        )(input)
        .map_err(|_| make_err(format!("invalid input: {}", input)))?;
        if values.len() < 2 {
            return Err(make_err("no enough arguments".into()));
        }

        // step2: 从 Vec 中依次解析 ByteJump 各字段
        let mut byte_jump = ByteJump {
            count: values[0]
                .trim()
                .parse()
                // wrap nom error
                .map_err(|_| make_err(format!("invalid count: {}", values[0])))?,
            offset: values[1]
                .trim()
                .parse()
                .map_err(|_| make_err(format!("invalid offset: {}", values[1])))?,
            ..Default::default()
        };

        // 解析可选字段
        for value in values[2..].iter() {
            let (value, name) = take_until_whitespace(value)
                .map_err(|_| make_err(format!("invalid value: {}", value)))?;
            match name {
                "relative" => byte_jump.relative = true,
                "little" => {
                    byte_jump.endian = Endian::Little;
                }
                "big" => {
                    byte_jump.endian = Endian::Big;
                }
                "align" => {
                    byte_jump.align = true;
                }
                "from_beginning" => {
                    byte_jump.from_beginning = true;
                }
                "from_end" => {
                    byte_jump.from_end = true;
                }
                "dce" => {
                    byte_jump.dce = true;
                }
                "string" => {
                    byte_jump.string = true;
                }
                "hex" => {
                    byte_jump.hex = true;
                }
                "dec" => {
                    byte_jump.dec = true;
                }
                "oct" => {
                    byte_jump.oct = true;
                }
                "multiplier" => {
                    byte_jump.multiplier = value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| make_err(format!("invalid multiplier: \"{}\"", value)))?;
                }
                "post_offset" => {
                    byte_jump.post_offset = value
                        .trim()
                        .parse::<i64>()
                        .map_err(|_| make_err(format!("invalid post_offset: \"{}\"", value)))?;
                }
                "bitmask" => {
                    let value = value.trim();
                    let trimmed = if value.starts_with("0x") || value.starts_with("0X") {
                        &value[2..]
                    } else {
                        value
                    };
                    let value = u64::from_str_radix(trimmed, 16)
                        .map_err(|_| make_err(format!("invalid bitmask: \"{}\"", value)))?;
                    byte_jump.bitmask = value;
                }
                _ => {
                    return Err(make_err(format!("unknown parameter: \"{}\"", name)));
                }
            }
        }

        Ok(byte_jump)
    }
}

/// 由字符串解析 CountOrName
impl FromStr for CountOrName {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = handle_value(input)?;
        // 如果 input 没能解析成功为 CountOrName::Value(i64)，那么就作为 CountOrName::Var(String)
        if let Ok(distance) = input.parse::<i64>() {
            Ok(CountOrName::Value(distance))
        } else {
            Ok(CountOrName::Var(input.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_str() {
        assert_eq!(parse_u64(" 12\r\n").unwrap(), 12u64);
        assert_eq!(
            parse_u64(" string12 \r\n").unwrap_err(),
            nom::Err::Error(SuruleParseError::IntegerParseError(
                " string12 \r\n".to_string()
            ))
        )
    }

    #[test]
    fn test_parse_flow() {
        assert_eq!(
            Flow::from_str("to_client,to_server, from_client , from_server, established, not_established, stateless, only_stream, no_stream, only_frag, no_frag").unwrap(),
            Flow(vec![
                FlowMatcher::ToClient,
                FlowMatcher::ToServer,
                FlowMatcher::FromClient,
                FlowMatcher::FromServer,
                FlowMatcher::Established,
                FlowMatcher::NotEstablished,
                FlowMatcher::Stateless,
                FlowMatcher::OnlyStream,
                FlowMatcher::NoStream,
                FlowMatcher::OnlyFrag,
                FlowMatcher::NoFrag
            ])
        );

        assert_eq!(
            Flow::from_str("foo, foo2"),
            Err(SuruleParseError::UnknownFlowOption("foo".to_string()).into())
        )
    }

    #[test]
    fn test_parse_flowbits() {
        assert_eq!(
            Flowbits::from_str("set,foo.bar"),
            Ok(Flowbits {
                command: FlowbitCommand::Set,
                names: vec!["foo.bar".into()]
            })
        );
        let _flowbits: Flowbits = "set,foo | bar".parse().unwrap();
        let _flowbits: Flowbits = "noalert".parse().unwrap();
    }

    #[test]
    fn test_byte_jump() {
        // Ok
        assert_eq!(
            "4,12".parse(),
            Ok(ByteJump {
                count: 4,
                offset: 12,
                ..Default::default()
            })
        );
        assert_eq!(
            "4,12,,".parse(),
            Ok(ByteJump {
                count: 4,
                offset: 12,
                ..Default::default()
            })
        );
        // Err
        assert_eq!(
            ByteJump::from_str(""),
            Err(SuruleParseError::EmptyStr.into())
        );
        assert_eq!(
            ByteJump::from_str("4"),
            Err(SuruleParseError::InvalidByteJump("no enough arguments".into()).into())
        );
        assert_eq!(
            ByteJump::from_str("4,12,multiplier"),
            Err(SuruleParseError::InvalidByteJump("invalid multiplier: \"\"".into()).into())
        );
    }

    #[test]
    fn test_count_or_name() {
        // Ok
        assert_eq!("123".parse(), Ok(CountOrName::Value(123)));
        assert_eq!("foo".parse(), Ok(CountOrName::Var("foo".into())));
        assert_eq!(" 1aa\r\n".parse(), Ok(CountOrName::Var("1aa".into())));
        // Err
        assert_eq!(
            CountOrName::from_str(""),
            Err(SuruleParseError::EmptyStr.into())
        );
    }
}
