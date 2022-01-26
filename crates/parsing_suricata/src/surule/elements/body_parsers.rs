//! Body Option Element 的解析函数，用于将字符串解析成 Option Element
use anyhow::Result;
use bytes::BufMut;
use ipnet::Ipv4Net;

use std::net::Ipv4Addr;
use std::ops::BitXorAssign;
use std::str::FromStr;

use super::types::*;
use super::util_parsers::{handle_value, take_until_whitespace};
use crate::surule::SuruleParseError;

#[inline(always)]
fn parse_num<T>(input: &str) -> Result<T, nom::Err<SuruleParseError>>
where
    T: FromStr,
{
    let clean_input = handle_value(input)?;

    clean_input
        .parse::<T>()
        .map_err(|_| SuruleParseError::IntegerParseError(input.to_string()).into())
}

/// 解析数字 u64
#[inline(always)]
pub(crate) fn parse_u64(input: &str) -> Result<u64, nom::Err<SuruleParseError>> {
    parse_num::<u64>(input)
}

/// 解析数字 usize
#[inline(always)]
pub(crate) fn parse_usize(input: &str) -> Result<usize, nom::Err<SuruleParseError>> {
    parse_num::<usize>(input)
}

/// 解析数字 isize
#[inline(always)]
pub(crate) fn parse_isize(input: &str) -> Result<isize, nom::Err<SuruleParseError>> {
    parse_num::<isize>(input)
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

/// 由字符串解析 Metadata
pub(crate) fn parse_metadata(input: &str) -> Result<Vec<String>, nom::Err<SuruleParseError>> {
    let metadata = input.split(",").map(|p| p.trim().to_string()).collect();

    Ok(metadata)
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
        // ref: https://stackoverflow.com/questions/26368288/how-do-i-stop-iteration-and-return-an-error-when-iteratormap-returns-a-result
        let flow_commands: Result<Vec<_>, _> = s
            .split(",")
            .map(|p| FlowMatcher::from_str(p.trim()))
            .collect();

        Ok(Flow(flow_commands?))
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

/// 由字符串解析 Content 的 pattern 部分
impl FromStr for Content {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = handle_value(input)?;

        let mut hex_flag = false;
        let mut buf: Vec<u8> = vec![];

        for sub_str in input.split('|') {
            if !hex_flag {
                buf.put(sub_str.as_bytes())
            } else {
                let clear_hex: String = sub_str.chars().filter(|c| !c.is_whitespace()).collect();
                buf.put(
                    hex::decode(clear_hex)
                        .map_err(|_| {
                            SuruleParseError::OddContentPatternHex(input.to_string()).into()
                        })?
                        .as_ref(),
                )
            }

            hex_flag.bitxor_assign(true);
        }

        Ok(Content {
            pattern: buf,
            ..Default::default()
        })
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
        let (_, values): (_, Vec<&str>) =
            nom::multi::separated_list1::<_, _, _, nom::error::Error<&str>, _, _>(
                nom::bytes::complete::tag(","),
                nom::sequence::preceded(
                    nom::character::complete::multispace0,
                    nom::bytes::complete::is_not(","),
                ),
            )(input)
            .map_err(|_| make_err(format!("invalid input: {}", input)))?;

        // step2: 从 Vec 中依次解析 ByteJump 各必选字段
        let count = values
            .get(0)
            .ok_or(make_err("no required arg: `num of bytes`".to_string()))?
            .trim()
            .parse()
            // wrap nom error
            .map_err(|_| make_err(format!("invalid count: {}", values[0])))?;
        if count > 8 {
            // u64 can't store bytes len bigger than 8
            return Err(make_err(format!("invalid count(too big): {}", values[0])));
        }
        let offset = values
            .get(1)
            .ok_or(make_err("no required arg: `offset`".to_string()))?
            .parse()
            .map_err(|_| make_err(format!("invalid offset: {}", values[1])))?;
        let mut byte_jump = ByteJump {
            count,
            offset,
            ..Default::default()
        };

        // step3: 解析可选字段
        let option_values = values.get(2..).unwrap_or(&[]);
        let mut prev_is_string = false;
        for value in option_values {
            let (value, name) = take_until_whitespace(value.trim())
                .map_err(|_| make_err(format!("invalid value: {}", value)))?;
            match name {
                "relative" => {
                    if byte_jump.relative == true {
                        return Err(make_err("duplicated relative".to_string()));
                    }

                    byte_jump.relative = true;
                    prev_is_string = false;
                }
                "little" => {
                    if byte_jump.endian.is_some() {
                        return Err(make_err("duplicated endian".to_string()));
                    }

                    byte_jump.endian = Some(Endian::Little);
                    prev_is_string = false;
                }
                "big" => {
                    if byte_jump.endian.is_some() {
                        return Err(make_err("duplicated endian".to_string()));
                    }

                    byte_jump.endian = Some(Endian::Big);
                    prev_is_string = false;
                }
                "align" => {
                    if byte_jump.align == true {
                        return Err(make_err("duplicated align".to_string()));
                    }

                    byte_jump.align = true;
                    prev_is_string = false;
                }
                "from_beginning" => {
                    if byte_jump.from.is_some() {
                        return Err(make_err(
                            "duplicated from_beginning or from_end".to_string(),
                        ));
                    }

                    byte_jump.from = Some(ByteJumpFrom::BEGIN);
                    prev_is_string = false;
                }
                "from_end" => {
                    if byte_jump.from.is_some() {
                        return Err(make_err(
                            "duplicated from_beginning or from_end".to_string(),
                        ));
                    }

                    byte_jump.from = Some(ByteJumpFrom::END);
                    prev_is_string = false;
                }
                "dce" => {
                    if byte_jump.dce == true {
                        return Err(make_err("duplicated dce".to_string()));
                    }

                    byte_jump.dce = true;
                    prev_is_string = false;
                }
                "string" => {
                    if byte_jump.string == true {
                        return Err(make_err("duplicated string".to_string()));
                    }

                    byte_jump.string = true;
                    prev_is_string = true;
                }
                "hex" => {
                    if !prev_is_string {
                        return Err(make_err("`hex` is not after `string`".to_string()));
                    }
                    if byte_jump.num_type.is_some() {
                        return Err(make_err("duplicated num type".to_string()));
                    }

                    byte_jump.num_type = Some(NumType::HEX);
                }
                "dec" => {
                    if !prev_is_string {
                        return Err(make_err("`dec` is not after `string`".to_string()));
                    }
                    if byte_jump.num_type.is_some() {
                        return Err(make_err("duplicated num type".to_string()));
                    }

                    byte_jump.num_type = Some(NumType::DEC);
                }
                "oct" => {
                    if !prev_is_string {
                        return Err(make_err("`oct` is not after `string`".to_string()));
                    }
                    if byte_jump.num_type.is_some() {
                        return Err(make_err("duplicated num type".to_string()));
                    }

                    byte_jump.num_type = Some(NumType::OCT);
                }
                "multiplier" => {
                    if byte_jump.multiplier.is_some() {
                        return Err(make_err("duplicated multiplier".to_string()));
                    }

                    byte_jump.multiplier = Some(
                        value
                            .trim()
                            .parse::<usize>()
                            .map_err(|_| make_err(format!("invalid multiplier: \"{}\"", value)))?,
                    );
                    prev_is_string = false;
                }
                "post_offset" => {
                    if byte_jump.post_offset.is_some() {
                        return Err(make_err("duplicated post offset".to_string()));
                    }

                    byte_jump.post_offset =
                        Some(value.trim().parse::<isize>().map_err(|_| {
                            make_err(format!("invalid post_offset: \"{}\"", value))
                        })?);
                    prev_is_string = false;
                }
                "bitmask" => {
                    if byte_jump.bitmask.is_some() {
                        return Err(make_err("duplicated bitmask".to_string()));
                    }

                    let value = value.trim();
                    let trimmed = if value.starts_with("0x") || value.starts_with("0X") {
                        &value[2..]
                    } else {
                        value
                    };
                    let value = usize::from_str_radix(trimmed, 16)
                        .map_err(|_| make_err(format!("invalid bitmask: \"{}\"", value)))?;
                    byte_jump.bitmask = Some(value);
                    prev_is_string = false;
                }
                _ => {
                    return Err(make_err(format!("unknown parameter: \"{}\"", name)));
                }
            }
        }

        Ok(byte_jump)
    }
}

/// 由字符串解析 ByteTest
impl FromStr for ByteTest {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // 内部工具函数：创建解析错误
        let make_err = |reason| SuruleParseError::InvalidByteTest(reason).into();

        let input = handle_value(input)?;

        // step1: 逗号分割字符串
        let (_, values): (_, Vec<&str>) =
            nom::multi::separated_list1::<_, _, _, nom::error::Error<&str>, _, _>(
                nom::bytes::complete::tag(","),
                nom::sequence::preceded(
                    nom::character::complete::multispace0,
                    nom::bytes::complete::is_not(","),
                ),
            )(input)
            .map_err(|_| make_err(format!("invalid input: {}", input)))?;

        // step2: 从 Vec 中依次解析 ByteTest 各必选字段
        // num of bytes
        let count = values
            .get(0)
            .ok_or(make_err("no required arg: `num of bytes`".to_string()))?
            .trim()
            .parse()
            .map_err(|_| make_err(format!("invalid count: {}", values[0])))?;
        if count > 8 {
            // u64 can't store bytes len bigger than 8
            return Err(make_err(format!("invalid count(too big): {}", values[0])));
        }
        // operator & its negation
        let operator;
        let mut op_nagation = false;
        let operator_str = values
            .get(1)
            .ok_or(make_err("no required arg: `operator`".to_string()))?
            .trim();
        if operator_str.starts_with('!') {
            operator = operator_str
                .trim_start_matches('!')
                .parse()
                .map_err(|_| make_err(format!("invalid count: {}", values[0])))?;
            op_nagation = true;
        } else {
            operator = operator_str
                .parse()
                .map_err(|_| make_err(format!("invalid count: {}", values[0])))?;
        }
        // test value
        let test_value_str = values
            .get(2)
            .ok_or(make_err("no required arg: `operator`".to_string()))?
            .trim();
        let test_value = if test_value_str.starts_with("0x") {
            u64::from_str_radix(test_value_str.trim_start_matches("0x"), 16)
                .map_err(|_| make_err(format!("invalid value(hex): {}", test_value_str)))?
        } else {
            u64::from_str(test_value_str)
                .map_err(|_| make_err(format!("invalid value(dec): {}", test_value_str)))?
        };
        // offset
        let offset = values
            .get(3)
            .ok_or(make_err("no required arg: `offset`".to_string()))?
            .trim()
            .parse()
            .map_err(|_| make_err(format!("invalid offset: {}", values[1])))?;

        let mut byte_test = ByteTest {
            count,
            op_nagation,
            operator,
            test_value,
            offset,
            ..Default::default()
        };

        // step3: 解析可选字段
        let option_values = values.get(4..).unwrap_or(&[]);
        let mut prev_is_string = false;
        for option_value in option_values {
            let (value_str, name) = take_until_whitespace(option_value.trim())
                .map_err(|_| make_err(format!("invalid value: {}", option_value)))?;
            let value_str = value_str.trim();
            match name {
                "relative" => {
                    if byte_test.relative == true {
                        return Err(make_err("duplicated relative".to_string()));
                    }

                    byte_test.relative = true;
                    prev_is_string = false;
                }
                "little" => {
                    if byte_test.endian.is_some() {
                        return Err(make_err("duplicated endian".to_string()));
                    }

                    byte_test.endian = Some(Endian::Little);
                    prev_is_string = false;
                }
                "big" => {
                    if byte_test.endian.is_some() {
                        return Err(make_err("duplicated endian".to_string()));
                    }

                    byte_test.endian = Some(Endian::Big);
                    prev_is_string = false;
                }
                "string" => {
                    if byte_test.string == true {
                        return Err(make_err("duplicated string".to_string()));
                    }

                    byte_test.string = true;
                    prev_is_string = true;
                }
                "hex" => {
                    if prev_is_string == false {
                        return Err(make_err("`hex` is not after `string`".to_string()));
                    }
                    if byte_test.num_type.is_some() {
                        return Err(make_err("duplicated num type".to_string()));
                    }

                    byte_test.num_type = Some(NumType::HEX);
                }
                "dec" => {
                    if !prev_is_string {
                        return Err(make_err("`dec` is not after `string`".to_string()));
                    }
                    if byte_test.num_type.is_some() {
                        return Err(make_err("duplicated num type".to_string()));
                    }

                    byte_test.num_type = Some(NumType::DEC);
                }
                "oct" => {
                    if !prev_is_string {
                        return Err(make_err("`oct` is not after `string`".to_string()));
                    }
                    if byte_test.num_type.is_some() {
                        return Err(make_err("duplicated num type".to_string()));
                    }

                    byte_test.num_type = Some(NumType::OCT);
                }
                "dce" => {
                    if byte_test.dce == true {
                        return Err(make_err("duplicated dce".to_string()));
                    }

                    byte_test.dce = true;
                    prev_is_string = false;
                }
                "bitmask" => {
                    if byte_test.bitmask.is_some() {
                        return Err(make_err("duplicated bitmask".to_string()));
                    }

                    let bitmask_value = if value_str.starts_with("0x") {
                        u64::from_str_radix(value_str.trim_start_matches("0x"), 16)
                            .map_err(|_| make_err(format!("invalid hex value: {}", value_str)))?
                    } else {
                        u64::from_str(value_str)
                            .map_err(|_| make_err(format!("invalid dec value: {}", value_str)))?
                    };
                    byte_test.bitmask = Some(bitmask_value);
                    prev_is_string = false;
                }
                _ => return Err(make_err(format!("unknown parameter: \"{}\"", name))),
            }
        }

        Ok(byte_test)
    }
}

// 由字符串解析 ByteTestOperator
impl FromStr for ByteTestOp {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = handle_value(input)?;

        let op = match input {
            "<" => ByteTestOp::Less,
            ">" => ByteTestOp::Greater,
            "=" => ByteTestOp::Equal,
            "<=" => ByteTestOp::LessEqual,
            ">=" => ByteTestOp::GreaterEquanl,
            "&" => ByteTestOp::And,
            "^" => ByteTestOp::Or,
            _ => {
                return Err(SuruleParseError::InvalidByteTest(format!(
                    "invalid bytejump operator `{}`",
                    input
                ))
                .into())
            }
        };

        Ok(op)
    }
}

/// 由字符串解析 Dsize
impl FromStr for IsDataAt {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(raw_input: &str) -> Result<Self, Self::Err> {
        let make_err = |reason| SuruleParseError::InvalidIsDataAt(reason).into();
        let input = handle_value(raw_input)?;

        // negate
        let (input, negate_op) = nom::combinator::opt(nom::bytes::complete::tag("!"))(input)?;
        let negate = negate_op.is_some();
        // pos
        let (input, pos_str) = nom::character::complete::digit1::<_, nom::error::Error<&str>>(input.trim_start())
            .map_err(|_| make_err(format!("no position number: {}", raw_input)))?;
        let pos = usize::from_str(pos_str)
            .map_err(|_| make_err(format!("error position number str: {}", pos_str)))?;
        // relative (optional)
        let (input, relative_op) = nom::combinator::opt(
            nom::sequence::preceded(
                nom::bytes::complete::tag(","),
                nom::sequence::preceded(
                    nom::character::complete::multispace0, 
                    nom::combinator::rest
                ),
            )
        )(input.trim_start())?;

        if let Some(relative_str) = relative_op {
            if relative_str.trim() == "relative" {
                Ok(IsDataAt {
                    pos,
                    negate,
                    relative: true
                })
            } else {
                Err(make_err(format!("unknow optional modifier: {}", relative_str)))
            }
        } else {
            let (_input, _eof) = nom::combinator::eof::<_, nom::error::Error<&str>>(input)
                .map_err(|_| make_err(format!("unterminated: {}", raw_input)))?;

            Ok(IsDataAt {
                pos,
                negate,
                relative: false
            })
        }
    }
}

/// 由字符串解析 Dsize
impl FromStr for Dsize {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(raw_input: &str) -> Result<Self, Self::Err> {
        let make_err = |reason| SuruleParseError::InvalidDsize(reason).into();

        let input = handle_value(raw_input)?;

        if let Ok((input, op_string)) = nom::branch::alt::<_, _, SuruleParseError, _>((
            nom::bytes::complete::tag("!"),
            nom::branch::alt((
                nom::bytes::complete::tag(">"),
                nom::bytes::complete::tag("<"),
            )),
        ))(input)
        {
            // parse operator "!number" / ">number" / "<number"
            let (_, size_num_string) =
                nom::sequence::terminated::<_, _, _, nom::error::Error<&str>, _, _>(
                    nom::character::complete::digit1,
                    nom::combinator::eof,
                )(input)
                .map_err(|_| make_err(format!("invalid size num string: \"{input}\"")))?;
            let size_num = usize::from_str(size_num_string).map_err(|_| {
                make_err(format!(
                    "can't convert size string to num: \"{size_num_string}\""
                ))
            })?;
            match op_string {
                "!" => Ok(Dsize::NotEqual(size_num)),
                ">" => Ok(Dsize::Greater(size_num)),
                "<" => Ok(Dsize::Less(size_num)),
                _ => Err(make_err(format!(
                    "unknow nom rst (please contact developer): {raw_input}"
                ))),
            }
        } else {
            // parse "number" / "number1<>number2"
            let (input, size_num_string) =
                nom::character::complete::digit1::<_, nom::error::Error<&str>>(input)
                    .map_err(|_| make_err(format!("invalid size num string: \"{input}\"")))?;
            let size_num = usize::from_str(size_num_string).map_err(|_| {
                make_err(format!(
                    "can't convert size string to num: \"{size_num_string}\""
                ))
            })?;

            if nom::combinator::eof::<_, nom::error::Error<&str>>(input).is_ok() {
                Ok(Dsize::Equal(size_num))
            } else {
                if let Ok((input, Some(_))) = nom::combinator::opt::<_, _, nom::error::Error<&str>, _>(
                    nom::bytes::complete::tag("<>"),
                )(input)
                {
                    let (_, size_num_string_max) =
                        nom::sequence::terminated::<_, _, _, nom::error::Error<&str>, _, _>(
                            nom::character::complete::digit1,
                            nom::combinator::eof,
                        )(input)
                        .map_err(|_| make_err(format!("invalid size num string2: \"{input}\"")))?;
                    let size_num_max = usize::from_str(size_num_string_max).map_err(|_| {
                        make_err(format!(
                            "can't convert size string2 to num: \"{size_num_string_max}\""
                        ))
                    })?;

                    if size_num >= (size_num_max - 1) {
                        return Err(make_err(format!(
                            "min({size_num}) must less than max({size_num_max})-1"
                        )));
                    }

                    Ok(Dsize::Range(size_num, size_num_max))
                } else {
                    Err(make_err(format!("not terminated: {raw_input}")))
                }
            }
        }
    }
}

/// 由字符串解析 Pcre
impl FromStr for Pcre {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(raw_input: &str) -> Result<Self, Self::Err> {
        let make_err = |reason| SuruleParseError::InvalidPcre(reason).into();
        let input = handle_value(raw_input)?;

        // parsing nagate pattern
        let (input, negate) = nom::combinator::opt(nom::bytes::complete::tag("!"))(input)?;
        let (input, _open_quote) = nom::bytes::complete::tag("\"")(input)?;
        let (input, _open_pcre_flag) = nom::bytes::complete::tag("/")(input)?;
        let pattern_end = input
            .rfind('/')
            .ok_or_else(|| make_err("no terminating pcre flag `/`".to_string()))?;
        let pattern = input[0..pattern_end].trim();
        let input = input[pattern_end..].trim_start();
        let (input, _close_pcre_flag) = nom::bytes::complete::tag("/")(input)?;

        // parsing modifiers when it exist
        let mut pcre = Pcre {
            negate: negate.is_some(),
            pattern: pattern.to_string(),
            ..Default::default()
        };
        if let Ok((_, _)) =
            nom::bytes::complete::tag::<_, _, SuruleParseError>("\"")(input.trim_start())
        {
            return Ok(pcre);
        };
        let (input, modifiers) = nom::character::complete::alphanumeric1(input)?;
        
        let mut _pcre_builder = pcre2::bytes::RegexBuilder::new();
        _pcre_builder.jit(true);
        for c in modifiers.chars() {
            match c {
                'i' => {
                    pcre.modifier_i = true;
                    _pcre_builder.caseless(true);
                },
                'm' => {
                    pcre.modifier_m = true;
                    _pcre_builder.multi_line(true);
                },
                's' => {
                    pcre.modifier_s = true;
                    _pcre_builder.dotall(true);
                },
                'x' => {
                    pcre.modifier_x = true;
                    _pcre_builder.extended(true);
                },
                'u' => {
                    pcre.modifier_u = true;
                    _pcre_builder.utf(true);
                },
                _ => {
                    tracing::debug!(target: "Suricata(Pcre::from_str)", "unknow modifier `{}`", c);
                }
            }
        }
        _pcre_builder.build("foo")
            .map_err(|_| make_err(format!("regex build failed: {:?}", _pcre_builder)))?; // try build pcre regex

        let (_input, _close_quote) =
            nom::bytes::complete::tag::<_, _, SuruleParseError>("\"")(input)
                .map_err(|_| make_err("no terminating quote `\"`".to_string()))?;

        Ok(pcre)
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

/// 由字符串解析 Xbits
impl FromStr for XBits {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parse_comma = nom::sequence::preceded(
            nom::character::complete::multispace0,
            nom::bytes::complete::tag(","),
        );
        // 内部工具函数：创建解析错误
        let make_err = |reason| SuruleParseError::InvalidByteJump(reason).into();

        // parse command
        let input = handle_value(input)?;
        let (input, command_str) = nom::character::complete::alphanumeric1(input)?;
        let command = XbitCommand::from_str(command_str)?;

        let (input, _) = parse_comma(input)?;

        // parse name
        let input = handle_value(input)?;
        let (input, name) = nom::bytes::complete::is_not(",")(input)?;

        let (input, _) = parse_comma(input)?;

        // parse track
        let input = handle_value(input)?;
        let (input, (_track_tag, _comma, track)) = nom::sequence::tuple((
            nom::bytes::complete::tag("track"),
            nom::character::complete::multispace0,
            nom::bytes::complete::is_not(","),
        ))(input)?;

        // parse expire
        let parse_expire_empty = nom::combinator::eof;
        let parse_expire_exist = |input| {
            let (input, (_comma, _expire_tag, expire_str)) = nom::sequence::tuple((
                nom::sequence::preceded(
                    nom::character::complete::multispace0,
                    nom::bytes::complete::tag(","),
                ),
                nom::sequence::preceded(
                    nom::character::complete::multispace0,
                    nom::bytes::complete::tag("expire"),
                ),
                nom::sequence::preceded(
                    nom::character::complete::multispace0,
                    nom::character::complete::alphanumeric1,
                ),
            ))(input)?;
            Ok((input, expire_str))
        };

        let (_input, expire_str) =
            nom::branch::alt((parse_expire_empty, parse_expire_exist))(input)?;
        let expire = if expire_str.is_empty() {
            None
        } else {
            let expire: u64 = expire_str.parse().map_err(|_| {
                make_err(format!("can't convert expire str to u64: {}", expire_str))
            })?;
            Some(expire)
        };

        Ok(XBits {
            command,
            name: name.trim().to_string(),
            track: track.trim().to_string(),
            expire,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_usize() {
        assert_eq!(parse_usize(" 12\r\n").unwrap(), 12usize);
        assert_eq!(
            parse_usize(" string12 \r\n").unwrap_err(),
            nom::Err::Error(SuruleParseError::IntegerParseError(
                " string12 \r\n".to_string()
            ))
        )
    }

    #[test]
    fn test_parse_isize() {
        assert_eq!(parse_isize(" -12\r\n").unwrap(), -12isize);
        assert_eq!(
            parse_usize(" string-12 \r\n").unwrap_err(),
            nom::Err::Error(SuruleParseError::IntegerParseError(
                " string-12 \r\n".to_string()
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
    fn test_metadata() {
        assert_eq!(
            parse_metadata("first str"),
            Ok(vec!["first str".to_string()])
        );

        assert_eq!(
            parse_metadata(" first str , second str "),
            Ok(vec!["first str".to_string(), "second str".to_string()])
        );
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
        assert_eq!(
            "4, 12, relative, multiplier 2, big, string, dec, align, from_beginning, post_offset -8, bitmask 1".parse(),
            Ok(ByteJump {
                count: 4,
                offset: 12,
                relative: true,
                multiplier: Some(2),
                endian: Some(Endian::Big),
                string: true,
                num_type: Some(NumType::DEC),
                align: true,
                from: Some(ByteJumpFrom::BEGIN),
                post_offset: Some(-8),
                bitmask: Some(1),
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
            Err(SuruleParseError::InvalidByteJump("no required arg: `offset`".into()).into())
        );
        assert_eq!(
            ByteJump::from_str("4,12,multiplier"),
            Err(SuruleParseError::InvalidByteJump("invalid multiplier: \"\"".into()).into())
        );
    }

    #[test]
    fn test_bytetest() {
        // OK
        assert_eq!(
            " 1, !& ,128,6 ".parse(),
            Ok(ByteTest {
                count: 1,
                op_nagation: true,
                operator: ByteTestOp::And,
                test_value: 128,
                offset: 6,
                ..Default::default()
            })
        );

        assert_eq!(
            " 1,!&,0x10,6, relative, little, string, hex, dce, bitmask 128 ".parse(),
            Ok(ByteTest {
                count: 1,
                op_nagation: true,
                operator: ByteTestOp::And,
                test_value: 16,
                offset: 6,
                relative: true,
                endian: Some(Endian::Little),
                string: true,
                num_type: Some(NumType::HEX),
                dce: true,
                bitmask: Some(128)
            })
        );

        // Err
        assert_eq!(
            ByteTest::from_str(""),
            Err(SuruleParseError::EmptyStr.into())
        );
        assert_eq!(
            ByteTest::from_str("1,!&,128,6,hex,string"),
            Err(
                SuruleParseError::InvalidByteTest("`hex` is not after `string`".to_string()).into()
            )
        );
        assert_eq!(
            ByteTest::from_str("1,!&,128,6,foo"),
            Err(SuruleParseError::InvalidByteTest("unknown parameter: \"foo\"".to_string()).into())
        );
    }

    #[test]
    fn test_isdataat() {
        assert_eq!(
            "10".parse(),
            Ok(IsDataAt {
                pos: 10,
                ..Default::default()
            })
        );

        assert_eq!(
            "10, relative".parse(),
            Ok(IsDataAt {
                pos: 10,
                relative: true,
                ..Default::default()
            })
        );

        assert_eq!(
            "!10".parse(),
            Ok(IsDataAt {
                pos: 10,
                negate: true,
                ..Default::default()
            })
        );

        assert_eq!(
            " !10 , relative ".parse(),
            Ok(IsDataAt {
                pos: 10,
                negate: true,
                relative: true
            })
        );
    }

    #[test]
    fn test_dsize() {
        assert_eq!("!123".parse(), Ok(Dsize::NotEqual(123)));

        assert_eq!("123".parse(), Ok(Dsize::Equal(123)));

        assert_eq!(">123".parse(), Ok(Dsize::Greater(123)));

        assert_eq!("<123".parse(), Ok(Dsize::Less(123)));

        assert_eq!("123<>1234".parse(), Ok(Dsize::Range(123, 1234)));
    }

    #[test]
    fn test_pcre() {
        assert_eq!(
            r#""/[0-9a-zA-Z]/""#.parse(),
            Ok(Pcre {
                negate: false,
                pattern: r"[0-9a-zA-Z]".to_string(),
                ..Default::default()
            })
        );

        assert_eq!(
            r#"!"/\/winhost(?:32|64)\.(exe|pack)$/i""#.parse(),
            Ok(Pcre {
                negate: true,
                pattern: r"\/winhost(?:32|64)\.(exe|pack)$".to_string(),
                modifier_i: true,
                ..Default::default()
            })
        );

        assert_eq!(
            r#""/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*BD9E5104-2F20/si""#.parse(),
            Ok(Pcre {
                negate: false,
                pattern: r"<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*BD9E5104-2F20".to_string(),
                modifier_i: true,
                modifier_s: true,
                ..Default::default()
            })
        );

        // unsupport modifiers will be ignore
        assert_eq!(
            r#""/lingua\\x3d.+?(SELECT|UPDATE|DELETE).+?FROM/Pi""#.parse(),
            Ok(Pcre {
                negate: false,
                pattern: r"lingua\\x3d.+?(SELECT|UPDATE|DELETE).+?FROM".to_string(),
                modifier_i: true,
                ..Default::default()
            })
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

    #[test]
    fn test_xbits() {
        // Ok: no expire
        assert_eq!(
            "isset, badssh, track ip_src".parse(),
            Ok(XBits {
                command: XbitCommand::IsSet,
                name: "badssh".to_string(),
                track: "ip_src".to_string(),
                expire: None
            })
        );

        // Ok: with expire
        assert_eq!(
            "set,ET.dropsite, track ip_src  ,expire 5000  ".parse(),
            Ok(XBits {
                command: XbitCommand::Set,
                name: "ET.dropsite".to_string(),
                track: "ip_src".to_string(),
                expire: Some(5000)
            })
        );

        // Err
        assert!(XBits::from_str("isset, badssh, track ip_src,").is_err());
        assert!(XBits::from_str("isset, badssh, track ip_src, xxx").is_err());
        assert!(XBits::from_str("isset, badssh, track ,expire 5000").is_err());
    }
}
