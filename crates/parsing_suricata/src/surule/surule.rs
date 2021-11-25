//! suricata rule - Surule
use std::str::FromStr;

use nom::IResult;
#[cfg(feature = "serde")]
use serde::{Serialize,Deserialize};

use super::types;
use super::parsers;
use super::utils;
use super::SuruleParseError;


#[cfg_attr(
    feature="serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum SuruleElement {
    // Header Elements:
    Actions(String),
    Protocol(String),
    SrcAddr(String),
    SrcPort(String),
    Direction(types::Direction),
    DstAddr(String),
    DstPort(String),

    // Body (Option) Elements:
    ByteJump(types::ByteJump),
    Classtype(String),
    Content(types::Content),
    Depth(u64),
    Dsize(String),
    Distance(types::Distance),
    EndsWith(bool),
    FastPattern(bool),
    FileData(types::FileData),
    Flow(String),
    Flowbits(types::Flowbits),
    FtpBounce(bool),
    IsDataAt(String),
    Message(String),
    Metadata(String),
    NoAlert(bool),
    NoCase(bool),
    Offset(u64),
    Pcre(String),
    RawBytes(bool),
    Reference(String),
    Rev(u64),
    Sid(u64),
    StartsWith(bool),
    Within(types::Within),   

    // Unknow Element
    GenericOption(types::GenericOption),
}

impl From<&str> for SuruleElement {
    // 不含值的字段，可以通过 &str 直接转换为 SuruleElement
    fn from(name_str: &str) -> Self {
        match name_str {
            "endswith"     => Self::EndsWith(true),
            "fast_pattern" => Self::FastPattern(true),
            "file_data"    => Self::FileData(types::FileData),
            "ftpbounce"    => Self::FtpBounce(true),
            "noalert"      => Self::NoAlert(true),
            "nocase"       => Self::NoCase(true),
            "rawbytes"     => Self::RawBytes(true),
            "startswith"   => Self::StartsWith(true),
            _ => Self::GenericOption(types::GenericOption {
                name: name_str.to_string(),
                val: None,
            }),
        }
    }
}


/// 从字符流中解析出可选字段含值元素的值的字符串
/// 
/// 该函数获得 ':' 后面的所有字符(input)，随后将第一个 ';' 前后的所有字符分为两组返回，
/// 不包含第一个 ';'。
fn parse_option_value(input: &str) -> IResult<&str, &str, SuruleParseError<&str>> {
    let mut escaped_flag = false;
    let mut end = 0;
    let mut terminated = false;

    // 跳过开头的空白字符
    let (input, _) = nom::character::complete::multispace0(input)?;

    // 获得第一个 ';' 的位置
    for (i, c) in input.chars().enumerate() {
        end = i;
        if c == '\\' {
            escaped_flag = true;
        } 
        // 跳过 '\;'
        else if escaped_flag {
            escaped_flag = false;
        } 
        else if c == ';' {
            terminated = true;
            break;
        }
    }

    if !terminated {
        Err(nom::Err::Error(SuruleParseError::UnterminatedRuleOptionValue))
    } else {
        // 不返回 ';'
        Ok((&input[end + 1..], &input[0..end]))
    }
}

// 解析可选字段元素
// fn parse_option_element(input: &str) -> IResult<&str, SuruleElement, SuruleParseError<&str>> {
//     let (input, name_str) = nom::sequence::preceded(
//         nom::character::complete::multispace0, 
//         nom::bytes::complete::is_not(":;")
//     )(input)?;
//     let (input, sep) = nom::character::complete::one_of(":;")(input)?;
//     if sep == ';' { // name_str 是不含值的字段
//         Ok((input, name_str.into()))
//     } else { // name_str 是含值的字段
//         let (input, value_str) = parse_option_value(input)?;
//         let surule_element = match name_str {
//             "byte_jump" => SuruleElement::ByteJump(parsers::parse_byte_jump(value_str)?),
//             "classtype" => SuruleElement::Classtype(value_str.to_owned()),
//             "content" => SuruleElement::Content(types::Content::new(value_str.to_owned())),
//             "depth" => SuruleElement::Depth(parsers::parse_u64(value_str, "depth")?),
//             "distance" => {
//                 SuruleElement::Distance(types::Distance(parsers::parse_count_or_name(value_str)?))
//             }
//             "within" => SuruleElement::Within(types::Within(parsers::parse_count_or_name(value_str)?)),
//             "dsize" => SuruleElement::Dsize(value_str.to_owned()),
//             "flow" => SuruleElement::Flow(value_str.to_owned()),
//             "flowbits" => SuruleElement::Flowbits(parsers::parse_flowbits(value_str)?),
//             "isdataat" => SuruleElement::IsDataAt(value_str.to_owned()),
//             "metadata" => SuruleElement::Metadata(value_str.to_owned()),
//             "msg" => SuruleElement::Message(utils::strip_quotes(value_str)),
//             "offset" => SuruleElement::Offset(parsers::parse_u64(value_str, "offset")?),
//             "pcre" => SuruleElement::Pcre(value_str.to_owned()),
//             "reference" => SuruleElement::Reference(value_str.to_owned()),
//             "rev" => SuruleElement::Rev(parsers::parse_u64(value_str, "rev")?),
//             "sid" => SuruleElement::Sid(parsers::parse_u64(value_str, "sid")?),
//             _ => SuruleElement::GenericOption(GenericOption {
//                 name: name_str.to_string(),
//                 val: Some(value_str.to_string()),
//             }),
//         };
//         Ok((input, surule_element))
//     }
// }