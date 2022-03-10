use parsing_parser::{L5Packet, ApplicationLayer, parsers::dnp3};
use serde::{Serialize, Deserialize};

use crate::{detect::IcsRuleDetector, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Dnp3Arg {
    src: Option<u16>,
    dst: Option<u16>,
    link_function_code: Option<u8>,
    #[serde(flatten)]
    app_layer: Dnp3AppLayer
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum Dnp3AppLayer {
    #[serde(rename = "0", alias = "0x00")]
    Confirm {},
    #[serde(rename = "1", alias = "0x01")]
    Read {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "2", alias = "0x02")]
    Write {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "3", alias = "0x03")]
    Select {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "14", alias = "0x0d")]
    ColdRestart {},
    #[serde(rename = "15", alias = "0x0e")]
    WarmRestart {},
    #[serde(rename = "18", alias = "0x12")]
    StopApplication {},
    #[serde(rename = "20", alias = "0x14")]
    EnableSpontaneousMessage {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "21", alias = "0x15")]
    DisableSpontaneousMessage {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "25", alias = "0x19")]
    OpenFile {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "129", alias = "0x81")]
    Response {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    },
    #[serde(rename = "130", alias = "0x82")]
    UnsolicitedResponse {
        objs: Option<u16>,
        vsq: Option<u8>,
        start: Option<u8>,
        stop: Option<u8>
    }
}

impl IcsRuleDetector for Dnp3Arg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Dnp3(dnp3) = &l5.application_layer {
            detect_option_eq!(self.src, dnp3.data_link_layer.source);

            detect_option_eq!(self.dst, dnp3.data_link_layer.destination);

            detect_option_eq!(self.link_function_code, dnp3.data_link_layer.dl_function);

            // TODO: detect objects
            match self.app_layer {
                Dnp3AppLayer::Confirm {} => if let dnp3::Dnp3ApplicationData::Confirm {} = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::Read {
                   ..
                } => if let dnp3::Dnp3ApplicationData::Read { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::Write {
                    ..
                } => if let dnp3::Dnp3ApplicationData::Write { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::Select {
                    ..
                } => if let dnp3::Dnp3ApplicationData::Select { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::ColdRestart {} => if let dnp3::Dnp3ApplicationData::ColdRestart {} = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::WarmRestart {} => if let dnp3::Dnp3ApplicationData::WarmRestart {} = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::StopApplication {} => if let dnp3::Dnp3ApplicationData::StopApplication {} = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::EnableSpontaneousMessage {
                    ..
                } => if let dnp3::Dnp3ApplicationData::EnableSpontaneousMessage { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::DisableSpontaneousMessage {
                    ..
                } => if let dnp3::Dnp3ApplicationData::DisableSpontaneousMessage { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::OpenFile {
                    ..
                } => if let dnp3::Dnp3ApplicationData::OpenFile { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::Response {
                    ..
                } => if let dnp3::Dnp3ApplicationData::Response { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                },
                Dnp3AppLayer::UnsolicitedResponse {
                    ..
                } => if let dnp3::Dnp3ApplicationData::UnsolicitedResponse { .. } = dnp3.application_layer.app_data {

                } else {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{IcsRule, IcsRuleBasis, icsrule::basis::{Action, Direction}, icsrule_arg::IcsRuleArg, HmIcsRules};

    use super::*;

    #[test]
    fn serialize_dnp3_icsrule() {
        let dnp3_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: Action::Alert,
                src_ip: None,
                src_port: None,
                dir: Direction::Uni,
                dst_ip: None,
                dst_port: Some(20000),
                msg: "DNP3 Read".to_string(),
            },
            args: IcsRuleArg::DNP3(
                Dnp3Arg {
                    src: Some(1),
                    dst: Some(2),
                    link_function_code: Some(1),
                    app_layer: Dnp3AppLayer::Read {
                        objs: Some(0x1001),
                        vsq: Some(1),
                        start: Some(0),
                        stop: Some(9)
                    }
                }
            )
        };

        assert_eq!( 
            serde_json::to_string(&dnp3_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":20000,"msg":"DNP3 Read","proname":"DNP3","args":{"src":1,"dst":2,"link_function_code":1,"function_code":"1","objs":4097,"vsq":1,"start":0,"stop":9}}"#
        )
    }

    #[test]
    fn deserialize_dnp3_icsrule() {
        let mut dnp3_rule = HmIcsRules::new();
        
        let file_str = "./tests/unitest_dnp3.json";
        assert!(dnp3_rule.load_rules(file_str));
    }
}
