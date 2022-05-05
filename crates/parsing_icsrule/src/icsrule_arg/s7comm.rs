use parsing_parser::{
    parsers::s7comm::{self, SyntaxIdEnum},
    ApplicationLayer, L5Packet,
};
use serde::{Deserialize, Serialize};

use crate::{
    detect::IcsRuleDetector, detect_address, detect_option_eq, detect_utils::bytes_to_u32,
};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "rosctr")]
pub enum S7CommArg {
    #[serde(rename = "1", alias = "0x01")]
    Job {
        #[serde(flatten)]
        param: S7JobParm,
    },
    #[serde(rename = "2", alias = "0x02")]
    Ack {},
    #[serde(rename = "3", alias = "0x03")]
    AckData {
        #[serde(flatten)]
        param: S7AckDataParm,
    },
    #[serde(rename = "7", alias = "0x07")]
    Userdata { subfunction: Option<u8> },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum S7JobParm {
    #[serde(rename = "240", alias = "0xf0", alias = "0xF0")]
    SetupCommunication {},
    #[serde(rename = "4", alias = "0x04")]
    ReadVar {
        area: Option<u8>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "5", alias = "0x05")]
    WriteVar {
        area: Option<u8>,
        start_address: Option<u32>,
        end_address: Option<u32>,
        min_value: Option<u32>,
        max_value: Option<u32>,
    },
    #[serde(rename = "26", alias = "0x1a", alias = "0x1A")]
    RequestDownload {},
    #[serde(rename = "27", alias = "0x1b", alias = "0x1B")]
    DownloadBlock {},
    #[serde(rename = "28", alias = "0x1c", alias = "0x1C")]
    DownloadEnded {},
    #[serde(rename = "29", alias = "0x1d", alias = "0x1D")]
    StartUpload {},
    #[serde(rename = "30", alias = "0x1e", alias = "0x1E")]
    Upload {},
    #[serde(rename = "31", alias = "0x1f", alias = "0x1F")]
    EndUpload {},
    #[serde(rename = "40", alias = "0x28")]
    PiService {},
    #[serde(rename = "41", alias = "0x29", alias = "0x29")]
    PlcStop {},
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum S7AckDataParm {
    #[serde(rename = "240", alias = "0xf0", alias = "0xF0")]
    SetupCommunication {},
    #[serde(rename = "4", alias = "0x04")]
    ReadVar {
        min_value: Option<u32>,
        max_value: Option<u32>,
    },
    #[serde(rename = "5", alias = "0x05")]
    WriteVar {},
    #[serde(rename = "26", alias = "0x1a", alias = "0x1A")]
    RequestDownload {},
    #[serde(rename = "27", alias = "0x1b", alias = "0x1B")]
    DownloadBlock {},
    #[serde(rename = "28", alias = "0x1c", alias = "0x1C")]
    DownloadEnded {},
    #[serde(rename = "29", alias = "0x1d", alias = "0x1D")]
    StartUpload {},
    #[serde(rename = "30", alias = "0x1e", alias = "0x1E")]
    Upload {},
    #[serde(rename = "31", alias = "0x1f", alias = "0x1F")]
    EndUpload {},
    #[serde(rename = "40", alias = "0x28")]
    PiService {},
    #[serde(rename = "41", alias = "0x29", alias = "0x29")]
    PlcStop {},
}

impl IcsRuleDetector for S7CommArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::S7comm(s7) = &l5.application_layer {
            match self {
                Self::Job { param } => match param {
                    S7JobParm::SetupCommunication {} => {}
                    S7JobParm::ReadVar {
                        area,
                        start_address,
                        end_address,
                    } => {
                        if let s7comm::Parameter::Job {
                            job_param: s7comm::JobParam::ReadVar { items, .. },
                            ..
                        } = &s7.parameter
                        {
                            for item in items {
                                if let s7comm::ParamItem {
                                    syntax_id_enum:
                                        SyntaxIdEnum::S7any {
                                            item_area,
                                            item_address,
                                            ..
                                        },
                                    ..
                                } = item
                                {
                                    detect_option_eq!(area, item_area);
                                    detect_address!(start_address, end_address, item_address);
                                } else {
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    S7JobParm::WriteVar {
                        area,
                        start_address,
                        end_address,
                        min_value,
                        max_value,
                    } => {
                        if let s7comm::Parameter::Job {
                            job_param:
                                s7comm::JobParam::WriteVar {
                                    items,
                                    standard_items,
                                    ..
                                },
                            ..
                        } = &s7.parameter
                        {
                            for item in items {
                                if let s7comm::ParamItem {
                                    syntax_id_enum:
                                        SyntaxIdEnum::S7any {
                                            item_area,
                                            item_address,
                                            ..
                                        },
                                    ..
                                } = item
                                {
                                    detect_option_eq!(area, item_area);
                                    detect_address!(start_address, end_address, item_address);
                                } else {
                                    return false;
                                }
                            }

                            for standard_item in standard_items {
                                if standard_item.data.len() <= 4 {
                                    if let Some(ref value) = bytes_to_u32(standard_item.data) {
                                        detect_address!(min_value, max_value, value);
                                    } else {
                                        return false;
                                    }
                                } else {
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    S7JobParm::RequestDownload {} => {}
                    S7JobParm::DownloadBlock {} => {}
                    S7JobParm::DownloadEnded {} => {}
                    S7JobParm::StartUpload {} => {}
                    S7JobParm::Upload {} => {}
                    S7JobParm::EndUpload {} => {}
                    S7JobParm::PiService {} => {}
                    S7JobParm::PlcStop {} => {}
                },
                Self::Ack {} => {
                    if let s7comm::Parameter::Ack {} = &s7.parameter {
                        // pass
                    } else {
                        return false;
                    }
                }
                Self::AckData { param } => match param {
                    S7AckDataParm::SetupCommunication {} => {}
                    S7AckDataParm::ReadVar {
                        min_value,
                        max_value,
                    } => {
                        if let s7comm::Parameter::AckData {
                            ackdata_param: s7comm::AckdataParam::ReadVar { standard_items, .. },
                            ..
                        } = &s7.parameter
                        {
                            for standard_item in standard_items {
                                if standard_item.data.len() <= 4 {
                                    if let Some(ref value) = bytes_to_u32(standard_item.data) {
                                        detect_address!(min_value, max_value, value);
                                    } else {
                                        return false;
                                    }
                                } else {
                                    return false;
                                }
                            }
                        }
                    }
                    S7AckDataParm::WriteVar {} => {}
                    S7AckDataParm::RequestDownload {} => {}
                    S7AckDataParm::DownloadBlock {} => {}
                    S7AckDataParm::DownloadEnded {} => {}
                    S7AckDataParm::StartUpload {} => {}
                    S7AckDataParm::Upload {} => {}
                    S7AckDataParm::EndUpload {} => {}
                    S7AckDataParm::PiService {} => {}
                    S7AckDataParm::PlcStop {} => {}
                },
                Self::Userdata { subfunction } => {
                    if let s7comm::Parameter::Userdata {
                        subfunction: _subfunction,
                        ..
                    } = &s7.parameter
                    {
                        detect_option_eq!(subfunction, _subfunction);
                    } else {
                        return false;
                    }
                }
            }

            true
        } else {
            false
        }
    }
}

#[cfg(test)]
pub mod tests {
    use parsing_rule::{RuleAction, Direction};

    use crate::{
        icsrule_arg::IcsRuleArg,
        HmIcsRules, IcsRule, IcsRuleBasis,
    };

    use super::*;

    #[test]
    fn serialize_s7comm_icsrule() {
        let s7comm_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: RuleAction::Alert,
                src_ip: None,
                src_port: None,
                dir: Direction::Bi,
                dst_ip: None,
                dst_port: None,
                msg: "Job - Read Var (0x04)".to_string(),
            },
            args: IcsRuleArg::S7COMM(S7CommArg::Job {
                param: S7JobParm::ReadVar {
                    area: Some(1),
                    start_address: Some(1),
                    end_address: Some(1),
                },
            }),
        };

        assert_eq!(
            serde_json::to_string(&s7comm_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"<>","dst":null,"dport":null,"msg":"Job - Read Var (0x04)","proname":"S7COMM","args":{"rosctr":"1","function_code":"4","area":1,"start_address":1,"end_address":1}}"#
        )
    }

    #[test]
    fn deserialize_s7comm_icsrule() {
        let mut s7comm_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_s7comm.json";
        assert!(s7comm_rule.load_rules(file_str));
    }
}
