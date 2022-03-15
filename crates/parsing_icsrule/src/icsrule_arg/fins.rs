use parsing_parser::{parsers::fins_tcp_req, ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::{detect::IcsRuleDetector, detect_address, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct FinsArg {
    dna: Option<u8>,
    dnn: Option<u8>,
    dua: Option<u8>,
    sna: Option<u8>,
    snn: Option<u8>,
    sua: Option<u8>,
    #[serde(flatten)]
    command_data: FinsCommandData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum FinsCommandData {
    #[serde(rename = "0x0101", alias = "257")]
    MemoryAreaRead {
        code: Option<u16>,          // area code
        start_address: Option<u32>, // beginning_address
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0102", alias = "258")]
    MemoryAreaWrite {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0103", alias = "259")]
    MemoryAreaFill {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0104", alias = "260")]
    MultipleMemoryAreaRead {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0105", alias = "261")]
    MemoryAreaTransfer {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0201", alias = "513")]
    ParameterAreaRead {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0202", alias = "514")]
    ParameterAreaWrite {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0203", alias = "515")]
    ParameterAreaClear {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x0220", alias = "544")]
    DataLinkTableRead {},
    #[serde(rename = "0x0221", alias = "545")]
    DataLinkTableWrite {},
    #[serde(rename = "0x0304", alias = "722")]
    ProgramAreaProtect {},
    #[serde(rename = "0x0305", alias = "723")]
    ProgramAreaProtectClear {},
    #[serde(rename = "0x0306", alias = "724")]
    ProgramAreaRead {},
    #[serde(rename = "0x0307", alias = "725")]
    ProgramAreaWrite {},
    #[serde(rename = "0x0308", alias = "726")]
    ProgramAreaClear {},
    #[serde(rename = "0x0401", alias = "1025")]
    Run { code: Option<u16> },
    #[serde(rename = "0x0402", alias = "1026")]
    Stop {},
    #[serde(rename = "0x0403", alias = "1027")]
    Reset {},
    #[serde(rename = "0x0501", alias = "1281")]
    ControllerDataRead {},
    #[serde(rename = "0x0502", alias = "1282")]
    ConnectionDataRead {},
    #[serde(rename = "0x0601", alias = "1537")]
    ControllerStatusRead {},
    #[serde(rename = "0x0602", alias = "1538")]
    NetworkStatusRead {},
    #[serde(rename = "0x0603", alias = "1539")]
    DataLinkStatusRead {},
    #[serde(rename = "0x0620", alias = "1568")]
    CycleTimeRead {},
    #[serde(rename = "0x0701", alias = "1793")]
    ClcokRead {},
    #[serde(rename = "0x0702", alias = "1794")]
    ClcokWrite {},
    #[serde(rename = "0x0801", alias = "2049")]
    LoopBackTest {},
    #[serde(rename = "0x0802", alias = "2050")]
    BroadcastTestResultsRead {},
    #[serde(rename = "0x0803", alias = "2051")]
    BroadcastTestDataSend {},
    #[serde(rename = "0x0920", alias = "2336")]
    MessageReadClearFALSRead {},
    #[serde(rename = "0x0C01", alias = "0x0c01", alias = "3073")]
    AccessRightAcquire {},
    #[serde(rename = "0x0C02", alias = "0x0c02", alias = "3074")]
    AccessRightForcedAcquire {},
    #[serde(rename = "0x0C03", alias = "0x0c03", alias = "3075")]
    AccessRightRelease {},
    #[serde(rename = "0x2101", alias = "8449")]
    ErrorClear {},
    #[serde(rename = "0x2102", alias = "8450")]
    ErrorLogRead {},
    #[serde(rename = "0x2103", alias = "8451")]
    ErrorLogClear {},
    #[serde(rename = "0x2201", alias = "8705")]
    FileNameRead {},
    #[serde(rename = "0x2202", alias = "8706")]
    SingleFileRead {},
    #[serde(rename = "0x2203", alias = "8707")]
    SingleFileWrite {},
    #[serde(rename = "0x2204", alias = "8708")]
    MemoryCardFormat {},
    #[serde(rename = "0x2205", alias = "8709")]
    FileDelete {},
    #[serde(rename = "0x2206", alias = "8710")]
    VolumeLabelCreateOrDelete {},
    #[serde(rename = "0x2207", alias = "8711")]
    FileCopy {},
    #[serde(rename = "0x2208", alias = "8712")]
    FileNameChange {},
    #[serde(rename = "0x2209", alias = "8713")]
    FileDataCheck {},
    #[serde(rename = "0x220A", alias = "0x220a", alias = "8714")]
    MemoryAreaFileTransfer {},
    #[serde(rename = "0x220B", alias = "0x220b", alias = "8715")]
    ParameterAreaFileTransfer {},
    #[serde(rename = "0x220C", alias = "0x220c", alias = "8716")]
    ProgramAreaFileTransfer {},
    #[serde(rename = "0x220F", alias = "0x220f", alias = "8718")]
    FileMemoryIndexRead {},
    #[serde(rename = "0x2210", alias = "8719")]
    FileMemoryRead {},
    #[serde(rename = "0x2211", alias = "8720")]
    FileMemoryWrite {},
    #[serde(rename = "0x2301", alias = "8961")]
    ForcedSetOrReset {},
    #[serde(rename = "0x2302", alias = "8962")]
    ForcedSetOrResetCancel {},
    #[serde(rename = "0x2303", alias = "8963")]
    MultipleForcedStatusRead {
        code: Option<u16>,
        start_address: Option<u32>,
        end_address: Option<u32>,
    },
    #[serde(rename = "0x2601", alias = "9729")]
    NameSet {},
    #[serde(rename = "0x2602", alias = "9730")]
    NameDelete {},
    #[serde(rename = "0x2603", alias = "9731")]
    NameRead {},
}

impl IcsRuleDetector for FinsArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::FinsTcpReq(fins_req) = &l5.application_layer {
            if let fins_tcp_req::State::Connected { fh } = &fins_req.state {
                detect_option_eq!(self.dna, fh.dna);
                detect_option_eq!(self.dnn, fh.dnn);
                detect_option_eq!(self.dua, fh.dua);
                detect_option_eq!(self.sna, fh.sna);
                detect_option_eq!(self.snn, fh.snn);
                detect_option_eq!(self.sua, fh.sua);

                match self.command_data {
                    FinsCommandData::MemoryAreaRead {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::MemoryAreaRead {
                            memory_area_code,
                            beginning_address,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, memory_area_code as u16);
                            detect_address!(start_address, end_address, beginning_address as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MemoryAreaWrite {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::MemoryAreaWrite {
                            memory_area_code,
                            beginning_address,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, memory_area_code as u16);
                            detect_address!(start_address, end_address, beginning_address as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MemoryAreaFill {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::MemoryAreaFill {
                            memory_area_code,
                            beginning_address,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, memory_area_code as u16);
                            detect_address!(start_address, end_address, beginning_address as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MultipleMemoryAreaRead {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::MultipleMemoryAreaRead { result: results } =
                            &fh.cmd_type.order
                        {
                            for result in results {
                                detect_option_eq!(code, result.memory_area_code as u16);
                                detect_address!(
                                    start_address,
                                    end_address,
                                    result.beginning_address as u32
                                );
                            }
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MemoryAreaTransfer {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::MemoryAreaTransfer {
                            memory_area_code_wc,
                            beginning_address,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, memory_area_code_wc as u16);
                            detect_address!(start_address, end_address, beginning_address as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ParameterAreaRead {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::ParameterAreaRead {
                            parameter_area_code,
                            beginning_word,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, parameter_area_code);
                            detect_address!(start_address, end_address, beginning_word as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ParameterAreaWrite {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::ParameterAreaWrite {
                            parameter_area_code,
                            beginning_word,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, parameter_area_code);
                            detect_address!(start_address, end_address, beginning_word as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ParameterAreaClear {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::ParameterAreaClear {
                            parameter_area_code,
                            beginning_word,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, parameter_area_code);
                            detect_address!(start_address, end_address, beginning_word as u32);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::DataLinkTableRead {} => {
                        if let fins_tcp_req::Order::DataLinkTableRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::DataLinkTableWrite {} => {
                        if let fins_tcp_req::Order::DataLinkTableWrite { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ProgramAreaProtect {} => {
                        if let fins_tcp_req::Order::ProgramAreaProtect { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ProgramAreaProtectClear {} => {
                        if let fins_tcp_req::Order::ProgramAreaProtectClear { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ProgramAreaRead {} => {
                        if let fins_tcp_req::Order::ProgramAreaRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ProgramAreaWrite {} => {
                        if let fins_tcp_req::Order::ProgramAreaWrite { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ProgramAreaClear {} => {
                        if let fins_tcp_req::Order::ProgramAreaClear { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::Run { code } => {
                        if let fins_tcp_req::Order::Run { mode_code, .. } = fh.cmd_type.order {
                            detect_option_eq!(code, mode_code as u16);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::Stop {} => {
                        if let fins_tcp_req::Order::Stop { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::Reset {} => {
                        if let fins_tcp_req::Order::Reset { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ControllerDataRead {} => {
                        if let fins_tcp_req::Order::ControllerDataRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ConnectionDataRead {} => {
                        if let fins_tcp_req::Order::ConnectionDataRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ControllerStatusRead {} => {
                        if let fins_tcp_req::Order::ControllerStatusRead { .. } = fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::NetworkStatusRead {} => {
                        if let fins_tcp_req::Order::NetworkStatusRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::DataLinkStatusRead {} => {
                        if let fins_tcp_req::Order::DataLinkStatusRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::CycleTimeRead {} => {
                        if let fins_tcp_req::Order::CycleTimeRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ClcokRead {} => {
                        if let fins_tcp_req::Order::ClcokRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ClcokWrite {} => {
                        if let fins_tcp_req::Order::ClcokWrite { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::LoopBackTest {} => {
                        if let fins_tcp_req::Order::LoopBackTest { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::BroadcastTestResultsRead {} => {
                        if let fins_tcp_req::Order::BroadcastTestResultsRead { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::BroadcastTestDataSend {} => {
                        if let fins_tcp_req::Order::BroadcastTestDataSend { .. } = fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MessageReadClearFALSRead {} => {
                        if let fins_tcp_req::Order::MessageReadClearFALSRead { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::AccessRightAcquire {} => {
                        if let fins_tcp_req::Order::AccessRightAcquire { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::AccessRightForcedAcquire {} => {
                        if let fins_tcp_req::Order::AccessRightForcedAcquire { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::AccessRightRelease {} => {
                        if let fins_tcp_req::Order::AccessRightRelease { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ErrorClear {} => {
                        if let fins_tcp_req::Order::ErrorClear { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ErrorLogRead {} => {
                        if let fins_tcp_req::Order::ErrorLogRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ErrorLogClear {} => {
                        if let fins_tcp_req::Order::ErrorLogClear { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileNameRead {} => {
                        if let fins_tcp_req::Order::FileNameRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::SingleFileRead {} => {
                        if let fins_tcp_req::Order::SingleFileRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::SingleFileWrite {} => {
                        if let fins_tcp_req::Order::SingleFileWrite { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MemoryCardFormat {} => {
                        if let fins_tcp_req::Order::MemoryCardFormat { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileDelete {} => {
                        if let fins_tcp_req::Order::FileDelete { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::VolumeLabelCreateOrDelete {} => {
                        if let fins_tcp_req::Order::VolumeLabelCreateOrDelete { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileCopy {} => {
                        if let fins_tcp_req::Order::FileCopy { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileNameChange {} => {
                        if let fins_tcp_req::Order::FileNameChange { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileDataCheck {} => {
                        if let fins_tcp_req::Order::FileDataCheck { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MemoryAreaFileTransfer {} => {
                        if let fins_tcp_req::Order::MemoryAreaFileTransfer { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ParameterAreaFileTransfer {} => {
                        if let fins_tcp_req::Order::ParameterAreaFileTransfer { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ProgramAreaFileTransfer {} => {
                        if let fins_tcp_req::Order::ProgramAreaFileTransfer { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileMemoryIndexRead {} => {
                        if let fins_tcp_req::Order::FileMemoryIndexRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileMemoryRead {} => {
                        if let fins_tcp_req::Order::FileMemoryRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::FileMemoryWrite {} => {
                        if let fins_tcp_req::Order::FileMemoryWrite { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ForcedSetOrReset {} => {
                        if let fins_tcp_req::Order::ForcedSetOrReset { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::ForcedSetOrResetCancel {} => {
                        if let fins_tcp_req::Order::ForcedSetOrResetCancel { .. } =
                            fh.cmd_type.order
                        {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::MultipleForcedStatusRead {
                        code,
                        start_address,
                        end_address,
                    } => {
                        if let fins_tcp_req::Order::MultipleForcedStatusRead {
                            memory_area_code,
                            beginning_address,
                            ..
                        } = fh.cmd_type.order
                        {
                            detect_option_eq!(code, memory_area_code as u16);
                            detect_address!(start_address, end_address, beginning_address);
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::NameSet {} => {
                        if let fins_tcp_req::Order::NameSet { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::NameDelete {} => {
                        if let fins_tcp_req::Order::NameDelete { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
                    }
                    FinsCommandData::NameRead {} => {
                        if let fins_tcp_req::Order::NameRead { .. } = fh.cmd_type.order {
                        } else {
                            return false;
                        }
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
mod tests {
    use crate::{
        icsrule::basis::{Action, Direction},
        icsrule_arg::IcsRuleArg,
        HmIcsRules, IcsRule, IcsRuleBasis,
    };

    use super::*;

    #[test]
    fn serialize_fins_icsrule() {
        let dnp3_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: Action::Alert,
                src_ip: None,
                src_port: None,
                dir: Direction::Uni,
                dst_ip: None,
                dst_port: Some(9600),
                msg: "Fins Memory Area Read".to_string(),
            },
            args: IcsRuleArg::FINS(FinsArg {
                dna: Some(1),
                dnn: None,
                dua: None,
                sna: None,
                snn: None,
                sua: None,
                command_data: FinsCommandData::MemoryAreaRead {
                    code: Some(1),
                    start_address: Some(1),
                    end_address: Some(1),
                },
            }),
        };

        assert_eq!(
            serde_json::to_string(&dnp3_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":9600,"msg":"Fins Memory Area Read","proname":"FINS","args":{"dna":1,"dnn":null,"dua":null,"sna":null,"snn":null,"sua":null,"function_code":"0x0101","code":1,"start_address":1,"end_address":1}}"#
        )
    }

    #[test]
    fn deserialize_dnp3_icsrule() {
        let mut fins_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_fins.json";
        assert!(fins_rule.load_rules(file_str));
    }
}
