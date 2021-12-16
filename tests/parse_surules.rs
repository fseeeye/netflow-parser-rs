use parsing_rs::suricata_rule::{Surules, VecSurules};

#[test]
fn parse_suricata_rules() {
    let filepath = "./tests/suricata_200.rules";
    assert!(VecSurules::parse_from_file(filepath).is_ok());
}