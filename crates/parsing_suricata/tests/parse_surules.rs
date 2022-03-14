use parsing_suricata::{Surules, VecSurules};

#[test]
fn parse_suricata_rules() {
    let filepath = "./tests/suricata_200.rules";
    let parse_rst = VecSurules::init_from_file(filepath);
    // println!("{parse_rst:?}");
    assert!(parse_rst.is_ok());
}
