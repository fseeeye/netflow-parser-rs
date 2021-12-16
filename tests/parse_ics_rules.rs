use parsing_rs::ics_rule::HmIcsRules;

#[test]
fn parse_ics_rules() {
    let file_str = "./tests/ics_rules.json";

    assert!(HmIcsRules::new().init(file_str))
}
