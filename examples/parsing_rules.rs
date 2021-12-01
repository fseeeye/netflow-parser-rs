use parsing_rs::icsrule::HmIcsRules;

fn main() {
    let file_str = "./examples/ics_rules.json";

    let mut rules = HmIcsRules::new();

    if rules.init(file_str) {
        println!("{:?}", rules);
    } else {
        println!("Rules Init failed...");
    };
}