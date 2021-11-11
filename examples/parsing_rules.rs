use parsing_rs::icsrule::Rules;

fn main() {
    let file_str = "./examples/ics_rules.json";

    let mut rules = Rules::new();

    if rules.init(file_str) {
        println!("{:?}", rules);
    } else {
        println!("Rules Init failed...");
    };
}