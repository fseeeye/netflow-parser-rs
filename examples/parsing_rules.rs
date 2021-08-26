use parsing_rs::{init_whitelist_rules, Rules};

fn main() {
    let file_str = "./examples/ics_rules.json";

    let mut rules = Rules::new();

    // assert_eq!(init_whitelist_rules(Rules::new(), file_str), true);
    if init_whitelist_rules(&mut rules, file_str) {
        println!("{:?}", rules);
    } else {
        println!("[!] init rule error!");
    }
}