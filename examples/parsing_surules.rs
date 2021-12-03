use parsing_rs::suricata_rule::{VecSurules, Surules};
use tracing::{error, info};

fn main() {
    tracing_subscriber::fmt::init();

    let filepath = "./examples/suricata.rules";
    match VecSurules::parse_from_file(filepath) {
        Ok(_) => info!(target: "EXAMPLE(parsing_surules)", "Done."),
        Err(_) => error!(target: "EXAMPLE(parsing_surules)", "Failed.")
    };
}