mod vec_surules;

pub use vec_surules::VecSurules;

use parsing_rule::Rules;
pub trait Surules: Rules {
    type Err;

    // ref: https://users.rust-lang.org/t/returning-option-self-in-a-trait/28081/2
    fn parse_from_file(filepath: &str) -> Result<Self, Self::Err>
    where
        Self: Sized;
}
