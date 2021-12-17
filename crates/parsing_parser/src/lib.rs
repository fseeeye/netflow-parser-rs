#![feature(destructuring_assignment)]

mod errors;
mod field_type;
mod layer;
mod packet;
mod protocol;
mod utils;

pub mod parsers;

pub use errors::ParseError;
// field -> protocol -> layer -> packet => parser
pub use layer::*;
pub use packet::*;
pub use protocol::*;
pub use field_type::{MacAddress, BerTL};