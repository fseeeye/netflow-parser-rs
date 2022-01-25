// detect basis
mod iplist;
mod portlist;

// detect payload keywords
mod byte_jump;
mod byte_test;
mod content;
mod dsize;
mod pcre;

// detect flow keywords
mod flowbits;

// pub trait SuruleElementDetector {
//     type Comparison<'a>;
//     fn check<'a>(&self, _: Self::Comparison<'a>) -> bool;
// }

// pub trait SuruleElementSimpleDetector: SuruleElementDetector {
//     fn check_simple(&self) -> bool;
// }
