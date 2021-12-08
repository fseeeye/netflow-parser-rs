mod portlist;
mod iplist;
mod flowbits;


pub trait SuruleElementDetector {
    type Comparison;
    fn check(&self, _: &Self::Comparison) -> bool;
}

pub trait SuruleElementSimpleDetector: SuruleElementDetector {
    fn check_simple(&self) -> bool;
}