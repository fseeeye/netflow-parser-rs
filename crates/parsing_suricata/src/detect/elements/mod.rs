mod flowbits;
mod iplist;
mod portlist;

pub trait SuruleElementDetector {
    type Comparison;
    fn check(&self, _: &Self::Comparison) -> bool;
}

pub trait SuruleElementSimpleDetector: SuruleElementDetector {
    fn check_simple(&self) -> bool;
}
