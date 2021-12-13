mod flowbits;
mod iplist;
mod portlist;

pub trait SuruleElementDetector {
    type Comparison<'a>;
    fn check<'a>(&self, _: Self::Comparison<'a>) -> bool;
}

pub trait SuruleElementSimpleDetector: SuruleElementDetector {
    fn check_simple(&self) -> bool;
}
