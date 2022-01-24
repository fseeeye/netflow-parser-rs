use crate::surule::elements::Dsize;

impl Dsize {
    pub fn check(&self, payload_slice: &[u8]) -> bool {
        let payload_size = payload_slice.len();

        match self {
            Dsize::Equal(num) => {
                payload_size == *num
            },
            Dsize::Greater(num) => {
                payload_size > *num
            },
            Dsize::Less(num) => {
                payload_size < *num
            },
            Dsize::NotEqual(num) => {
                payload_size != *num
            },
            Dsize::Range(min, max) => {
                (payload_size > *min) && (payload_size < *max) 
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_dsize() {
        let dsize_eq = Dsize::Equal(10);
        let dsize_ue = Dsize::NotEqual(11);
        let dsize_ge = Dsize::Greater(9);
        let dsize_le = Dsize::Less(11);
        let dsize_rg = Dsize::Range(9,11);
        let payload: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        assert!(dsize_eq.check(payload));
        assert!(dsize_ue.check(payload));
        assert!(dsize_ge.check(payload));
        assert!(dsize_le.check(payload));
        assert!(dsize_rg.check(payload));
    }
}