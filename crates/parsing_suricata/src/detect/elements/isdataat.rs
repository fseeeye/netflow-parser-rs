use crate::surule::elements::IsDataAt;

impl IsDataAt {
    pub fn check(&self, payload_slice: &[u8], last_pos: usize) -> bool {
        let payload_size = payload_slice.len();

        let rst: bool;
        if self.relative {
            rst = self.pos <= (payload_size - last_pos);
        } else {
            rst = self.pos <= payload_size;
        }

        if self.negate {
            !rst
        } else {
            rst
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_isdataat() {
        let isdataat_common = IsDataAt {
            pos: 9,
            ..Default::default()
        };
        assert!(isdataat_common.check(b"abcdefghi", 99));
        assert!(!isdataat_common.check(b"abcdefgh", 99));

        let isdataat_relative = IsDataAt {
            pos: 6,
            relative: true,
            ..Default::default()
        };
        assert!(isdataat_relative.check(b"abcdefghi", 3));
        assert!(!isdataat_relative.check(b"abcdefghi", 4));

        let isdataat_negative = IsDataAt {
            pos: 6,
            relative: true,
            negate: true,
        };
        assert!(!isdataat_negative.check(b"abcdefghi", 3));
        assert!(isdataat_negative.check(b"abcdefghi", 4));
    }
}
