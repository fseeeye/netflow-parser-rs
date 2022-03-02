#[macro_export]
macro_rules! detect_address {
    ( $sa:ident, $ea:ident, $ta:ident ) => {
        if let Some($sa) = $sa {
            if $sa > $ta {
                return false;
            }
        }

        if let Some($ea) = $ea {
            if $ea < $ta {
                return false;
            }
        }
    };
}

#[macro_export]
macro_rules! detect_option_eq {
    ( $optioner:ident, $target:ident ) => {
        if let Some($optioner) = $optioner {
            if $optioner != $target {
                return false;
            }
        }
    };
}

#[inline]
pub(crate) fn bytes_to_u32(num_bytes: &[u8]) -> Option<u32> {
    let mut out: u32 = 0;
    
    for &i in num_bytes.iter() {
        out = out.checked_shl(8)? | i as u32;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_u32() {
        let a = &[0x01, 0x00, 0x00];
        assert_eq!(bytes_to_u32(a), Some(0x010000));

        let b= &[0x01, 0x00, 0x00, 0x00];
        assert_eq!(bytes_to_u32(b), Some(0x01000000));

        let c = &[0x10,0x00,0x00, 0x00, 0x00];
        assert_eq!(bytes_to_u32(c), Some(0x00));
    }
}
