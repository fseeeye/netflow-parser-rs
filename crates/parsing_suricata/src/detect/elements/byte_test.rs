use crate::{
    surule::elements::{ByteTest, NumType, Endian, ByteTestOp}, 
    detect::utils::uisize_add
};

use std::str::FromStr;


impl ByteTest {
    pub fn check(&self, payload_slice: &[u8], last_pos: usize) -> Option<usize> {
        let payload_len = payload_slice.len();
        if payload_len == 0 { return None }

        // Step1: Get Bytes start position
        // relative & offset
        let num_pos;
        if self.relative {
            num_pos = uisize_add(last_pos, self.offset)?;
        } else {
            num_pos = if self.offset.is_negative() { return None } else { self.offset as usize };
        }

        // Step2: Get Converted Num
        // num_of_bytes(count) & endian & string + num_type
        let mut num: u64 = if self.string {
            let num_string = std::str::from_utf8(payload_slice.get(num_pos..num_pos+(self.count as usize))?).ok()?;
            
            match self.num_type {
                Some(NumType::HEX) => {
                    // u64::from_str_radix(num_string, 16).ok()?
                    let num_bytes = hex::decode(num_string).ok()?;
                    self.bytes_to_u64(&num_bytes)?
                },
                Some(NumType::DEC) => {
                    // Warning: won't impl endian
                    u64::from_str(num_string).ok()?
                },
                Some(NumType::OCT) => {
                    // Warning: won't impl endian
                    u64::from_str_radix(num_string, 8).ok()?
                },
                None => {
                    // Default: HEX
                    let num_bytes = hex::decode(num_string).ok()?;
                    self.bytes_to_u64(&num_bytes)?
                }
            }
        } else {
            let num_bytes = payload_slice.get(num_pos..num_pos+(self.count as usize))?;
            self.bytes_to_u64(&num_bytes)?
        };
        // bitmask
        if let Some(bitmask_inner) = self.bitmask {
            num &= bitmask_inner as u64;
        }

        // Step3: Test Operation
        match self.operator {
            ByteTestOp::Equal => {
                if !((!self.op_nagation && num == self.test_value) || (self.op_nagation && num != self.test_value)) {
                    return None
                }
            },
            ByteTestOp::Greater => {
                if !((!self.op_nagation && num > self.test_value) || (self.op_nagation && num <= self.test_value)) {
                    return None
                }
            },
            ByteTestOp::GreaterEquanl => {
                if !((!self.op_nagation && num >= self.test_value) || (self.op_nagation && num < self.test_value)) {
                    return None
                }
            },
            ByteTestOp::Less => {
                if !((!self.op_nagation && num < self.test_value) || (self.op_nagation && num >= self.test_value)) {
                    return None
                }
            },
            ByteTestOp::LessEqual => {
                if !((!self.op_nagation && num <= self.test_value) || (self.op_nagation && num > self.test_value)) {
                    return None
                }
            },
            ByteTestOp::And => {
                if !((!self.op_nagation && (num & self.test_value) != 0) || (self.op_nagation && !(num & self.test_value) != 0)) {
                    return None
                }
            },
            ByteTestOp::Or => {
                if !((!self.op_nagation && (num | self.test_value) != 0) || (self.op_nagation && !(num | self.test_value) != 0)) {
                    return None
                }
            }
        }

        Some(last_pos)
    }

    #[inline]
    fn bytes_to_u64(&self, num_bytes: &[u8]) -> Option<u64> {
        let mut out: u64 = 0;
        if self.endian == Some(Endian::Little) {
            for &i in num_bytes.iter().rev() {
                out = out.checked_shl(8)? | i as u64;
            }
        } else {
            // Default: BigEndian
            for &i in num_bytes.iter() {
                out = out.checked_shl(8)? | i as u64;
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_bytetest() {
        // Common Example
        let bytetest_common = ByteTest {
            count: 2,
            op_nagation: false,
            operator: ByteTestOp::Equal,
            test_value: 16,
            offset: 1,
            ..Default::default()
        };
        let payload: &[u8] = &[0, 0x00, 0x10, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(bytetest_common.check(payload, 99), Some(99));
    }

}