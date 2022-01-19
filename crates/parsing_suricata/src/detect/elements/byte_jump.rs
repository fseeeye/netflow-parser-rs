use std::str::FromStr;

use crate::{
    surule::elements::{ByteJump, NumType, Endian, ByteJumpFrom}, 
    detect::utils::uisize_add
};


impl ByteJump {
    pub fn jump(&self, payload_slice: &[u8], last_pos: usize) -> Option<usize> {
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
        
        // Step2: Get Jump Num 
        // num_of_bytes(count) & endian & string + num_type
        let mut num: u64  = if self.string {
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
                },
            }
        } else {
            let num_bytes = payload_slice.get(num_pos..num_pos+(self.count as usize))?;
            self.bytes_to_u64(&num_bytes)?
        };
        // multiplier
        if let Some(multiplier_inner) = self.multiplier {
            num = num.checked_mul(multiplier_inner as u64)?;
        }
        // align: rounds the number up to the next 32bit boundary
        // ref: https://stackoverflow.com/questions/29925524/how-do-i-round-to-the-next-32-bit-alignment
        if self.align {
            // num = num.checked_add(2^32 - (num % 2^32))?;
            num = num.checked_add(4 - (num % 4))?; // Warning: correct?
        }
        // bitmask
        if let Some(bitmask_inner) = self.bitmask {
            num &= bitmask_inner as u64;
        }

        // Step3: Jump Operation
        let mut new_pos: usize;
        // from_beginning / from_end
        match self.from {
            Some(ByteJumpFrom::BEGIN) => {
                new_pos = num.try_into().ok()?;
            },
            Some(ByteJumpFrom::END) => {
                new_pos = num.checked_add((payload_len - 1)as u64)?.try_into().ok()?;
            },
            None => {
                new_pos = num.checked_add(num_pos as u64)?.checked_add(self.count as u64)?.try_into().ok()?;
            }
        }
        // post_offset
        new_pos = uisize_add(new_pos, self.post_offset.unwrap_or(0))?;

        if new_pos < payload_len { Some(new_pos) } else { None }
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
    fn check_bytejump() {
        // Common Example
        let bytejump_common = ByteJump {
            count: 2,
            offset: 1,
            ..Default::default()
        };
        let payload: &[u8] = &[0, 0x00, 0x02, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(bytejump_common.jump(payload, 99), Some(5));
        
        // ByteJump Keyword: relative
        let bytejump_relative = ByteJump {
            count: 2,
            offset: 1,
            relative: true,
            ..Default::default()
        };
        let payload: &[u8] = &[0, 1, 0x00, 0x01, 4, 5, 6, 7, 8, 9];
        assert_eq!(bytejump_relative.jump(payload, 1), Some(5));

        // ByteJump Keyword: string & <num_type>
        let bytejump_string = ByteJump {
            count: 2,
            offset: 0,
            string: true,
            num_type: Some(NumType::HEX),
            ..Default::default()
        };
        let payload: &[u8] = &[0x30, 0x31, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(bytejump_string.jump(payload, 99), Some(3));

        // ByteJump Keyword: bitmask
        let bytejump_bitmask = ByteJump {
            count: 2,
            offset: 0,
            bitmask: Some(0x01),
            ..Default::default()
        };
        let payload: &[u8] = &[0x00, 0xff, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(bytejump_bitmask.jump(payload, 99), Some(3));

        // ByteJump Keyword: align
        let bytejump_align = ByteJump {
            count: 2,
            offset: 0,
            align: true,
            ..Default::default()
        };
        let payload: &[u8] = &[0x00, 0x01, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(bytejump_align.jump(payload, 99), Some(6));

        // Complex Example
        let bytejump_complex = ByteJump {
            count: 2,
            offset: 2,
            relative: true,
            endian: Some(Endian::Little),
            multiplier: Some(2),
            from: Some(ByteJumpFrom::BEGIN),
            post_offset: Some(-1),
            ..Default::default()
        };
        let payload: &[u8] = &[0, 1, 2, 0x01, 0x00, 5, 6, 7, 8, 9];
        assert_eq!(bytejump_complex.jump(payload, 1), Some(1));
    }
}