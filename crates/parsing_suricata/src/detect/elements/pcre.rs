use crate::surule::elements::Pcre;

impl Pcre {
    pub fn check(&self, payload_slice: &[u8]) -> bool {
        let mut pcre_builder = pcre2::bytes::RegexBuilder::new();
        pcre_builder.jit(true);

        if self.modifier_i {
            pcre_builder.caseless(true);
        }

        if self.modifier_m {
            pcre_builder.multi_line(true);
        }

        if self.modifier_s {
            pcre_builder.dotall(true);
        }

        if self.modifier_u {
            pcre_builder.utf(true);
        }

        if self.modifier_x {
            pcre_builder.extended(true);
        }

        if let Ok(pcre_regex) = pcre_builder.build(&self.pattern) {
            if let Ok(rst) = pcre_regex.is_match(payload_slice) {
                if self.negate {
                    !rst
                } else {
                    rst
                }
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pcre() {
        let pcre_caseless = Pcre {
            pattern: "NICK .*USA.*[0-9]{3,}".to_string(),
            modifier_i: true,
            ..Default::default()
        };
        let pcre_negative = Pcre {
            negate: true,
            pattern: "NICK .*USA.*[0-9]{3,}".to_string(),
            ..Default::default()
        };

        assert!(pcre_caseless.check(b"nIck balabalaUsAbalbala1234"));
        assert!(!pcre_negative.check(b"NICK balabalaUSAbalbala1234"));
    }
}