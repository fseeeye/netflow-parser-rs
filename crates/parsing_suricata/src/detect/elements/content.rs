use crate::surule::elements::{Content, ContentPosKey};

impl Content {
    #[inline]
    pub fn check(&self, payload_slice: &[u8], last_pos: usize) -> Option<usize> {
        if self.nocase {
            self.check_content_pos(payload_slice.to_ascii_lowercase().as_slice(), last_pos)
        } else {
            self.check_content_pos(payload_slice, last_pos)
        }
        // TODO: fastpattern
    }

    #[inline]
    fn check_content_pos(&self, payload_slice: &[u8], last_pos: usize) -> Option<usize> {
        let pattern_slice = self.pattern.as_slice();

        match self.pos_key {
            ContentPosKey::NotSet => find_subsequence(payload_slice, pattern_slice),
            ContentPosKey::StartsWith => {
                if pattern_slice.len() > payload_slice.len() {
                    None
                } else {
                    if &payload_slice[..pattern_slice.len()] == pattern_slice {
                        Some(pattern_slice.len())
                    } else {
                        None
                    }
                }
            }
            ContentPosKey::EndsWith => {
                if pattern_slice.len() > payload_slice.len() {
                    None
                } else {
                    if &payload_slice[payload_slice.len() - pattern_slice.len()..] == pattern_slice
                    {
                        Some(payload_slice.len())
                    } else {
                        None
                    }
                }
            }
            ContentPosKey::Absolute {
                depth: depth_op,
                offset: offset_op,
            } => {
                let min: usize;
                let max: usize;
                let payload_len = payload_slice.len();

                if let Some(offset) = offset_op {
                    min = if offset < payload_len {
                        offset
                    } else {
                        payload_len
                    };
                } else {
                    min = 0;
                }
                if let Some(depth) = depth_op {
                    let end = min + depth;
                    max = if end < payload_len { end } else { payload_len };
                } else {
                    max = payload_len;
                }
                let payload_slice_new = &payload_slice[min..max];

                find_subsequence(payload_slice_new, pattern_slice).map(|p| p + min)
            }
            ContentPosKey::Relative {
                within: within_op,
                distance: distance_op,
            } => {
                let offset: usize;
                if let Some(distance) = distance_op {
                    if distance < 0 {
                        let distance_abs = distance.wrapping_abs() as usize;
                        if distance_abs > last_pos {
                            offset = 0;
                        } else {
                            offset = last_pos - distance_abs;
                        }
                    } else {
                        offset = last_pos + (distance as usize);
                    }
                } else {
                    offset = last_pos;
                }

                let payload_len = payload_slice.len();
                let min = if offset < payload_len {
                    offset
                } else {
                    payload_len
                };
                // Warning: 匹配算法实现和 Suricata 文档有出入，因为根据对现有规则的观察，文档描述存在问题。
                let max: usize;
                if let Some(within) = within_op {
                    let end = min + within;
                    max = if end < payload_len { end } else { payload_len };
                } else {
                    max = payload_len;
                }
                let payload_slice_new = &payload_slice[min..max];

                find_subsequence(payload_slice_new, pattern_slice).map(|p| p + min)
            }
        }
    }
}

// ref: https://stackoverflow.com/questions/35901547/how-can-i-find-a-subsequence-in-a-u8-slice
#[inline(always)]
fn find_subsequence<T>(haystack: &[T], needle: &[T]) -> Option<usize>
where
    for<'a> &'a [T]: PartialEq,
{
    let needle_len = needle.len();
    haystack
        .windows(needle_len)
        .position(|window| window == needle)
        .map(|p| p + needle_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_content_pos() {
        let content_notset = Content {
            pattern: vec![2, 3],
            pos_key: ContentPosKey::NotSet,
            ..Default::default()
        };
        let content_startswith = Content {
            pattern: vec![1, 2, 3],
            pos_key: ContentPosKey::StartsWith,
            ..Default::default()
        };
        let content_endswith = Content {
            pattern: vec![5, 6],
            pos_key: ContentPosKey::EndsWith,
            ..Default::default()
        };
        let content_absolute1 = Content {
            pattern: vec![3],
            pos_key: ContentPosKey::Absolute {
                depth: Some(6),
                offset: Some(6),
            },
            ..Default::default()
        };
        let content_absolute2 = Content {
            pattern: vec![6],
            pos_key: ContentPosKey::Absolute {
                depth: None,
                offset: Some(6),
            },
            ..Default::default()
        };
        let content_absolute3 = Content {
            pattern: vec![6],
            pos_key: ContentPosKey::Absolute {
                depth: Some(5),
                offset: None,
            },
            ..Default::default()
        };
        let content_relative = Content {
            pattern: vec![5],
            pos_key: ContentPosKey::Relative {
                within: Some(3),
                distance: Some(3),
            },
            ..Default::default()
        };

        let payload: &[u8] = &[1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6];
        assert_eq!(content_notset.check_content_pos(payload, 0), Some(3));
        assert_eq!(content_startswith.check_content_pos(payload, 0), Some(3));
        assert_eq!(content_endswith.check_content_pos(payload, 0), Some(12));
        assert_eq!(content_absolute1.check_content_pos(payload, 0), Some(9));
        assert_eq!(content_absolute2.check_content_pos(payload, 0), Some(12));
        assert_eq!(content_absolute3.check_content_pos(payload, 0), None);
        assert_eq!(content_relative.check_content_pos(payload, 5), Some(11));
    }

    #[test]
    fn test_content() {
        let content_nocase = Content {
            pattern: b"fg".to_vec(),
            nocase: true,
            ..Default::default()
        };
        let content_opcua_hello = Content {
            pattern: b"HELFO".to_vec(),
            nocase: false,
            pos_key: ContentPosKey::StartsWith,
            ..Default::default()
        };

        let payload: &[u8] = b"aBcdEfGH";
        assert_eq!(content_nocase.check(payload, 0), Some(7));
        let payload: Vec<u8> = vec![
            72, 69, 76, 70, 79, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 160, 15, 0, 0,
            0, 0, 0, 0, 47, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120,
            112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 85, 65, 47, 83, 116,
            97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114,
        ];
        assert_eq!(content_opcua_hello.check(payload.as_slice(), 0), Some(5));
    }
}
