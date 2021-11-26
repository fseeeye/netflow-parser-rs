/// 检查一个变量的值是否和其 default 值相同。
///
/// 对于 Serde 的 skip_serializing_if（判断是否该序列化某个field）十分好用，用于限制默认值被序列化输出。
pub(super) fn is_default<T>(val: &T) -> bool
where
    T: Default + PartialEq,
{
    (*val) == T::default()
}

/// 移除字符串中 非转义的引号 以及 转义符
pub(super) fn strip_quotes(input: &str) -> String {
    let mut escaped_flag = false;
    let mut rst: Vec<char> = Vec::new();

    for c in input.chars() {
        if escaped_flag {
            rst.push(c);
            escaped_flag = false;
        } else {
            match c {
                '"' => {
                    // pass unescaped quotes
                }
                '\\' => {
                    escaped_flag = true;
                }
                _ => {
                    rst.push(c);
                }
            }
        }
    }

    rst.iter().collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_quotes() {
        assert_eq!(
            strip_quotes(r#""some quoted \" \\ string""#),
            r#"some quoted " \ string"#
        );
    }
}
