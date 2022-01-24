/// usize add with isize
#[allow(dead_code)]
#[inline]
pub(crate) fn uisize_add(unum: usize, inum: isize) -> Option<usize> {
    if inum.is_negative() {
        unum.checked_sub(inum.wrapping_abs() as usize)
    } else {
        unum.checked_add(inum as usize)
    }
}

/// usize sub with isize
#[allow(dead_code)]
#[inline]
pub(crate) fn uisize_sub(unum: usize, inum: isize) -> Option<usize> {
    if inum.is_negative() {
        unum.checked_add(inum.wrapping_abs() as usize)
    } else {
        unum.checked_sub(inum as usize)
    }
}

/// u64 add with i64
#[allow(dead_code)]
#[inline]
pub(crate) fn ui64_add(unum: u64, inum: i64) -> Option<u64> {
    if inum.is_negative() {
        unum.checked_sub(inum.wrapping_abs() as u64)
    } else {
        unum.checked_add(inum as u64)
    }
}

/// u64 sub with i64
#[allow(dead_code)]
#[inline]
pub(crate) fn ui64_sub(unum: u64, inum: i64) -> Option<u64> {
    if inum.is_negative() {
        unum.checked_add(inum.wrapping_abs() as u64)
    } else {
        unum.checked_sub(inum as u64)
    }
}
