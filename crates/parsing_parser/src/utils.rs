#[inline(always)]
pub fn crc16_check(crc16: u16, bytes: &[u8], mut seed: u16, table: [u16; 256]) -> bool {
    for &byte in bytes {
        seed = table[((seed ^ (byte as u16)) & 0xffu16) as usize] ^ (seed >> 8);
    }
    !seed == crc16
}

#[inline(always)]
pub fn crc16_0x3d65_check(crc16: u16, bytes: &[u8], seed: u16) -> bool {
    let crc16_precompiled_3d65_reverse: [u16; 256] = [
        0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
        0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
        0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
        0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
        0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
        0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
        0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
        0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
        0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
        0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
        0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
        0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
        0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
        0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
        0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
        0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
        0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
        0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
        0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
        0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
        0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
        0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
        0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
        0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
        0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
        0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
        0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
        0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
        0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
        0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
        0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
        0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
    ];

    crc16_check(crc16, bytes, seed, crc16_precompiled_3d65_reverse)
}

#[allow(dead_code)]
#[inline(always)]
pub fn crc16_0x9949_check(crc16: u16, bytes: &[u8], seed: u16) -> bool {
    let crc16_precompiled_9949_reverse: [u16; 256] = [
        0x0000, 0x0ED2, 0x1DA4, 0x1376, 0x3B48, 0x359A, 0x26EC, 0x283E,
        0x7690, 0x7842, 0x6B34, 0x65E6, 0x4DD8, 0x430A, 0x507C, 0x5EAE,
        0xED20, 0xE3F2, 0xF084, 0xFE56, 0xD668, 0xD8BA, 0xCBCC, 0xC51E,
        0x9BB0, 0x9562, 0x8614, 0x88C6, 0xA0F8, 0xAE2A, 0xBD5C, 0xB38E,
        0xFF73, 0xF1A1, 0xE2D7, 0xEC05, 0xC43B, 0xCAE9, 0xD99F, 0xD74D,
        0x89E3, 0x8731, 0x9447, 0x9A95, 0xB2AB, 0xBC79, 0xAF0F, 0xA1DD,
        0x1253, 0x1C81, 0x0FF7, 0x0125, 0x291B, 0x27C9, 0x34BF, 0x3A6D,
        0x64C3, 0x6A11, 0x7967, 0x77B5, 0x5F8B, 0x5159, 0x422F, 0x4CFD,
        0xDBD5, 0xD507, 0xC671, 0xC8A3, 0xE09D, 0xEE4F, 0xFD39, 0xF3EB,
        0xAD45, 0xA397, 0xB0E1, 0xBE33, 0x960D, 0x98DF, 0x8BA9, 0x857B,
        0x36F5, 0x3827, 0x2B51, 0x2583, 0x0DBD, 0x036F, 0x1019, 0x1ECB,
        0x4065, 0x4EB7, 0x5DC1, 0x5313, 0x7B2D, 0x75FF, 0x6689, 0x685B,
        0x24A6, 0x2A74, 0x3902, 0x37D0, 0x1FEE, 0x113C, 0x024A, 0x0C98,
        0x5236, 0x5CE4, 0x4F92, 0x4140, 0x697E, 0x67AC, 0x74DA, 0x7A08,
        0xC986, 0xC754, 0xD422, 0xDAF0, 0xF2CE, 0xFC1C, 0xEF6A, 0xE1B8,
        0xBF16, 0xB1C4, 0xA2B2, 0xAC60, 0x845E, 0x8A8C, 0x99FA, 0x9728,
        0x9299, 0x9C4B, 0x8F3D, 0x81EF, 0xA9D1, 0xA703, 0xB475, 0xBAA7,
        0xE409, 0xEADB, 0xF9AD, 0xF77F, 0xDF41, 0xD193, 0xC2E5, 0xCC37,
        0x7FB9, 0x716B, 0x621D, 0x6CCF, 0x44F1, 0x4A23, 0x5955, 0x5787,
        0x0929, 0x07FB, 0x148D, 0x1A5F, 0x3261, 0x3CB3, 0x2FC5, 0x2117,
        0x6DEA, 0x6338, 0x704E, 0x7E9C, 0x56A2, 0x5870, 0x4B06, 0x45D4,
        0x1B7A, 0x15A8, 0x06DE, 0x080C, 0x2032, 0x2EE0, 0x3D96, 0x3344,
        0x80CA, 0x8E18, 0x9D6E, 0x93BC, 0xBB82, 0xB550, 0xA626, 0xA8F4,
        0xF65A, 0xF888, 0xEBFE, 0xE52C, 0xCD12, 0xC3C0, 0xD0B6, 0xDE64,
        0x494C, 0x479E, 0x54E8, 0x5A3A, 0x7204, 0x7CD6, 0x6FA0, 0x6172,
        0x3FDC, 0x310E, 0x2278, 0x2CAA, 0x0494, 0x0A46, 0x1930, 0x17E2,
        0xA46C, 0xAABE, 0xB9C8, 0xB71A, 0x9F24, 0x91F6, 0x8280, 0x8C52,
        0xD2FC, 0xDC2E, 0xCF58, 0xC18A, 0xE9B4, 0xE766, 0xF410, 0xFAC2,
        0xB63F, 0xB8ED, 0xAB9B, 0xA549, 0x8D77, 0x83A5, 0x90D3, 0x9E01,
        0xC0AF, 0xCE7D, 0xDD0B, 0xD3D9, 0xFBE7, 0xF535, 0xE643, 0xE891,
        0x5B1F, 0x55CD, 0x46BB, 0x4869, 0x6057, 0x6E85, 0x7DF3, 0x7321,
        0x2D8F, 0x235D, 0x302B, 0x3EF9, 0x16C7, 0x1815, 0x0B63, 0x05B1
    ];

    crc16_check(crc16, bytes, seed, crc16_precompiled_9949_reverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_0x3d65_check_test() {
        // let crc16: u16 = 0xce7a;
        let crc16 : u16 = 0x3185;
        let bytes: &[u8] = &[0xc0, 0xd7, 0x00];
        let seed: u16 = 0;
        assert!(!crc16_0x3d65_check(crc16, bytes, seed));
    }
}