use byteorder::{ByteOrder, LittleEndian};

/// Oh hey, these are the NEWDES S-boxes! ;)
/// https://groups.google.com/forum/#!msg/sci.crypt/DFmZzBcgF2M/xZ36MbKGuX8J
#[rustfmt::skip]
const MARTINI: [u8; 256] = [
    0x20, 0x89, 0xef, 0xbc, 0x66, 0x7d, 0xdd, 0x48, 0xd4, 0x44, 0x51, 0x25, 0x56, 0xed, 0x93, 0x95,
    0x46, 0xe5, 0x11, 0x7c, 0x73, 0xcf, 0x21, 0x14, 0x7a, 0x8f, 0x19, 0xd7, 0x33, 0xb7, 0x8a, 0x8e,
    0x92, 0xd3, 0x6e, 0xad, 0x01, 0xe4, 0xbd, 0x0e, 0x67, 0x4e, 0xa2, 0x24, 0xfd, 0xa7, 0x74, 0xff,
    0x9e, 0x2d, 0xb9, 0x32, 0x62, 0xa8, 0xfa, 0xeb, 0x36, 0x8d, 0xc3, 0xf7, 0xf0, 0x3f, 0x94, 0x02,
    0xe0, 0xa9, 0xd6, 0xb4, 0x3e, 0x16, 0x75, 0x6c, 0x13, 0xac, 0xa1, 0x9f, 0xa0, 0x2f, 0x2b, 0xab,
    0xc2, 0xaf, 0xb2, 0x38, 0xc4, 0x70, 0x17, 0xdc, 0x59, 0x15, 0xa4, 0x82, 0x9d, 0x08, 0x55, 0xfb,
    0xd8, 0x2c, 0x5e, 0xb3, 0xe2, 0x26, 0x5a, 0x77, 0x28, 0xca, 0x22, 0xce, 0x23, 0x45, 0xe7, 0xf6,
    0x1d, 0x6d, 0x4a, 0x47, 0xb0, 0x06, 0x3c, 0x91, 0x41, 0x0d, 0x4d, 0x97, 0x0c, 0x7f, 0x5f, 0xc7,
    0x39, 0x65, 0x05, 0xe8, 0x96, 0xd2, 0x81, 0x18, 0xb5, 0x0a, 0x79, 0xbb, 0x30, 0xc1, 0x8b, 0xfc,
    0xdb, 0x40, 0x58, 0xe9, 0x60, 0x80, 0x50, 0x35, 0xbf, 0x90, 0xda, 0x0b, 0x6a, 0x84, 0x9b, 0x68,
    0x5b, 0x88, 0x1f, 0x2a, 0xf3, 0x42, 0x7e, 0x87, 0x1e, 0x1a, 0x57, 0xba, 0xb6, 0x9a, 0xf2, 0x7b,
    0x52, 0xa6, 0xd0, 0x27, 0x98, 0xbe, 0x71, 0xcd, 0x72, 0x69, 0xe1, 0x54, 0x49, 0xa3, 0x63, 0x6f,
    0xcc, 0x3d, 0xc8, 0xd9, 0xaa, 0x0f, 0xc6, 0x1c, 0xc0, 0xfe, 0x86, 0xea, 0xde, 0x07, 0xec, 0xf8,
    0xc9, 0x29, 0xb1, 0x9c, 0x5c, 0x83, 0x43, 0xf9, 0xf5, 0xb8, 0xcb, 0x09, 0xf1, 0x00, 0x1b, 0x2e,
    0x85, 0xae, 0x4b, 0x12, 0x5d, 0xd1, 0x64, 0x78, 0x4c, 0xd5, 0x10, 0x53, 0x04, 0x6b, 0x8c, 0x34,
    0x3a, 0x37, 0x03, 0xf4, 0x61, 0xc5, 0xee, 0xe3, 0x76, 0x31, 0x4f, 0xe6, 0xdf, 0xa5, 0x99, 0x3b,
];

pub(crate) const JDROCKS: (&[u8; 3], &[u8; 3]) = (b"VcS", b"j4:");

// Flags:
const PLI_PROTECTION: u32 = 0x00000002;
const _ENCODING: u32 = 0x00000004;

pub(crate) struct VCS {
    // file: File, // @ 0x00
    _flags: u32, // @ 0x04

    // star_fixup: u16, // @ 0x06
    /// Plain text length (max 48 bytes?)
    pub(crate) length: u8, // @ 0x08

    _version: u16,      // @ 0x0a "spEarth"; 0 or 1
    _license_code: u32, // @ 0x10 "LibLicenseCode"

    /// 64-bit feedback block before `dewars_rocks` mixing
    pub(crate) last_block: [u8; 8], // @ 0x14

    /// Cipher state
    pub(crate) state: [u8; 7 * 8 + 4], // @ 0x1c

    /// Temporary byte buffer for enciphering
    pub(crate) buffer: [u8; 0x30], // @ 0x58

    // Technically global state, but we'll just manage it here...
    #[cfg(feature = "random")]
    prng: PCG32,
}

impl VCS {
    pub(crate) fn new() -> Self {
        #[cfg(feature = "random")]
        let seed = {
            use byteorder::NativeEndian;
            use getrandom::getrandom;

            let mut seed = [0_u8; 16];

            getrandom(&mut seed).expect("Failed to generate a random seed");

            (
                NativeEndian::read_u64(&seed[0..8]),
                NativeEndian::read_u64(&seed[8..16]),
            )
        };

        Self {
            // file,
            _flags: PLI_PROTECTION,
            // star_fixup: 0,
            length: 0,
            _version: 0,
            _license_code: 0,
            last_block: [0; 8],
            state: [0; 7 * 8 + 4],
            buffer: [0; 0x30],

            #[cfg(feature = "random")]
            prng: PCG32::seed(seed.0, seed.1),
        }
    }

    /// Write the protected prologue.
    fn _vcs_sp_encode_on(&mut self) -> Vec<u8> {
        if self._flags != _ENCODING {
            return Vec::new();
        }

        self._vcs_sp_write_string(b"`protected\n");

        // Eh? Why?
        // self.flags |= ENCODING;

        #[cfg(feature = "random")]
        {
            // Fill buffer with random bytes
            for b in self.buffer.iter_mut() {
                *b = (Self::manhattan(&mut self.prng) & 0xff) as u8;
            }
        }
        self.length = 0x30;

        // Copy randomized buffer to last_block
        self.last_block[..].copy_from_slice(&self.buffer[0x08..0x10]);

        // Copy randomized buffer to state
        // AKA key expansion
        for j in 0..4 {
            let j = j * 15;
            self.state[j..j + 15].copy_from_slice(&self.buffer[0x10..0x1f]);
        }

        // Put a header into the buffer
        let magic = if self._version == 0 {
            JDROCKS.0
        } else {
            JDROCKS.1
        };

        self.buffer[0..3].copy_from_slice(magic);
        self.buffer[3] = b'G';
        self.buffer[4] = if self._flags & PLI_PROTECTION == PLI_PROTECTION {
            1
        } else {
            0
        };
        LittleEndian::write_u32(&mut self.buffer[0x1f..0x1f + 4], self._license_code);

        // Encipher
        Self::dewars_rocks(&self.state, &mut self.buffer[0..8]);
        Self::dewars_rocks(&self.state, &mut self.buffer[0x1f..0x1f + 8]);

        // Encode and write
        Self::_slo_gin_fizz(&self.buffer, self.length as usize)
    }

    /// Write the protected epilogue.
    fn _vcs_sp_encode_off(&mut self) -> Vec<u8> {
        if self._flags == _ENCODING {
            return Vec::new();
        }

        // Encipher, encode, and write
        if self.length > 0 {
            self._encipher();
        }
        Self::_slo_gin_fizz(&self.buffer, self.length as usize);

        self._flags &= !PLI_PROTECTION;

        self._vcs_sp_write_string(b"$\n`endprotected\n")
    }

    /// Returns plain text or cipher text string
    fn _vcs_sp_write_string(&mut self, s: &[u8]) -> Vec<u8> {
        if self._flags == _ENCODING {
            // Write plain text
            // self.file.write(s)?;

            return Vec::from(s);
        }

        // Cocktail cipher here!
        self.buffer.copy_from_slice(&s[..0x30]);

        // Encipher, encode, and write
        self._encipher();
        Self::_slo_gin_fizz(&self.buffer, self.length as usize)
    }

    /// Encrypt a block operating in CBC mode.
    /// This is common code extracted from `_vcs_sp_sncode_off` and `_vcs_sp_write_string`.
    /// Likely inlined.
    fn _encipher(&mut self) {
        for p in 0..Self::pad_length(self.length as usize, 8) / 8 {
            let p = p * 8;

            for (i, b) in self.last_block.iter().enumerate() {
                self.buffer[p + i] ^= b;
            }

            Self::dewars_rocks(&self.state, &mut self.buffer[p..p + 8]);

            // Update last_block
            self.last_block.copy_from_slice(&self.buffer[p..p + 8]);
        }
    }

    /// Decrypt a block operating in CBC mode.
    /// Reciprocal function to encipher.
    pub(crate) fn decipher(&mut self) {
        let mut last_block = [0; 8];

        for p in 0..Self::pad_length(self.length as usize, 8) / 8 {
            let p = p * 8;

            // Update last_block
            last_block.copy_from_slice(&self.last_block);
            self.last_block.copy_from_slice(&self.buffer[p..p + 8]);

            Self::dewars_rocks(&self.state, &mut self.buffer[p..p + 8]);

            for (i, b) in last_block.iter().enumerate() {
                self.buffer[p + i] ^= b;
            }
        }
    }

    /// Mixes a large 60-bit cipher state with a 64-bit block output using the `MARTINI` S-box.
    /// This is the NEWDES `encrypt` function.
    fn dewars_rocks(state: &[u8; 7 * 8 + 4], buffer: &mut [u8]) {
        for i in 0..8 {
            let i = i * 7;
            buffer[4] ^= MARTINI[(buffer[0] ^ state[i]) as usize];
            buffer[5] ^= MARTINI[(buffer[1] ^ state[i + 1]) as usize];
            buffer[6] ^= MARTINI[(buffer[2] ^ state[i + 2]) as usize];
            buffer[7] ^= MARTINI[(buffer[3] ^ state[i + 3]) as usize];
            buffer[1] ^= MARTINI[(buffer[4] ^ state[i + 4]) as usize];
            buffer[2] ^= MARTINI[(buffer[4] ^ buffer[5]) as usize];
            buffer[3] ^= MARTINI[(buffer[6] ^ state[i + 5]) as usize];
            buffer[0] ^= MARTINI[(buffer[7] ^ state[i + 6]) as usize];
        }

        buffer[4] ^= MARTINI[(buffer[0] ^ state[7 * 8]) as usize];
        buffer[5] ^= MARTINI[(buffer[1] ^ state[7 * 8 + 1]) as usize];
        buffer[6] ^= MARTINI[(buffer[2] ^ state[7 * 8 + 2]) as usize];
        buffer[7] ^= MARTINI[(buffer[3] ^ state[7 * 8 + 3]) as usize];
    }

    /// Pad the provided length to the next multiple of `n`.
    fn pad_length(length: usize, n: u8) -> usize {
        let n = n as f64;
        ((length as f64 / n).ceil() * n) as usize
    }

    /// Encode cipher text block.
    /// sic: Sloe gin
    fn _slo_gin_fizz(buffer: &[u8], in_length: usize) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&buffer);

        // Length padding
        let (padded_length, length_adjusted) = {
            if in_length != 0x30 {
                let padded_length = Self::pad_length(in_length, 8);

                (Self::pad_length(padded_length, 3), true)
            } else {
                (in_length, false)
            }
        };

        for _ in 0..padded_length - in_length {
            input.push(0);
        }

        // Encode the input with a weird base-64 variant
        let mut output = Vec::new();
        for i in 0..padded_length / 3 {
            let i = i * 3;
            let first = input[i];
            let second = input[i + 1];
            let third = input[i + 2];

            output.push((((first & 0xc0) >> 2) + ((second & 0xc0) >> 4) + (third >> 6)) + 0x28);
            output.push((first & 0x3f) + 0x28);
            output.push((second & 0x3f) + 0x28);
            output.push((third & 0x3f) + 0x28);
        }

        // Replace '`' with '#' and '*' with '&'
        for b in output.iter_mut() {
            if *b == b'`' {
                *b = b'#';
            } else if *b == b'*' {
                *b = b'&';
            }
        }

        // Output the line trailer
        if length_adjusted {
            // This is an interesting case!
            output.push((in_length & 0xff) as u8 + 0x28);

            let length = output.len();
            if output[length - 1] == b'*' && output[length - 2] == b'/' {
                output[length - 1] = b'&';
                // self.star_fixup += 1;
            }
        } else {
            output.push(b'\n');
        }

        // self.file.write(&output[..o + 1])?;

        output
    }

    /// Decode cipher text block.
    /// Return the decoded cipher text, length, and a bool indicating there are more blocks.
    pub(crate) fn vodka_twist(buffer: &[u8], mut in_length: usize) -> (Vec<u8>, usize, bool) {
        let mut input = Vec::new();
        input.extend_from_slice(&buffer);

        // Strip trailers
        if input[in_length - 1] == b'\n' {
            in_length -= 1;
        }
        if input[in_length - 1] == b'\r' {
            in_length -= 1;
        }

        let (out_length, more) = if input[in_length - 1] == b'$' {
            in_length -= 2;

            // This is that weird `star_fixup` thing again...
            if input[in_length] == b'&' {
                input[in_length] = b'*';
            }

            (input[in_length] as usize - 0x28, false)
        } else {
            (0x30, true)
        };

        // Replace '#' with '`' and '&' with '*'
        for b in input[0..in_length].iter_mut() {
            if *b == b'#' {
                *b = b'`';
            } else if *b == b'&' {
                *b = b'*';
            }
        }

        let mut output = Vec::new();
        for i in 0..in_length / 4 {
            let i = i * 4;
            let temp = input[i] - 0x28;
            output.push(((temp & 0x30) << 2) + (input[i + 1] - 0x28));
            output.push(((temp & 0x0c) << 4) + (input[i + 2] - 0x28));
            output.push((temp << 6) + (input[i + 3] - 0x28));
        }

        (output, out_length, more)
    }

    /// Get initialization vector
    pub(crate) fn get_iv(state: &mut [u8; 7 * 8 + 4], buffer: &[u8]) {
        // Shuffle the state in from decoded block
        // cycles:
        // 0xb, 0xc, 0xd, 0xe, 0x8, (0x9, 0xa),
        // 0x4, 0x5, 0x6, 0x7, 0x1, (0x2, 0x3),
        // 0xc, 0xd, 0xe, 0x0, 0x9, (0xa, 0xb),
        // 0x5, 0x6, 0x7, 0x8, 0x2, (0x3, 0x4),
        // 0xd, 0xe, 0x0, 0x1, 0xa, (0xb, 0xc),
        // 0x6, 0x7, 0x8, 0x9, 0x3, (0x4, 0x5),
        // 0xe, 0x0, 0x1, 0x2, 0xb, (0xc, 0xd),
        // 0x7, 0x8, 0x9, 0xa, 0x4, (0x5, 0x6),
        // 0x0, 0x1, 0x2, 0x3, [DONE]
        let mut i = 0xb;
        for o in 0..(state.len() / 7) + 1 {
            let o = o * 7;

            state[o] = buffer[0x10 + i];
            i += 1;
            if i == 0xf {
                i = 0x0;
            }

            state[o + 1] = buffer[0x10 + i];
            i += 1;
            if i == 0xf {
                i = 0x0;
            }

            state[o + 2] = buffer[0x10 + i];
            i += 1;
            if i == 0xf {
                i = 0x0;
            }

            state[o + 3] = buffer[0x10 + i];
            i = (i + 0x9) % 0xf;
            if i != 0xc {
                state[o + 4] = buffer[0x10 + i];
                state[o + 5] = buffer[0x11 + i];
                state[o + 6] = buffer[0x12 + i];

                i = (i + 0xb) % 0xf;
            }
        }
    }

    pub(crate) fn sp_mercury(&mut self, s: &[u8]) {
        let (mut decoded, length, _more) = VCS::vodka_twist(&s[..], s.len());

        VCS::get_iv(&mut self.state, &decoded);

        // Decipher
        VCS::dewars_rocks(&self.state, &mut decoded[0..8]);
        VCS::dewars_rocks(&self.state, &mut decoded[0x1f..0x1f + 8]);

        self.buffer.copy_from_slice(&decoded[..length]);
    }

    /// PRNG
    #[cfg(feature = "random")]
    fn manhattan(prng: &mut PCG32) -> u32 {
        prng.next_u32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dewars_rocks() {
        let state = [0; 7 * 8 + 4];
        let mut buffer = [0; 8];

        // Assert that S-boxes have scrambled the buffer
        VCS::dewars_rocks(&state, &mut buffer);
        assert_ne!(buffer, [0; 8]);

        // Assert that the buffer has been unscrambled
        VCS::dewars_rocks(&state, &mut buffer);
        assert_eq!(buffer, [0; 8]);
    }

    #[test]
    fn test_vodka_twist_and_slo_gin_fizz() {
        // Test full block
        let buffer = br",D,X&[[LHUW^=RRM8W^](^+H8,fb(UA;)VN4I(1+D,(A.IU1+fKA)SQ\,LYe=:dL";

        #[rustfmt::skip]
        let expected = [
            0x1c, 0x44, 0x30, 0x33, 0x33, 0xa4, 0xad, 0x2f,
            0x36, 0x6a, 0x6a, 0x65, 0x6f, 0x36, 0x35, 0x36,
            0x03, 0x20, 0x44, 0x3e, 0x3a, 0x2d, 0x19, 0x13,
            0x2e, 0x26, 0x4c, 0x80, 0x09, 0x43, 0x44, 0xc0,
            0x19, 0x21, 0x6d, 0x89, 0x3e, 0x23, 0xd9, 0x2b,
            0x29, 0x74, 0x24, 0x71, 0x3d, 0x52, 0x7c, 0x64,
        ];

        let (decoded, length, more) = VCS::vodka_twist(&buffer[..], buffer.len());
        assert_eq!(&decoded[..], &expected[..]);
        assert_eq!(length, decoded.len());
        assert_eq!(more, true);

        let encoded = VCS::_slo_gin_fizz(&decoded[..], decoded.len());
        assert_eq!(&encoded[..encoded.len() - 1], &buffer[..]);
        assert_eq!(encoded[encoded.len() - 1], b'\n');

        // Test final block
        let buffer = br"FS3:g3\W#&ZF/$";
        let expected = [0x6b, 0xcb, 0x92, 0xcb, 0xf4, 0xef, 0xc2, 0xb2, 0x1e];

        let (decoded, length, more) = VCS::vodka_twist(&buffer[..], buffer.len());
        assert_eq!(&decoded[..], &expected[..]);
        assert_eq!(length, 7);
        assert_eq!(more, false);

        let encoded = VCS::_slo_gin_fizz(&decoded[..], length);
        assert_eq!(&encoded[..], &buffer[..buffer.len() - 1]);
    }
}
