pub struct SmallFloat {
    value: u32,
}

impl SmallFloat {
    const MANTISSA_BITS: u32 = 3;
    const MANTISSA_VALUE: u32 = 1 << Self::MANTISSA_BITS;
    const MANTISSA_MASK: u32 = Self::MANTISSA_VALUE - 1;

    pub fn from_u32_raw(value: u32) -> Self {
        Self { value }
    }

    // Bin sizes follow floating point (exponent + mantissa) distribution (piecewise linear log approx)
    // This ensures that for each size class, the average overhead percentage stays the same
    fn from_u32(size: u32, round_up: bool) -> Self {
        let mut exp = 0;
        let mut mantissa;

        if size < Self::MANTISSA_VALUE {
            // Denorm: 0..(MANTISSA_VALUE-1)
            mantissa = size;
        } else {
            // Normalized: Hidden high bit always 1. Not stored. Just like float.
            let leading_zeros = size.leading_zeros();
            let highest_set_bit = 31 - leading_zeros;

            let mantissa_start_bit = highest_set_bit - Self::MANTISSA_BITS;
            exp = mantissa_start_bit + 1;
            mantissa = (size >> mantissa_start_bit) & Self::MANTISSA_MASK;

            if round_up {
                let low_bits_mask = (1 << mantissa_start_bit) - 1;

                if (size & low_bits_mask) != 0 {
                    mantissa += 1;
                }
            }
        }

        let value = if round_up {
            (exp << Self::MANTISSA_BITS) + mantissa // + allows mantissa->exp overflow for round up
        } else {
            (exp << Self::MANTISSA_BITS) | mantissa
        };

        Self { value }
    }

    pub fn from_u32_round_up(size: u32) -> Self {
        Self::from_u32(size, true)
    }

    pub fn from_u32_round_down(size: u32) -> Self {
        Self::from_u32(size, false)
    }

    pub fn raw_value(&self) -> u32 {
        self.value
    }
}

impl Into<u32> for SmallFloat {
    fn into(self) -> u32 {
        let exponent = self.value >> Self::MANTISSA_BITS;
        let mantissa = self.value & Self::MANTISSA_MASK;

        if exponent == 0 {
            // Denorms
            mantissa
        } else {
            (mantissa | Self::MANTISSA_VALUE) << (exponent - 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_to_float() {
        // Denorms, exp=1 and exp=2 + mantissa = 0 are all precise.
        // NOTE: Assuming 8 value (3 bit) mantissa.
        // If this test fails, please change this assumption!
        let precise_number_count = 17;
        for i in 0..precise_number_count {
            let round_up = SmallFloat::from_u32_round_up(i);
            let round_down = SmallFloat::from_u32_round_down(i);
            assert_eq!(i, round_up.raw_value());
            assert_eq!(i, round_down.raw_value());
        }

        // Test some random picked numbers
        struct NumberFloatUpDown {
            number: u32,
            up: u32,
            down: u32,
        }

        let test_data: [NumberFloatUpDown; 6] = [
            NumberFloatUpDown {
                number: 17,
                up: 17,
                down: 16,
            },
            NumberFloatUpDown {
                number: 118,
                up: 39,
                down: 38,
            },
            NumberFloatUpDown {
                number: 1024,
                up: 64,
                down: 64,
            },
            NumberFloatUpDown {
                number: 65536,
                up: 112,
                down: 112,
            },
            NumberFloatUpDown {
                number: 529445,
                up: 137,
                down: 136,
            },
            NumberFloatUpDown {
                number: 1048575,
                up: 144,
                down: 143,
            },
        ];

        for expectation in test_data {
            let round_up = SmallFloat::from_u32_round_up(expectation.number);
            let round_down = SmallFloat::from_u32_round_down(expectation.number);
            assert_eq!(expectation.up, round_up.raw_value());
            assert_eq!(expectation.down, round_down.raw_value());
        }
    }

    #[test]
    fn float_to_uint() {
        // Denorms, exp=1 and exp=2 + mantissa = 0 are all precise.
        // NOTE: Assuming 8 value (3 bit) mantissa.
        // If this test fails, please change this assumption!
        let precise_number_count: u32 = 17;
        for i in 0..precise_number_count {
            let f = SmallFloat::from_u32_raw(i);
            assert_eq!(i, f.into());
        }

        // Test that float->uint->float conversion is precise for all numbers
        // NOTE: Test values < 240. 240->4G = overflows 32 bit integer
        for i in 0..240 {
            let f = SmallFloat::from_u32_raw(i);
            let v = f.into();
            let round_up = SmallFloat::from_u32_round_up(v);
            let round_down = SmallFloat::from_u32_round_down(v);
            assert_eq!(i, round_up.raw_value());
            assert_eq!(i, round_down.raw_value());
            //if ((i%8) == 0) printf("\n");
            //printf("%u->%u ", i, v);
        }
    }
}
