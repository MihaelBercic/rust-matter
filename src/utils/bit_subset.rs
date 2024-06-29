use std::ops::RangeInclusive;

///
/// @author Mihael Berčič
/// @date 19. 6. 24
///

/// A trait which allows for individual bit inspection.
pub trait BitSubset {
    fn bit_subset(&self, from_bit: usize, count: u32) -> Self;

    fn set_bits(&mut self, range: RangeInclusive<Self>, value: Self)
    where
        Self: Sized;
}

macro_rules! bit_subset {
    ($($t:ty),* => {$a:item $b:item}) => {
        $(
        impl BitSubset for $t {
            $a
            $b
        }
        )*
    };
}

bit_subset! {
    i8,i16,i32,i64,i128,u8,u16,u32,u64,u128 => {

        /// 
        fn bit_subset(&self, from_bit: usize, count: u32) -> Self {
            let mask = (1 << count) - 1;
            (self >> from_bit) & mask
        }


        /// Set bits (range is inclusive).
        ///
        /// Examples:
        ///
        /// `4..=4` sets the 4th bit.
        ///
        /// `0..=4` sets the bits on 0th, 1st, 2nd, 3rd, 4th index.
        fn set_bits(&mut self, range: RangeInclusive<Self>, value: Self) {
            let _debug_clone = self.clone();
            let bits = Self::BITS as Self;
            let bits_used = range.end() + 1 - range.start();
            let shifted_value = value << range.start();
            let right_mask_shift = bits - range.start();
            let left_mask_shift = bits_used + range.start();
            let left_mask = if left_mask_shift >= bits {0} else {Self::MAX << left_mask_shift};
            let right_mask = if right_mask_shift >= bits {0} else {Self::MAX >> right_mask_shift};
            let mask = left_mask | right_mask;
            *self &= mask;
            *self |= shifted_value;
        }
    }
}