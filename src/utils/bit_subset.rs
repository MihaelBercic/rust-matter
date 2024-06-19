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
        fn bit_subset(&self, from_bit: usize, count: u32) -> Self {
            let mask = (1 << count) - 1;
            (self >> from_bit) & mask
        }


        /// Set bits (range is half inclusive).
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
//             println!("Bits used:      {}/{}
// Self:           {:08b}
// Shifted value:  {:08b}
// Left mask:      {:08b}
// Right mask:     {:08b}
// Self After:     {:08b}
// ", bits_used, bits, _debug_clone, shifted_value, left_mask, right_mask, self);
        }

//         fn set_bits(mut self, from_bit: u32, value: Self) -> Self {
//             let self_debug = self.clone(); // TODO: remove it's for printout...
//             let bits_used = max(Self::BITS - value.leading_zeros(), 1);
//             let shifted_value = value << from_bit;
//             let right_mask_shift = Self::BITS - from_bit;
//             let left_mask_shift = bits_used + from_bit;
//             let right_mask = if right_mask_shift >= Self::BITS {0} else {Self::MAX >> right_mask_shift};
//             let left_mask = if left_mask_shift >= Self::BITS {0} else {Self::MAX << left_mask_shift};
//             let mask = left_mask | right_mask;
//             self &= mask;
//             self |= shifted_value;
//             println!(
// "
// Value:         {:08b} (Used bits {}/{})
// Shifted value: {:08b}
// Right mask:    {:08b}
// Left mask:     {:08b}
// Mask:          {:08b}
// Self before:   {:08b}
// Self after:    {:08b} ({})
//
// ", value, bits_used, Self::BITS, shifted_value, right_mask, left_mask,mask, self_debug, self, self);
//             self
//         }
    }
}