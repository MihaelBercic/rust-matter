#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TagNumber {
    Short(u8),
    Medium(u16),
    Long(u32),
}