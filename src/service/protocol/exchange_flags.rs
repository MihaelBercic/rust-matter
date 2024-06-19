use crate::discovery::mdns::structs::BitSubset;

#[derive(Debug)]
pub struct ProtocolExchangeFlags {
    pub byte: u8,
}

impl ProtocolExchangeFlags {
    /// A flag bit indicates whether the message was sent by the initiator.
    pub fn sent_by_initiator(&self) -> bool {
        self.byte.bit_subset(0, 1) == 1
    }

    /// A flag bit indicates whether this message serves as an acknowledgement.
    pub fn is_acknowledgement(&self) -> bool {
        self.byte.bit_subset(1, 1) == 1
    }

    /// A flag bit indicates whether the sender requests for acknowledgment packet.
    pub fn needs_acknowledgement(&self) -> bool {
        self.byte.bit_subset(2, 1) == 1
    }

    /// A flag bit indicates whether secured extensions are present in the packet.
    pub fn is_secured_extensions_present(&self) -> bool {
        self.byte.bit_subset(3, 1) == 1
    }

    /// A flag bit indicates whether vendor information is present in the packet.
    pub fn is_vendor_present(&self) -> bool {
        self.byte.bit_subset(4, 1) == 1
    }
}