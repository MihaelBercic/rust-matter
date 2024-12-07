use crate::{
    rewrite::enums::MatterSessionType::{self, *},
    utils::BitSubset,
};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MatterSecurityFlags {
    pub(crate) flags: u8,
}

impl MatterSecurityFlags {
    /// Indicates whether additional privacy decoding is required.
    pub fn is_encoded_with_privacy(&self) -> bool {
        self.flags.bit_subset(7, 1) == 1
    }

    /// Indicates whether the message is Data or Control message type.
    pub fn is_control_message(&self) -> bool {
        self.flags.bit_subset(6, 1) == 1
    }

    /// Indicator whether the message has message extensions or not.
    pub fn has_message_extensions(&self) -> bool {
        self.flags.bit_subset(5, 1) == 1
    }

    /// Retrieves the session type of the matter message.
    pub fn session_type(&self) -> MatterSessionType {
        match self.flags.bit_subset(0, 2) {
            0 => Unicast,
            1 => Group,
            _ => ReservedForFuture,
        }
    }

    /// Sets the flags indicating whether the message is encoded with Privacy features or not.
    pub fn set_privacy_encoded(&mut self, encoded: bool) -> &mut Self {
        self.flags.set_bits(7..=7, encoded as u8);
        self
    }

    /// Sets the flag indicating whether the message is Control or Data message.
    pub fn set_is_control_message(&mut self, is_control: bool) -> &mut Self {
        self.flags.set_bits(6..=6, is_control as u8);
        self
    }

    /// Sets a flag whether the message contains message extensions or not.
    pub fn set_has_message_extensions(&mut self, has_extensions: bool) -> &mut Self {
        self.flags.set_bits(5..=5, has_extensions as u8);
        self
    }

    /// Sets the session type of the matter message.
    pub fn set_session_type(&mut self, session_type: MatterSessionType) -> &mut Self {
        let value = match session_type {
            Unicast => 0,
            Group => 1,
            ReservedForFuture => 2,
        };
        self.flags.set_bits(0..=2, value);
        self
    }
}
