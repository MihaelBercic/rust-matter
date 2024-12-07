use std::cmp::Ordering;

use super::enums::MessageType;

#[derive(Clone, Debug)]
pub struct MessageReceptionState {
    pub peer_node_id: u64,
    pub message_type: MessageType,
    pub max_counter: u32,
    pub bitmap: u32,
}

impl MessageReceptionState {
    /// Bitmap indicates whether the (max_counter - [message_counter]) ID has been seen.
    /// max-counter - (max-counter - 1) =  1 (first bit)
    /// max-counter - (max-counter - 2) =  2 (second bit)
    pub fn already_seen(&mut self, message_counter: u32) -> bool {
        match message_counter.cmp(&self.max_counter) {
            Ordering::Equal => true,
            Ordering::Greater => {
                let difference = message_counter - self.max_counter;
                self.max_counter = message_counter;
                self.bitmap <<= difference;
                false
            }
            Ordering::Less => {
                let bit_index = self.max_counter - message_counter - 1;
                let is_duplicate = (self.bitmap >> bit_index) & 1 == 1;
                if bit_index >= 32 || is_duplicate {
                    // If outside the window, mark as duplicate.
                    return true;
                }
                self.bitmap |= 2u32.pow(bit_index);
                false
            }
        }
    }

    /// ◦ The Peer Node ID SHALL reference the given Peer Node ID.
    ///
    /// ◦ The Message Type SHALL be the given Message Type.
    ///
    /// ◦ The Encryption Level SHALL be the given Encryption Level.
    ///
    /// ◦ If the Encryption Level is NOT unencrypted, the Encryption Key SHALL reference the given key.
    ///
    /// ◦ The max_message_counter SHALL be set to the given max_message_counter.
    ///
    /// ◦ The Message Counter bitmap SHALL be set to all 1, indicating that only new messages with counter greater than max_message_counter SHALL be accepted.
    pub fn new(peer_node: u64, message_type: MessageType, max_counter: u32) -> MessageReceptionState {
        MessageReceptionState {
            peer_node_id: peer_node,
            message_type,
            max_counter,
            bitmap: u32::MAX,
        }
    }
}
