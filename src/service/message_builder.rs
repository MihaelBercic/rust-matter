use crate::service::enums::{MatterDestinationID, MatterDestinationType, MatterSessionType};
use crate::service::enums::MatterDestinationType::{GroupID, NodeID};
use crate::service::message::MatterMessage;
use crate::service::message_extension::MatterMessageExtension;
use crate::service::message_flags::MatterMessageFlags;
use crate::service::message_header::MatterMessageHeader;
use crate::service::security_flags::MatterSecurityFlags;

///
/// @author Mihael Berčič
/// @date 24. 7. 24
///

pub struct MatterMessageBuilder {
    message: MatterMessage,
}

impl MatterMessageBuilder {
    /// Creates a new message builder with an empty, default matter message.
    pub fn new() -> Self {
        return Self {
            message: MatterMessage {
                header: MatterMessageHeader {
                    flags: MatterMessageFlags { flags: 0 },
                    session_id: 0,
                    security_flags: MatterSecurityFlags { flags: 0 },
                    message_counter: 0,
                    source_node_id: None,
                    destination_node_id: None,
                    message_extensions: None,
                },
                payload: vec![],
                integrity_check: vec![],
            },
        };
    }

    pub fn set_source_node_id(mut self, id: u64) -> Self {
        self.message.header.source_node_id = Some(id);
        return self.set_is_source_present(true);
    }

    pub fn set_destination(mut self, destination: MatterDestinationID) -> Self {
        self.message.header.destination_node_id = Some(destination.clone());
        return match destination {
            MatterDestinationID::Group(_) => self.set_type_of_destination(GroupID),
            MatterDestinationID::Node(_) => self.set_type_of_destination(NodeID),
        };
    }

    pub fn set_counter(mut self, counter: u32) -> Self {
        self.message.header.message_counter = counter;
        return self;
    }

    pub fn set_session_id(mut self, session_id: u16) -> Self {
        self.message.header.session_id = session_id;
        return self;
    }

    pub fn set_message_extensions(mut self, data: &[u8]) -> Self {
        let vec: Vec<u8> = data.to_vec();
        self.message.header.message_extensions = Some(MatterMessageExtension { data: vec });
        return self;
    }

    pub fn set_privacy_encoded_flag(mut self, encoded: bool) -> Self {
        self.message.header.security_flags.set_privacy_encoded(encoded);
        return self;
    }

    /// Sets the flags indicating whether the message is encoded with Privacy features or not.
    pub fn set_privacy_encoded(mut self, encoded: bool) -> Self {
        self.message.header.security_flags.set_privacy_encoded(encoded);
        return self;
    }

    /// Sets the flag indicating whether the message is Control or Data message.
    pub fn set_is_control_message(mut self, is_control: bool) -> Self {
        self.message.header.security_flags.set_is_control_message(is_control);
        return self;
    }

    /// Sets a flag whether the message contains message extensions or not.
    pub fn set_has_message_extensions(mut self, has_extensions: bool) -> Self {
        self.message.header.security_flags.set_has_message_extensions(has_extensions);
        return self;
    }

    /// Sets the session type of the matter message.
    pub fn set_session_type(mut self, session_type: MatterSessionType) -> Self {
        self.message.header.security_flags.set_session_type(session_type);
        return self;
    }


    /// ----------------- Message Flags --------------- \\\

    pub fn set_version(mut self, version: u8) -> Self {
        self.message.header.flags.set_version(version);
        return self;
    }

    pub fn set_is_source_present(mut self, is_present: bool) -> Self {
        self.message.header.flags.set_is_source_present(is_present);
        return self;
    }

    fn set_type_of_destination(mut self, destination: MatterDestinationType) -> Self {
        self.message.header.flags.set_type_of_destination(destination);
        return self;
    }


    /// ----------------- Message Flags --------------- \\\



    pub fn set_payload(mut self, payload: &[u8]) -> Self {
        self.message.payload.clear();
        self.message.payload.extend_from_slice(payload);
        // TODO: set integrity checks and stuff
        return self;
    }

    pub fn build(self) -> MatterMessage {
        return self.message;
    }
}