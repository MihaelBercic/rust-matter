///
/// @author Mihael Berčič
/// @date 21. 9. 24
///

pub mod device;
pub mod information_blocks;
pub mod cluster;
pub mod endpoint;
pub mod endpoint_builder;
pub mod device_builder;
pub mod enums;

use crate::log_info;
use crate::network::network_message::NetworkMessage;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::interaction::enums::InteractionProtocolOpcode;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::session::protocol_message::ProtocolMessage;
use crate::tlv::element_type::ElementType::{Array, Structure};
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, MatterError};
use std::io::Cursor;

pub fn process_interaction_model(matter_message: MatterMessage, protocol_message: ProtocolMessage) -> Result<NetworkMessage, MatterError> {
    let opcode = InteractionProtocolOpcode::from(protocol_message.opcode);
    let tlv = TLV::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    match opcode {
        InteractionProtocolOpcode::ReadRequest => {
            let Structure(children) = tlv.control.element_type else {
                return Err(generic_error("Incorrect TLV type..."));
            };

            for child in children {
                let Some(Short(tag_number)) = child.tag.tag_number else {
                    return Err(generic_error("Incorrect tag number..."));
                };
                match tag_number {
                    0 => {                                                      // 0 = Attribute Read
                        log_info!("Reading attribute requests!");
                        let Array(children) = child.control.element_type else {
                            return Err(generic_error("Incorrect Array of Attribute..."));
                        };

                        for child in children {
                            let attribute_path = AttributePath::try_from(child)?;

                            dbg!(attribute_path);
                        }
                    }
                    _ => {}
                }
            }


            Err(generic_error("Not yet implemented"))
        }
        _ => todo!("Not implemented yet {:?}", opcode)
    }
}