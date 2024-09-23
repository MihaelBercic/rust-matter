mod device;
mod information_blocks;
mod cluster;

use crate::log_info;
use crate::network::network_message::NetworkMessage;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::session::protocol_message::ProtocolMessage;
use crate::tlv::element_type::ElementType::{Array, Structure};
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, MatterError};
use std::io::Cursor;

///
/// @author Mihael Berčič
/// @date 21. 9. 24
///

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum InteractionProtocolOpcode {
    StatusResponse = 0x01,
    ReadRequest = 0x02,
    SubscribeRequest = 0x03,
    SubscribeResponse = 0x04,
    ReportData = 0x05,
    WriteRequest = 0x06,
    WriteResponse = 0x07,
    InvokeRequest = 0x08,
    InvokeResponse = 0x09,
    TimedRequest = 0x0A,
}

impl From<u8> for InteractionProtocolOpcode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => InteractionProtocolOpcode::StatusResponse,
            0x02 => InteractionProtocolOpcode::ReadRequest,
            0x03 => InteractionProtocolOpcode::SubscribeRequest,
            0x04 => InteractionProtocolOpcode::SubscribeResponse,
            0x05 => InteractionProtocolOpcode::ReportData,
            0x06 => InteractionProtocolOpcode::WriteRequest,
            0x07 => InteractionProtocolOpcode::WriteResponse,
            0x08 => InteractionProtocolOpcode::InvokeRequest,
            0x09 => InteractionProtocolOpcode::InvokeResponse,
            0x0A => InteractionProtocolOpcode::TimedRequest,
            _ => panic!("Unknown Interaction Opcode"),
        }
    }
}

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
                    0 => {
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