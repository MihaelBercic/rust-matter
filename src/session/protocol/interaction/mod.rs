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

use crate::network::network_message::NetworkMessage;
use crate::session::counters::GLOBAL_UNENCRYPTED_COUNTER;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::interaction::enums::{InteractionProtocolOpcode, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::protocol_id::ProtocolID::ProtocolInteractionModel;
use crate::session::protocol_message::ProtocolMessage;
use crate::tlv::element_type::ElementType::{Array, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, MatterError};
use crate::{build_network_message_no_destination, log_debug, log_info, DEVICE, ENCRYPTED_SESSIONS};
use std::io::Cursor;

pub fn process_interaction_model(matter_message: MatterMessage, protocol_message: ProtocolMessage) -> Result<NetworkMessage, MatterError> {
    let Ok(session_map) = &mut ENCRYPTED_SESSIONS.lock() else {
        return Err(generic_error("Unable to lock ENCRYPTED_SESSIONS"));
    };
    let Some(session) = session_map.get_mut(&matter_message.header.session_id) else {
        return Err(generic_error("No session found"));
    };
    let opcode = InteractionProtocolOpcode::from(protocol_message.opcode);
    let tlv = TLV::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    match opcode {
        InteractionProtocolOpcode::ReadRequest => {
            let Structure(children) = tlv.control.element_type else {
                return Err(generic_error("Incorrect TLV type..."));
            };
            let mut attribute_requests: Vec<AttributePath> = vec![];
            for child in children {
                let Some(Short(tag_number)) = child.tag.tag_number else {
                    return Err(generic_error("Incorrect tag number..."));
                };
                match tag_number {
                    0 => {           // 0 = Attribute Read
                        let requests = parse_attribute_requests(child)?;
                        attribute_requests.extend(requests);
                        log_info!("Reading attribute requests!");
                    }
                    _ => {}
                }
            }
            log_info!("We have {} attribute read requests!", attribute_requests.len());
            let mut reports: Vec<AttributeReport> = vec![];
            for path in attribute_requests {
                if let Ok(mut mutex) = DEVICE.try_lock() {
                    match path.node_id {
                        QueryParameter::Wildcard => {
                            for x in mutex.values() {
                                let mut to_add = x.read_attributes(path.clone());
                                for a in &mut to_add {
                                    a.set_node_id(0)
                                }
                                reports.extend(to_add);
                            }
                        }
                        QueryParameter::Specific(device_id) => {
                            if let Some(device) = mutex.get_mut(&device_id) {
                                reports.extend(device.read_attributes(path.clone()));
                            }
                        }
                    }
                }
            }
            log_debug!("We have {} reports to send!", reports.len());

            let mut to_send = vec![];
            for report in reports {
                to_send.push(TLV::simple(report.into()));
            }
            let response = Structure(vec![
                TLV::new(Array(to_send), ContextSpecific8, Tag::simple(Short(1)))
            ]);
            let response: Vec<u8> = TLV::simple(response).into();
            let protocol_message = ProtocolMessageBuilder::new()
                .set_protocol(ProtocolInteractionModel)
                .set_opcode(InteractionProtocolOpcode::ReportData as u8)
                .set_acknowledged_message_counter(matter_message.header.message_counter)
                .set_payload(&response)
                .build();
            return Ok(build_network_message_no_destination(protocol_message, &GLOBAL_UNENCRYPTED_COUNTER));
            Err(generic_error("Not yet implemented"))
        }
        _ => todo!("Not implemented yet {:?}", opcode)
    }
}

fn parse_attribute_requests(tlv: TLV) -> Result<Vec<AttributePath>, MatterError> {
    let mut paths = Vec::new();
    let Array(children) = tlv.control.element_type else {
        return Err(generic_error("Incorrect Array of Attribute..."));
    };

    for child in children {
        paths.push(AttributePath::try_from(child)?);
    }
    Ok(paths)
}