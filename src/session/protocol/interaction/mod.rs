///
/// @author Mihael Berčič
/// @date 21. 9. 24
///
pub mod cluster;
pub mod enums;
pub mod information_blocks;

use crate::mdns::enums::DeviceType;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::interaction::enums::InteractionProtocolOpcode;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData};
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::protocol_id::ProtocolID::ProtocolInteractionModel;
use crate::session::protocol_message::ProtocolMessage;
use crate::session::session::Session;
use crate::tlv::element_type::ElementType::{Array, BooleanTrue, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, tlv_error, MatterError};
use crate::{log_debug, log_info, DEVICE};
use std::io::Cursor;

pub fn process_interaction_model(
    matter_message: &MatterMessage,
    protocol_message: ProtocolMessage,
    session: &mut Session,
) -> Result<ProtocolMessageBuilder, MatterError> {
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
                    0 => {
                        // 0 = Attribute Read
                        let requests = parse_attribute_requests(child)?;
                        attribute_requests.extend(requests);
                        log_info!("Reading attribute requests!");
                    }
                    _ => {}
                }
            }
            log_info!("We have {} attribute read requests!", attribute_requests.len());
            let mut reports: Vec<AttributeReport> = vec![];
            if let Ok(guard) = &mut DEVICE.lock() {
                for path in attribute_requests {
                    reports.extend(guard.read_attributes(path))
                }
            }

            log_debug!("We have {} reports to send!", reports.len());
            let mut to_send = vec![];
            for report in reports {
                to_send.push(TLV::simple(report.into()));
            }
            let response = Structure(vec![
                TLV::new(Array(to_send), ContextSpecific8, Tag::simple(Short(1))),
                TLV::new(BooleanTrue, ContextSpecific8, Tag::simple(Short(4))),
            ]);
            let response: Vec<u8> = TLV::simple(response).into();
            let builder = ProtocolMessageBuilder::new()
                .set_protocol(ProtocolInteractionModel)
                .set_needs_acknowledgement(false)
                .set_exchange_id(protocol_message.exchange_id)
                .set_opcode(InteractionProtocolOpcode::ReportData as u8)
                .set_acknowledged_message_counter(matter_message.header.message_counter)
                .set_payload(&response);
            Ok(builder)
        }
        InteractionProtocolOpcode::InvokeRequest => {
            let mut responses = vec![];
            let Structure(children) = tlv.control.element_type else {
                return Err(tlv_error("Incorrect TLV type..."));
            };

            for child in children {
                let Some(Short(tag_number)) = child.tag.tag_number else {
                    return Err(tlv_error("Incorrect tag number..."));
                };
                match tag_number {
                    2 => {
                        let Array(children) = child.control.element_type else {
                            return Err(tlv_error("Incorrect TLV type..."));
                        };
                        let Ok(device) = &mut DEVICE.lock() else {
                            return Err(generic_error("Unable to lock DEVICE!"));
                        };
                        for child in children {
                            let command_data = CommandData::try_from(child)?;
                            responses.extend(device.invoke_command(command_data, session));
                        }
                    }
                    _ => (),
                }
            }
            let mut tlv_responses = vec![];
            for response in responses {
                tlv_responses.push(TLV::simple(response.try_into()?))
            }
            let invoke_response = Structure(vec![
                TLV::new(BooleanTrue, ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(Array(tlv_responses), ContextSpecific8, Tag::simple(Short(1))),
            ]);

            let tlv = TLV::simple(invoke_response);
            let payload = tlv.to_bytes();
            let builder = ProtocolMessageBuilder::new()
                .set_exchange_id(protocol_message.exchange_id)
                .set_acknowledged_message_counter(matter_message.header.message_counter)
                .set_opcode(InteractionProtocolOpcode::InvokeResponse as u8)
                .set_payload(&payload)
                .set_protocol(ProtocolInteractionModel);
            Ok(builder)
        }
        _ => Err(generic_error(&format!("OPCODE: {:?}", opcode))),
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
