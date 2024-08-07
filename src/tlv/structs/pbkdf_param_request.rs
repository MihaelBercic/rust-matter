#![allow(unused)]

use crate::tlv::{create_advanced_tlv, create_tlv};
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Structure, Unsigned16, Unsigned32};
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{MatterError, MatterLayer};
use crate::utils::MatterLayer::Application;

///
/// @author Mihael Berčič
/// @date 31. 7. 24
///
#[derive(Debug)]
pub struct PBKDFParamRequest {
    pub initiator_random: Vec<u8>, // 32B
    pub initiator_session_id: u16, // range 16 bits vs length 16 bits?
    pub passcode_id: u8,
    pub has_params: bool,
    pub initiator_session_parameters: Option<SessionParameter>,
}


impl TryFrom<TLV> for PBKDFParamRequest {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        let mut initiator_random = vec![];
        let mut initiator_session_id: u16 = 0;
        let mut passcode_id: u8 = 0;
        let mut has_params: bool = false;
        let mut initiator_session_parameters: Option<SessionParameter> = None;
        if let ElementType::Structure(children) = value.control.element_type {
            for child in children {
                match child.control.element_type {
                    ElementType::OctetString8(string) if child.tag.tag_number == Some(Short(1)) => {
                        initiator_random.extend(string);
                    }
                    ElementType::Unsigned16(value) if child.tag.tag_number == Some(Short(2)) => {
                        initiator_session_id = value;
                    }
                    ElementType::Unsigned8(value) if child.tag.tag_number == Some(Short(3)) => {
                        passcode_id = value;
                    }
                    ElementType::BooleanTrue if child.tag.tag_number == Some(Short(4)) => {
                        has_params = true;
                    }
                    ElementType::BooleanFalse if child.tag.tag_number == Some(Short(4)) => {
                        has_params = false;
                    }
                    _ if child.tag.tag_number == Some(Short(5)) => {
                        initiator_session_parameters = Some(SessionParameter::try_from(child)?);
                    }
                    _ => {
                        return Err(MatterError::new(Application, &format!("Unknown Element Type: {:?}", child)));
                    }
                }
            }
            return Ok(PBKDFParamRequest {
                initiator_random,
                initiator_session_id,
                passcode_id,
                has_params,
                initiator_session_parameters,
            });
        }
        Err(MatterError::new(MatterLayer::Application, "TLV is not a structure!"))
    }
}


#[derive(Debug, Clone)]
pub struct SessionParameter {
    session_idle_interval: Option<u32>,
    session_active_interval: Option<u32>,
    session_active_threshold: Option<u16>,
}

impl TryFrom<TLV> for SessionParameter {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        let mut session_idle_interval: Option<u32> = None;
        let mut session_active_interval: Option<u32> = None;
        let mut session_active_threshold: Option<u16> = None;
        if let ElementType::Structure(children) = value.control.element_type {
            for child in children {
                match child.tag.tag_number {
                    Some(Short(tag)) => {
                        match tag {
                            1 => session_idle_interval = Some(child.control.element_type.into_u32()?),
                            2 => session_active_interval = Some(child.control.element_type.into_u32()?),
                            3 => session_active_threshold = Some(child.control.element_type.into_u16()?),
                            _ => {}
                        }
                    }
                    _ => return Err(MatterError::new(Application, "Non-short tag not allowed!"))
                }
            }
            return Ok(SessionParameter {
                session_idle_interval,
                session_active_interval,
                session_active_threshold,
            });
        }
        Err(MatterError::new(Application, "Unable to parse SessionParameter from TLV"))
    }
}

impl Into<TLV> for SessionParameter {
    fn into(self) -> TLV {
        let mut children = vec![];
        if let Some(idle_interval) = self.session_idle_interval {
            children.push(create_advanced_tlv(Unsigned32(idle_interval), ContextSpecific8, Some(Short(1)), None, None));
        }
        if let Some(active_interval) = self.session_active_interval {
            children.push(create_advanced_tlv(Unsigned32(active_interval), ContextSpecific8, Some(Short(2)), None, None));
        }
        if let Some(active_threshold) = self.session_active_threshold {
            children.push(create_advanced_tlv(Unsigned16(active_threshold), ContextSpecific8, Some(Short(3)), None, None));
        }
        create_tlv(Structure(children))
    }
}