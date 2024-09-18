#![allow(unused)]

use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{BooleanFalse, BooleanTrue, Structure, Unsigned16, Unsigned32};
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::tlv::{create_advanced_tlv, create_tlv, tlv_octet_string, tlv_unsigned};
use crate::utils::MatterError;
use crate::utils::MatterLayer::Application;
use byteorder::{LittleEndian, WriteBytesExt, LE};
use p256::pkcs8::der::Writer;

///
/// @author Mihael Berčič
/// @date 31. 7. 24
///
#[derive(Debug, Clone)]
pub struct PBKDFParamRequest {
    pub initiator_random: Vec<u8>, // 32B
    pub initiator_session_id: u16, // range 16 bits vs length 16 bits?
    pub passcode_id: u16,
    pub has_params: bool,
    pub initiator_session_parameters: Option<SessionParameter>,
}

impl PBKDFParamRequest {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(&self.initiator_random);
        vec.write_u16::<LittleEndian>(self.initiator_session_id);
        vec.write_u16::<LittleEndian>(self.passcode_id);
        vec.write_byte(self.has_params as u8);
        vec
    }
}

impl TryFrom<TLV> for PBKDFParamRequest {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        let mut initiator_random = vec![];
        let mut initiator_session_id: u16 = 0;
        let mut passcode_id: u16 = 0;
        let mut has_params: bool = false;
        let mut initiator_session_parameters: Option<SessionParameter> = None;
        if let Structure(children) = value.control.element_type {
            for child in children {
                if let Some(Short(tag)) = child.tag.tag_number {
                    match tag {
                        1..=4 => {
                            let element_type = child.control.element_type.clone();
                            match tag {
                                1 => initiator_random.extend_from_slice(&element_type.into_octet_string()?),
                                2 => initiator_session_id = element_type.into_u16()?,
                                3 => passcode_id = element_type.into_u16()?,
                                _ => has_params = element_type.into_boolean()?,
                            }
                        }
                        5 => initiator_session_parameters = Some(SessionParameter::try_from(child)?),
                        _ => return Err(MatterError::new(Application, &format!("Unknown Element Type: {:?}", child)))
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
        Err(MatterError::new(Application, "TLV is not a structure!"))
    }
}

impl Into<TLV> for PBKDFParamRequest {
    fn into(self) -> TLV {
        let mut children = vec![
            create_advanced_tlv(tlv_octet_string(&self.initiator_random), ContextSpecific8, Some(Short(1)), None, None),
            create_advanced_tlv(tlv_unsigned(self.initiator_session_id), ContextSpecific8, Some(Short(2)), None, None),
            create_advanced_tlv(tlv_unsigned(self.passcode_id), ContextSpecific8, Some(Short(3)), None, None),
            create_advanced_tlv(if self.has_params { BooleanTrue } else { BooleanFalse }, ContextSpecific8, Some(Short(4)), None, None),
        ];
        if let Some(params) = self.initiator_session_parameters {
            let mut tlv: TLV = params.into();
            tlv.tag.tag_number = Some(Short(5));
            tlv.control.tag_control = ContextSpecific8;
            children.push(tlv);
        }
        create_tlv(
            Structure(children)
        )
    }
}


#[derive(Debug, Clone)]
pub struct SessionParameter {
    session_idle_interval: Option<u32>,
    session_active_interval: Option<u32>,
    session_active_threshold: Option<u16>,
}

impl SessionParameter {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        if let Some(idle_interval) = self.session_idle_interval { vec.write_u32::<LE>(idle_interval); }
        if let Some(active_interval) = self.session_active_interval { vec.write_u32::<LE>(active_interval); }
        if let Some(active_threshold) = self.session_active_threshold { vec.write_u16::<LE>(active_threshold); }
        vec
    }
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