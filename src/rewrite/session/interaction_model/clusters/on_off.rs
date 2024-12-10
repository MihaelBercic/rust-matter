use crate::{
    rewrite::{
        protocol_message::protocol_message::ProtocolMessage,
        session::interaction_model::{
            cluster_implementation::ClusterImplementation,
            enums::{QueryParameter::*, StartUpOnOffEnum},
            information_blocks::attribute::{self, Attribute, AttributeReport},
        },
    },
    session::{protocol::interaction::information_blocks::AttributePath, Device},
    tlv::{
        element_type::ElementType,
        structs::{self, StatusReport},
    },
};
use std::any::Any;

pub struct OnOffCluster {
    pub(crate) is_on: Attribute<0, bool>,
    pub(crate) global_scene_control: Attribute<0x4000, bool>,
    pub(crate) on_time: Attribute<0x4001, u16>,
    pub(crate) off_wait_time: Attribute<0x4002, u16>,
    pub(crate) start_up_on_off: Attribute<0x4003, StartUpOnOffEnum>,
}

impl ClusterImplementation for OnOffCluster {
    fn read_attribute(&self, path: &attribute::AttributePath) -> Vec<AttributeReport> {
        match path.attribute_id {
            Wildcard => vec![
                self.is_on.clone().into(),
                self.global_scene_control.clone().into(),
                self.on_time.clone().into(),
                self.off_wait_time.clone().into(),
                self.start_up_on_off.clone().into(),
            ],
            Specific(id) => vec![match id {
                0 => self.is_on.clone().into(),
                0x4000 => self.global_scene_control.clone().into(),
                0x4001 => self.on_time.clone().into(),
                0x4002 => self.off_wait_time.clone().into(),
                0x4003 => self.start_up_on_off.clone().into(),
                _ => todo!(),
            }],
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl Default for OnOffCluster {
    fn default() -> Self {
        Self {
            is_on: false.into(),
            global_scene_control: true.into(),
            on_time: 0.into(),
            off_wait_time: 0.into(),
            start_up_on_off: StartUpOnOffEnum::Off.into(),
        }
    }
}
