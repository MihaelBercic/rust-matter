use crate::Matter;
use crate::service::protocol::structs::ProtocolMessage;
use crate::service::structs::MatterMessage;
use crate::useful::MatterError;

pub trait Transport {
    fn receive(&self, data: &[u8]) -> Result<(), MatterError>;
}

impl Transport for Matter {
    fn receive(&self, data: &[u8]) -> Result<(), MatterError> {
        let matter_message = MatterMessage::try_from(data)?;
        let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
        println!("{:#?}", protocol_message);
        Ok(())
    }
}