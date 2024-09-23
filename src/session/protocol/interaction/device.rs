use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 22. 9. 24
///
#[derive(Clone, Debug)]
pub enum QueryParameter<T> {
    Wildcard,
    Specific(T),
}

pub trait ClusterImplementation {
    fn read_attribute(&self, attribute_path: AttributePath) -> TLV;
    // fn write_attribute(attribute_path: AttributePath, value: TLV);
    // fn invoke_command(command_path: CommandPath);
}


pub struct OnOffCluster {
    on_off: bool,
}
