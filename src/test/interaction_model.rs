use crate::log_info;
use crate::session::protocol::interaction::cluster::{Device, SampleOnOffCluster};
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::AttributePath;

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
#[test]
pub fn test_interaction_model() {
    let mut device = Device::new();
    device.insert(1, ClusterID::OnOffCluster, SampleOnOffCluster { on_off: Default::default(), supported_commands: vec![] });


    let results = device.read_attributes(AttributePath {
        enable_tag_compression: false,
        node_id: QueryParameter::Wildcard,
        endpoint_id: QueryParameter::Wildcard,
        cluster_id: QueryParameter::Specific(6),
        attribute_id: QueryParameter::Wildcard,
        list_index: None,
    });
    log_info!("{:?}", results);
}