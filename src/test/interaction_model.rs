use crate::log_debug;
use crate::session::protocol::interaction::cluster::BasicInformationCluster;
use crate::session::protocol::interaction::device_builder::DeviceBuilder;
use crate::session::protocol::interaction::endpoint_builder::EndpointBuilder;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::AttributePath;

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
#[test]
pub fn test_interaction_model() {
    let basic_information = BasicInformationCluster {
        data_model_revision: 1,
        vendor_name: "Mihael Berčič".to_string(),
        vendor_id: 0xFFF1,
        product_id: 0x8000,
        product_name: "New Thermo".to_string(),
        node_label: "New Thermo".to_string(),
        location: "Living Room".to_string(),
        hardware_version: 1,
        hardware_version_string: "".to_string(),
        software_version: 1,
        software_version_string: "".to_string(),
        manufacturing_date: None,
        part_number: None,
        product_url: None,
        product_label: None,
        serial_number: None,
        local_config_disabled: None,
        reachable: None,
        unique_id: None,
        product_appearance: None,
        capability_minima: Default::default(),
    };
    let endpoint = EndpointBuilder::new()
        .add_cluster(ClusterID::BasicInformation, basic_information)
        .build();
    let device = DeviceBuilder::new()
        .add_endpoint(endpoint)
        .build();
    let path = AttributePath {
        enable_tag_compression: false,
        node_id: QueryParameter::Wildcard,
        endpoint_id: QueryParameter::Wildcard,
        cluster_id: QueryParameter::Wildcard,
        attribute_id: QueryParameter::Specific(0),
        list_index: None,
    };
    let results = device.read_attributes(path);
    log_debug!("Results {}", results.len())
}


