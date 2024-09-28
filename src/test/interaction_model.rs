use crate::log_debug;
use crate::session::protocol::interaction::cluster::{BasicInformationCluster, ClusterImplementation};
use crate::session::protocol::interaction::device_builder::DeviceBuilder;
use crate::session::protocol::interaction::endpoint_builder::EndpointBuilder;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::AttributePath;

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
#[test]
pub fn test_interaction_model() {
    let basic_information = BasicInformationCluster {
        data_model_revision: Attribute { id: 0, value: 1 },
        vendor_name: Attribute { id: 0, value: "Mihael Berčič".to_string() },
        vendor_id: Attribute { id: 0, value: 0xFFF1 },
        product_id: Attribute { id: 0, value: 0x8000 },
        product_name: Attribute { id: 0, value: "New Thermo".to_string() },
        node_label: Attribute { id: 0, value: "New Thermo".to_string() },
        location: Attribute { id: 0, value: "Living Room".to_string() },
        hardware_version: Attribute { id: 0, value: 1 },
        hardware_version_string: Attribute { id: 0, value: "".to_string() },
        software_version: Attribute { id: 0, value: 1 },
        software_version_string: Attribute { id: 0, value: "".to_string() },
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
    let mut device = DeviceBuilder::new()
        .add_endpoint(endpoint)
        .build();
    let path = AttributePath {
        enable_tag_compression: false,
        node_id: QueryParameter::Wildcard,
        endpoint_id: QueryParameter::Wildcard,
        cluster_id: QueryParameter::Wildcard,
        attribute_id: QueryParameter::Wildcard,
        list_index: None,
    };

    let reports = device.read_attributes(path);
    log_debug!("Results {}", reports.len());
    dbg!(reports);
}

struct TestCluster {
    id: u32,
    is_on: Attribute<bool>,
    name: Attribute<String>,
    version: Option<Attribute<String>>,
}

impl ClusterImplementation for TestCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        let mut vector: Vec<AttributeReport> = match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                vec![
                    self.is_on.clone().into(),
                    self.name.clone().into(),
                    self.version.clone().into()
                ]
            }
            QueryParameter::Specific(id) => {
                vec![self.is_on.clone().into()]
            }
        };
        for report in &mut vector {
            report.set_cluster_id(self.id);
        }
        vector
    }
}