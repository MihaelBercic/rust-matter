use crate::session::protocol::interaction::device::{DeviceBuilder, OnOffCluster};
use crate::session::protocol::interaction::endpoint::{ClusterID, EndpointBuilder};

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
#[test]
pub fn test_interaction_model() {
    let on_off_cluster = OnOffCluster { on_off: true };
    let endpoint = EndpointBuilder::new()
        .add_cluster(ClusterID::OnOffCluster, on_off_cluster)
        .build();
    let device = DeviceBuilder::new()
        .add_endpoint(endpoint)
        .build();
}


