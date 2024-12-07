use crate::rewrite::session::interaction_model::{cluster_implementation::ClusterImplementation, clusters::on_off::OnOffCluster, enums::QueryParameter::*};

#[test]
fn test_on_off_cluster() {
    let on_off = OnOffCluster::default();
    assert_eq!(
        on_off
            .read_attribute(&crate::rewrite::session::interaction_model::information_blocks::attribute::AttributePath {
                enable_tag_compression: false,
                node_id: Wildcard,
                endpoint_id: Wildcard,
                cluster_id: Wildcard,
                attribute_id: Wildcard,
                list_index: None,
            })
            .len(),
        2
    );

    assert_eq!(
        on_off
            .read_attribute(&crate::rewrite::session::interaction_model::information_blocks::attribute::AttributePath {
                enable_tag_compression: false,
                node_id: Wildcard,
                endpoint_id: Wildcard,
                cluster_id: Wildcard,
                attribute_id: Specific(2),
                list_index: None,
            })
            .len(),
        1
    );
}
