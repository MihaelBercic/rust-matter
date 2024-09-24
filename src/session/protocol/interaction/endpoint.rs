use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::AttributeReport;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use std::collections::HashMap;

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
pub struct Endpoint {
    pub(crate) cluster_map: HashMap<ClusterID, Box<dyn ClusterImplementation>>,
}

impl Endpoint {
    pub fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        let mut vec = vec![];
        match attribute_path.cluster_id {
            QueryParameter::Wildcard => {
                for (cluster_id, cluster) in &self.cluster_map {
                    let read = cluster.read_attributes(attribute_path.clone());
                    for mut x in read {
                        x.data.path.cluster_id = Specific(cluster_id.clone() as u32);
                        vec.push(x);
                    }
                }
            }
            QueryParameter::Specific(cluster_id) => {
                let cluster = ClusterID::try_from(cluster_id).unwrap();
                let read = self.cluster_map.get(&cluster).unwrap().read_attributes(attribute_path.clone());
                for mut x in read {
                    x.data.path.cluster_id = Specific(cluster_id);
                    vec.push(x);
                }
            }
        }
        vec
    }
}


