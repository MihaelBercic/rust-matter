use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use std::collections::HashMap;
use std::process::id;

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
pub struct Endpoint {
    pub(crate) clusters: HashMap<ClusterID, Box<dyn ClusterImplementation>>,
}

impl Endpoint {
    pub fn read_attributes(&self, path: AttributePath) -> Vec<AttributeReport> {
        let mut attribute_reports = vec![];
        match path.cluster_id {
            QueryParameter::Wildcard => {
                for (id, endpoint) in &self.clusters {
                    let mut reports = endpoint.read_attributes(path.clone());
                    for report in &mut reports {
                        report.set_cluster_id(id.clone() as u32)
                    }
                    attribute_reports.extend(reports);
                }
            }
            QueryParameter::Specific(cluster_id) => {
                let cluster = ClusterID::try_from(cluster_id).unwrap();
                let Some(cluster) = self.clusters.get(&cluster) else {
                    todo!("Not yet implemented...")
                };
                let mut reports = cluster.read_attributes(path);
                for report in &mut reports {
                    report.set_cluster_id(id.clone() as u32)
                }
                attribute_reports.extend(reports)
            }
        }

        attribute_reports
    }
}


