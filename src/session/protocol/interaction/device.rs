use crate::session::protocol::interaction::endpoint::Endpoint;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use std::collections::HashMap;

///
/// @author Mihael Berčič
/// @date 22. 9. 24
///
pub struct Device {
    pub(crate) endpoints: HashMap<u16, Endpoint>,
}

impl Device {
    pub fn read_attributes(&mut self, path: AttributePath) -> Vec<AttributeReport> {
        let mut attribute_reports = vec![];
        match path.endpoint_id {
            QueryParameter::Wildcard => {
                for (id, endpoint) in &self.endpoints {
                    let mut reports = endpoint.read_attributes(path.clone());
                    for report in &mut reports {
                        report.set_endpoint_id(*id);
                    }
                    attribute_reports.extend(reports);
                }
            }
            QueryParameter::Specific(id) => {
                let Some(endpoint) = self.endpoints.get(&id) else {
                    todo!("Not yet implemented...")
                };
                let mut reports = endpoint.read_attributes(path);
                for report in &mut reports {
                    report.set_endpoint_id(id);
                }
                attribute_reports.extend(reports)
            }
        }
        for report in &mut attribute_reports {
            report.set_node_id(0);
        }
        attribute_reports
    }
}


pub struct OnOffCluster {
    pub on_off: bool,
}