use crate::session::protocol::interaction::device::QueryParameter::Specific;
use crate::session::protocol::interaction::endpoint::Endpoint;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::AttributeReport;
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
    pub fn read_attributes(&self, path: AttributePath) -> Vec<AttributeReport> {
        let mut attribute_reports = vec![];
        let x = &path.endpoint_id;
        match &path.endpoint_id {
            QueryParameter::Wildcard => {
                for (id, endpoint) in &self.endpoints {
                    let read = endpoint.read_attributes(path.clone());
                    for mut x in read {
                        x.data.path.endpoint_id = Specific(*id);
                        attribute_reports.push(x);
                    }
                }
            }
            QueryParameter::Specific(id) => {}
        }
        attribute_reports
    }
}


pub struct OnOffCluster {
    pub on_off: bool,
}