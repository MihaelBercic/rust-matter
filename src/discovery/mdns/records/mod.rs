use std::collections::HashMap;

pub mod aaaa_record;
pub mod ptr_record;
pub mod srv_record;
pub mod txt_record;
pub mod record_type;


pub struct SRVRecord {
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

pub struct TXTRecord {
    pub map: HashMap<String, String>,
}

pub struct PTRRecord {
    pub domain: String,
}


#[derive(Debug)]
pub struct AAAARecord {
    pub address: String,
}