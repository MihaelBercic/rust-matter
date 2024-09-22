pub mod aaaa_record;
pub mod ptr_record;
pub mod srv_record;
pub mod txt_record;
pub mod record_type;
pub mod record_information;
pub mod complete_record;


pub struct SRVRecord {
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

pub struct TXTRecord<'a> {
    pub pairs: Vec<(&'a str, String)>,
}

pub struct PTRRecord<'a> {
    pub domain: &'a String,
}


#[derive(Debug)]
pub struct AAAARecord {
    pub address: String,
}

#[derive(Debug)]
pub struct ARecord {
    pub address: String,
}