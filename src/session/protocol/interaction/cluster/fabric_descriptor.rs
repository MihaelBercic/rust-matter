#[derive(Debug)]
pub struct FabricDescriptor {
    pub root_public_key: Vec<u8>,
    pub vendor_id: u16,
    pub fabric_id: u64,
    pub node_id: u64,
    pub label: String,
}
