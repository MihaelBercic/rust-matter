pub struct FabricDescriptor {
    root_public_key: Vec<u8>,
    vendor_id: u16,
    fabric_id: u64,
    node_id: u64,
    label: String,
}
