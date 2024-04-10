#[cfg(test)]
pub mod discovery_tests {
    use crate::discovery::mdns;

    #[test]
    fn hello() {
        mdns::hi();
    }
}