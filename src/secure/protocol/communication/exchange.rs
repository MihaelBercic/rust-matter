#![allow(unused)]

use crate::secure::protocol::communication::enums::ExchangeRole;

pub struct Exchange {
    id: u16,
    session: u16,
    role: ExchangeRole,
}