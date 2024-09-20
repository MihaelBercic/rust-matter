#![allow(unused)]

use crate::session::protocol::communication::enums::ExchangeRole;

pub struct Exchange {
    id: u16,
    session: u16,
    role: ExchangeRole,
}