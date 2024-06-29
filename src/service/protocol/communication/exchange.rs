#![allow(unused)]

use crate::service::protocol::communication::enums::ExchangeRole;

pub struct Exchange {
    id: u16,
    session: u16,
    role: ExchangeRole,
}