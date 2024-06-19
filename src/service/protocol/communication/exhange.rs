pub struct Exchange {
    id: u16,
    session: u16,
    role: ExchangeRole,
}

pub enum ExchangeRole {
    Intitator,
    Responder,
}

pub trait SessionContext {}