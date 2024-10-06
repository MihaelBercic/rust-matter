use crate::mdns::records::record_type::RecordType::*;

#[repr(u16)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RecordType {
    Unsupported(u16) = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    DNAME = 39,
    APL = 42,
    DS = 43,
    NSEC = 47,
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => A,
            2 => NS,
            5 => CNAME,
            6 => SOA,
            12 => PTR,
            13 => HINFO,
            15 => MX,
            16 => TXT,
            17 => RP,
            18 => AFSDB,
            24 => SIG,
            25 => KEY,
            28 => AAAA,
            29 => LOC,
            33 => SRV,
            35 => NAPTR,
            36 => KX,
            37 => CERT,
            39 => DNAME,
            42 => APL,
            43 => DS,
            47 => NSEC,
            _ => Unsupported(value),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        match value {
            A => 1,
            NS => 2,
            CNAME => 5,
            SOA => 6,
            PTR => 12,
            HINFO => 13,
            MX => 15,
            TXT => 16,
            RP => 17,
            AFSDB => 18,
            SIG => 24,
            KEY => 25,
            AAAA => 28,
            LOC => 29,
            SRV => 33,
            NAPTR => 35,
            KX => 36,
            CERT => 37,
            DNAME => 39,
            APL => 42,
            DS => 43,
            NSEC => 47,
            _ => 0,
        }
    }
}

