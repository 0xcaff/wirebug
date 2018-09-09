use std::net::Ipv4Addr;

pub struct IPV4 {
    version: u8,
    internet_header_length: u8,

    precedence: u8,
    low_delay: bool,
    high_throughput: bool,
    high_reliability: bool,

    total_length: u16,
    identification: u16,

    dont_fragment: bool,
    more_fragments: bool,

    fragment_offset: u16,
    time_to_live: u8,
    protocol: Protocol,
    header_checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Other(u8),
}

