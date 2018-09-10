use nom::{be_u16, be_u8};
use std::net::Ipv4Addr;
use util::take_bool;

#[derive(Debug, Eq, PartialEq)]
pub struct Ipv4 {
    internet_header_length: u8,

    type_of_service: TypeOfService,

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

impl Ipv4 {
    pub fn new(
        internet_header_length: u8,

        type_of_service: TypeOfService,

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
    ) -> Ipv4 {
        Ipv4 {
            internet_header_length,
            type_of_service,
            total_length,
            identification,
            dont_fragment,
            more_fragments,
            fragment_offset,
            time_to_live,
            protocol,
            header_checksum,
            source,
            destination,
        }
    }
}

named!(
    pub parse_ip_packet<Ipv4>,
    bits!(do_parse!(
                                tag_bits!(u8, 4, 4) >>
        internet_header_length: take_bits!(u8, 4) >>
        type_of_service:        bytes!(parse_ip_tos) >>
        total_length:           bytes!(be_u16) >>
        identification:         bytes!(be_u16) >>
                                tag_bits!(u8, 1, 0) >>
        dont_fragment:          take_bool >>
        more_fragments:         take_bool >>
        fragment_offset:        take_bits!(u16, 13) >>
        time_to_live:           bytes!(be_u8) >>
        protocol:               bytes!(be_u8) >>
        header_checksum:        bytes!(be_u16) >>
        source:                 bytes!(parse_ip_addr) >>
        destination:            bytes!(parse_ip_addr) >>
            (Ipv4 {
            internet_header_length,
            type_of_service,
            total_length,
            identification,
            dont_fragment,
            more_fragments,
            fragment_offset,
            time_to_live,
            protocol: Protocol::from_number(protocol),
            header_checksum,
            source,
            destination,
        })
    ))
);

named!(
    pub parse_ip_addr<Ipv4Addr>,
    do_parse!(
        octets: take!(4) >>
        (Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    )
);

#[derive(Eq, PartialEq, Debug)]
pub struct TypeOfService {
    raw: u8,

    precedence: u8,
    low_delay: bool,
    high_throughput: bool,
    high_reliability: bool,
}

impl TypeOfService {
    fn new(
        raw: u8,
        precedence: u8,
        low_delay: bool,
        high_throughput: bool,
        high_reliability: bool,
    ) -> TypeOfService {
        TypeOfService {
            raw,
            precedence,
            low_delay,
            high_throughput,
            high_reliability,
        }
    }
}

named!(pub parse_ip_tos<TypeOfService>,
    bits!(
        do_parse!(
            raw:              peek!(take_bits!(u8, 8)) >>
            precedence:       take_bits!(u8, 3) >>
            low_delay:        take_bool >>
            high_throughput:  take_bool >>
            high_reliability: take_bool >>
                              tag_bits!(u8, 2, 0) >>
            (TypeOfService {
                raw,
                precedence,
                low_delay,
                high_throughput,
                high_reliability,
            })
        )
    )
);

#[derive(Debug, Eq, PartialEq)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Other(u8),
}

impl Protocol {
    pub fn from_number(num: u8) -> Protocol {
        match num {
            0x01 => Protocol::ICMP,
            0x06 => Protocol::TCP,
            0x11 => Protocol::UDP,
            _ => Protocol::Other(num),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use ip::{parse_ip_addr, parse_ip_packet, parse_ip_tos, Ipv4, Protocol, TypeOfService};
    use std::net::Ipv4Addr;

    #[test]
    fn parse_tos() {
        let raw: u8 = 0b10000100;
        let (_, tos) = parse_ip_tos(&[raw]).unwrap();
        assert_eq!(tos, TypeOfService::new(raw, 0b100, false, false, true))
    }

    #[test]
    fn parse_addr() {
        let raw_addr: [u8; 4] = [213, 233, 171, 10];
        let (_, addr) = parse_ip_addr(&raw_addr).unwrap();
        assert_eq!(
            addr,
            Ipv4Addr::new(raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3])
        )
    }

    #[test]
    fn parse_packet() {
        let raw = hex::decode("4520003C16DB00003F06CC8AD5E9AB0A5EB6B88C").unwrap();
        let (_, packet) = parse_ip_packet(&raw).unwrap();
        assert_eq!(
            packet,
            Ipv4::new(
                5,
                parse_ip_tos(&[0x20]).unwrap().1,
                60,
                0x16db,
                false,
                false,
                0,
                63,
                Protocol::TCP,
                0xcc8a,
                Ipv4Addr::new(213, 233, 171, 10),
                Ipv4Addr::new(94, 182, 184, 140),
            )
        )
    }
}
