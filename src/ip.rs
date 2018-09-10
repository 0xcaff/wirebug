use nom::{be_u16, be_u8, IResult};
use std::net::Ipv4Addr;
use util::take_bool;

#[derive(Debug, Eq, PartialEq)]
pub struct Ipv4Header {
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

impl Ipv4Header {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Ipv4Header> {
        parse_ip_header(input)
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }
}

named!(
    pub parse_ip_header<Ipv4Header>,
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
                                bytes!(take!((internet_header_length - 5) * 4)) >>

        (Ipv4Header {
            internet_header_length: internet_header_length * 4,
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
    pub fn parse(input: &[u8]) -> IResult<&[u8], TypeOfService> {
        parse_ip_tos(input)
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

    use ip::{parse_ip_addr, Ipv4Header, Protocol, TypeOfService};
    use std::net::Ipv4Addr;

    #[test]
    fn parse_tos() {
        let raw: u8 = 0b10000100;
        let (_, tos) = TypeOfService::parse(&[raw]).unwrap();
        assert_eq!(
            tos,
            TypeOfService {
                raw,
                precedence: 0b100,
                low_delay: false,
                high_throughput: false,
                high_reliability: true
            }
        )
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
    fn parse_header() {
        let raw = hex::decode("4520003C16DB00003F06CC8AD5E9AB0A5EB6B88C").unwrap();
        let (_, packet) = Ipv4Header::parse(&raw).unwrap();
        assert_eq!(
            packet,
            Ipv4Header {
                internet_header_length: 20,
                type_of_service: TypeOfService::parse(&[0x20]).unwrap().1,
                total_length: 60,
                identification: 0x16db,
                dont_fragment: false,
                more_fragments: false,
                fragment_offset: 0,
                time_to_live: 63,
                protocol: Protocol::TCP,
                header_checksum: 0xcc8a,
                source: Ipv4Addr::new(213, 233, 171, 10),
                destination: Ipv4Addr::new(94, 182, 184, 140),
            },
        )
    }
}
