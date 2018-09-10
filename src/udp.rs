use nom::{be_u16, IResult};

#[derive(Eq, PartialEq, Debug)]
pub struct UdpPacket {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    data: Vec<u8>,
}

impl UdpPacket {
    pub fn new(
        source_port: u16,
        destination_port: u16,
        length: u16,
        checksum: u16,
        data: Vec<u8>,
    ) -> UdpPacket {
        UdpPacket {
            source_port,
            destination_port,
            length,
            checksum,
            data,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], UdpPacket> {
        parse_udp_packet(input)
    }
}

named!(pub parse_udp_packet<UdpPacket>, do_parse!(
    source_port:      be_u16 >>
    destination_port: be_u16 >>
    length:           be_u16 >>
    checksum:         be_u16 >>
    data:             take!(length - 8) >>
    (UdpPacket {
        source_port,
        destination_port,
        length,
        checksum,
        data: data.to_vec(),
    })
));

#[cfg(test)]
mod tests {
    extern crate hex;
    use udp::UdpPacket;

    #[test]
    fn parse() {
        // From: https://erg.abdn.ac.uk/users/gorry/course/inet-pages/packet-dec12.html
        let raw = hex::decode("99d0043f0012722868656c6c6f68656c6c6f").unwrap();
        let (_, packet) = UdpPacket::parse(&raw).unwrap();
        assert_eq!(
            packet,
            UdpPacket::new(
                39376,
                1087,
                18,
                0x7228,
                hex::decode("68656c6c6f68656c6c6f").unwrap(),
            )
        )
    }
}
