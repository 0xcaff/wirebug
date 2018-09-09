use nom::{be_u16, be_u8};

#[derive(Debug, PartialEq, Eq)]
pub struct IcmpPacket {
    packet_type: PacketType,
    code: u8,
    checksum: u16,
}

impl IcmpPacket {
    pub fn new(packet_type: PacketType, code: u8, checksum: u16) -> IcmpPacket {
        IcmpPacket {
            packet_type,
            code,
            checksum,
        }
    }
}

named!(pub parse_icmp_packet<IcmpPacket>, do_parse!(
    packet_type: be_u8 >>
    code:        be_u8 >>
    checksum:    be_u16 >>
    (IcmpPacket {
        packet_type: PacketType::new(packet_type),
        code,
        checksum,
    })
));

#[derive(Debug, PartialEq, Eq)]
pub struct PacketType {
    value: u8,
}

impl PacketType {
    fn new(value: u8) -> PacketType {
        PacketType { value }
    }

    fn nice_name(&self) -> Option<&'static str> {
        match self.value {
            0 => Some("Echo reply"),
            3 => Some("Destination unreachable"),
            4 => Some("Source quench"),
            5 => Some("Redirect message"),
            8 => Some("Echo request"),
            9 => Some("Router advertisement"),
            10 => Some("Router solicitation"),
            11 => Some("Time exceeded"),
            12 => Some("Parameter problem: bad ip header"),
            13 => Some("Timestamp"),
            14 => Some("Timestamp reply"),
            15 => Some("Information request"),
            16 => Some("Information reply"),
            17 => Some("Address mask request"),
            18 => Some("Address mask reply"),
            30 => Some("Traceroute"),
            42 => Some("Extended echo request"),
            43 => Some("Extended echo reply"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;
    use icmp::{parse_icmp_packet, IcmpPacket, PacketType};

    #[test]
    fn parse() {
        // From: https://erg.abdn.ac.uk/users/gorry/eg3561/inet-pages/packet-dec2.html
        let input = hex::decode("000045da1e600000335e3ab8000042ac08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637").unwrap();
        let (_, packet) = parse_icmp_packet(&input).unwrap();
        assert_eq!(packet, IcmpPacket::new(PacketType::new(0), 0, 0x45da))
    }
}
