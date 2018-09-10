use ether::EtherFrame;
use icmp::IcmpHeader;
use ip::Ipv4Header;
use ip::Protocol;
use tcp::TcpHeader;
use udp::UdpPacket;

#[derive(Fail, Debug)]
pub enum ParseError {
    #[fail(display = "Ethernet frame invalid.")]
    InvalidEthernetFrame,

    #[fail(display = "Failed to parse IP Header")]
    InvalidIpHeader,

    #[fail(display = "Failed to parse ICMP packet")]
    InvalidIcmpPacket,

    #[fail(display = "Failed to parse TCP header")]
    InvalidTcpHeader,

    #[fail(display = "Failed to parse UDP packet")]
    InvalidUdpPacket,
}

#[derive(Eq, PartialEq, Debug)]
pub struct Packet {
    frame: EtherFrame,
    ip_header: Ipv4Header,
    contents: PacketContents,
}

impl Packet {
    pub fn new(frame: EtherFrame, ip_header: Ipv4Header, contents: PacketContents) -> Packet {
        Packet {
            frame,
            ip_header,
            contents,
        }
    }

    pub fn parse(input: &[u8]) -> Result<Packet, ParseError> {
        let (after_ether_header, ether_frame) =
            EtherFrame::parse(input).map_err(|_e| ParseError::InvalidEthernetFrame)?;

        let (after_ip_header, ip_header) =
            Ipv4Header::parse(after_ether_header).map_err(|_e| ParseError::InvalidIpHeader)?;

        let contents = PacketContents::parse(ip_header.protocol(), after_ip_header)?;

        Ok(Packet {
            frame: ether_frame,
            ip_header,
            contents,
        })
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum PacketContents {
    ICMP { header: IcmpHeader, data: Vec<u8> },

    TCP { header: TcpHeader, data: Vec<u8> },

    UDP { packet: UdpPacket },

    Other,
}

impl PacketContents {
    fn parse(proto: &Protocol, input: &[u8]) -> Result<PacketContents, ParseError> {
        let contents = match proto {
            Protocol::ICMP => {
                let (after_header, header) =
                    IcmpHeader::parse(input).map_err(|_e| ParseError::InvalidIcmpPacket)?;

                let data = after_header.to_vec();

                PacketContents::ICMP { header, data }
            }
            Protocol::TCP => {
                let (after_header, header) =
                    TcpHeader::parse(input).map_err(|_e| ParseError::InvalidTcpHeader)?;
                let data = after_header.to_vec();

                PacketContents::TCP { header, data }
            }
            Protocol::UDP => {
                let (_, packet) =
                    UdpPacket::parse(input).map_err(|_e| ParseError::InvalidUdpPacket)?;

                PacketContents::UDP { packet }
            }
            _ => PacketContents::Other,
        };

        Ok(contents)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use ether::EtherFrame;
    use icmp::IcmpHeader;
    use ip::Ipv4Header;
    use packet::{Packet, PacketContents};
    use tcp::TcpHeader;
    use udp::UdpPacket;

    #[test]
    fn parse_icmp() {
        // From: https://erg.abdn.ac.uk/users/gorry/eg3561/inet-pages/packet-dec2.html
        let raw_ether_frame = hex::decode("08002086354b00e0f7263fe90800").unwrap();
        let raw_ip_header = hex::decode("45000054aafb4000fc01fa308b85e9028b85d96e").unwrap();
        let raw_icmp_header = hex::decode("000045da1e600000").unwrap();
        let raw_icmp_data = hex::decode("335e3ab8000042ac08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637").unwrap();

        let mut raw = raw_ether_frame.clone();
        raw.append(&mut raw_ip_header.clone());
        raw.append(&mut raw_icmp_header.clone());
        raw.append(&mut raw_icmp_data.clone());

        let packet = Packet::parse(&raw).unwrap();

        assert_eq!(
            packet,
            Packet::new(
                EtherFrame::parse(&raw_ether_frame).unwrap().1,
                Ipv4Header::parse(&raw_ip_header).unwrap().1,
                PacketContents::ICMP {
                    header: IcmpHeader::parse(&raw_icmp_header).unwrap().1,
                    data: raw_icmp_data,
                }
            )
        )
    }

    #[test]
    fn parse_tcp() {
        // From: https://erg.abdn.ac.uk/users/gorry/eg3561/inet-pages/packet-decode3.html
        let raw_ether_frame = hex::decode("00e0f7263fe908002086354b0800").unwrap();
        let raw_ip_header = hex::decode("4500002c08b84000ff0699978b85d96e8b85e902").unwrap();
        let raw_tcp_packet =
            hex::decode("900500177214f1140000000060022238a92c0000020405b4").unwrap();

        let mut raw = raw_ether_frame.clone();
        raw.append(&mut raw_ip_header.clone());
        raw.append(&mut raw_tcp_packet.clone());

        let packet = Packet::parse(&raw).unwrap();

        assert_eq!(
            packet,
            Packet::new(
                EtherFrame::parse(&raw_ether_frame).unwrap().1,
                Ipv4Header::parse(&raw_ip_header).unwrap().1,
                PacketContents::TCP {
                    header: TcpHeader::parse(&raw_tcp_packet).unwrap().1,
                    data: Vec::new(),
                },
            )
        )
    }

    #[test]
    fn parse_udp() {
        // From: https://erg.abdn.ac.uk/users/gorry/course/inet-pages/packet-dec12.html
        let raw_ether_frame = hex::decode("00e0f7263fe908002086354b0800").unwrap();
        let raw_ip_header = hex::decode("45000026ab494000ff11f7008b85d96e8b85e902").unwrap();
        let raw_udp_packet = hex::decode("99d0043f0012722868656c6c6f68656c6c6f").unwrap();

        let mut raw = raw_ether_frame.clone();
        raw.append(&mut raw_ip_header.clone());
        raw.append(&mut raw_udp_packet.clone());

        let packet = Packet::parse(&raw).unwrap();

        assert_eq!(
            packet,
            Packet::new(
                EtherFrame::parse(&raw_ether_frame).unwrap().1,
                Ipv4Header::parse(&raw_ip_header).unwrap().1,
                PacketContents::UDP {
                    packet: UdpPacket::parse(&raw_udp_packet).unwrap().1
                },
            )
        )
    }
}
