pub struct IcmpPacket {
    packet_type: u8,
    code: u8,
    checksum: [u8; 2],
}
