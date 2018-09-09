pub struct TcpHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    // TODO: Flags
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    data: [u8],
}

