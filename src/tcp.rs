use nom::{be_u16, be_u32, IResult};
use util::take_bool;

#[derive(Eq, PartialEq, Debug)]
pub struct TcpHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,

    urgent: bool,
    acknowledgment: bool,
    push: bool,
    reset: bool,
    synchronize: bool,
    fin: bool,

    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

impl TcpHeader {
    fn new(
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        acknowledgment_number: u32,
        data_offset: u8,

        urgent: bool,
        acknowledgment: bool,
        push: bool,
        reset: bool,
        synchronize: bool,
        fin: bool,

        window_size: u16,
        checksum: u16,
        urgent_pointer: u16,
    ) -> TcpHeader {
        TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            urgent,
            acknowledgment,
            push,
            reset,
            synchronize,
            fin,
            window_size,
            checksum,
            urgent_pointer,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], TcpHeader> {
        parse_tcp_header(input)
    }
}

named!(
    pub parse_tcp_header<TcpHeader>,
    bits!(
        do_parse!(
            source_port:           bytes!(be_u16) >>
            destination_port:      bytes!(be_u16) >>
            sequence_number:       bytes!(be_u32) >>
            acknowledgment_number: bytes!(be_u32) >>
            data_offset:           take_bits!(u8, 4) >>
                                   tag_bits!(u8, 3, 0) >>
                                   take_bits!(u8, 3) >>
            urgent:                take_bool >>
            acknowledgment:        take_bool >>
            push:                  take_bool >>
            reset:                 take_bool >>
            synchronize:           take_bool >>
            fin:                   take_bool >>

            window_size:           bytes!(be_u16) >>
            checksum:              bytes!(be_u16) >>
            urgent_pointer:        bytes!(be_u16) >>
                                   bytes!(take!((data_offset - 5) * 4)) >>

            (TcpHeader {
                source_port,
                destination_port,
                sequence_number,
                acknowledgment_number,
                data_offset: data_offset * 4,
                urgent,
                acknowledgment,
                push,
                reset,
                synchronize,
                fin,
                window_size,
                checksum,
                urgent_pointer,
            })
        )
    )
);

#[cfg(test)]
mod tests {
    extern crate hex;
    use tcp::TcpHeader;

    #[test]
    fn parse() {
        // From: https://erg.abdn.ac.uk/users/gorry/eg3561/inet-pages/packet-decode3.html
        let raw = hex::decode("900500177214f1140000000060022238a92c0000020405b4").unwrap();
        let (_, packet) = TcpHeader::parse(&raw).unwrap();
        assert_eq!(
            packet,
            TcpHeader::new(
                36869, 23, 1913975060, 0, 24, false, false, false, false, true, false, 8760,
                0xa92c, 0
            )
        )
    }
}
