use mac_address::{parse_mac_address, MacAddress};
use nom::{be_u16, IResult};

#[derive(Eq, PartialEq, Debug)]
pub struct EtherFrame {
    destination: MacAddress,
    source: MacAddress,
    ether_type: EtherType,
}

impl EtherFrame {
    pub fn parse(input: &[u8]) -> IResult<&[u8], EtherFrame> {
        do_parse!(
            input,
            destination: parse_mac_address >> 
            source: parse_mac_address >>
            ether_type: parse_ether_type >>

            (EtherFrame {
                destination,
                source,
                ether_type,
            })
        )
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum EtherType {
    IP,
    Length(u16),
    Other(u16),
}

named!(
    parse_ether_type<EtherType>,
    do_parse!(
        data: be_u16 >>

        (match data {
            0...1500 => EtherType::Length(data),
            0x0800 => EtherType::IP,
            _ => EtherType::Other(data),
        })
    )
);

#[cfg(test)]
mod tests {
    extern crate hex;

    use ether::EtherFrame;
    use ether::EtherType;
    use mac_address::MacAddress;

    #[test]
    fn parse() {
        let input = hex::decode("00248C01790800248C0179060800").unwrap();

        let (_, frame) = EtherFrame::parse(&input).unwrap();
        assert_eq!(
            frame,
            EtherFrame {
                destination: MacAddress::new([0x00, 0x24, 0x8c, 0x01, 0x79, 0x08]),
                source: MacAddress::new([0x00, 0x24, 0x8c, 0x01, 0x79, 0x06]),
                ether_type: EtherType::IP,
            }
        )
    }
}
