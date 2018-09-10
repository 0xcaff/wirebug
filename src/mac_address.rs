use nom::IResult;
use std::fmt;
use std::fmt::Formatter;

#[derive(Eq, PartialEq)]
pub struct MacAddress {
    value: [u8; 6],
}

named!(pub parse_mac_address<MacAddress>,
    do_parse!(
        value: take!(6) >>
        (MacAddress {
            value: [
                value[0], value[1], value[2],
                value[3], value[4], value[5]
            ]
        })
    )
);

impl MacAddress {
    pub fn parse(input: &[u8]) -> IResult<&[u8], MacAddress> {
        parse_mac_address(input)
    }

    pub fn new(value: [u8; 6]) -> MacAddress {
        MacAddress { value }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.value[0], self.value[1], self.value[2],
            self.value[3], self.value[4], self.value[5]
        )
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;

    #[test]
    fn parse() {
        let (_, addr) = MacAddress::parse(&[1, 2, 3, 4, 5, 250]).unwrap();
        assert_eq!(addr, MacAddress::new([1, 2, 3, 4, 5, 250]))
    }

    #[test]
    fn debug_output() {
        let addr = MacAddress::new([0x1, 0x2, 0x3, 0x4, 0x5, 0xfa]);
        assert_eq!(format!("{:?}", addr), "01:02:03:04:05:fa");
    }
}
