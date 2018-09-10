use nom::IResult;

pub fn take_bool(input: (&[u8], usize)) -> IResult<(&[u8], usize), bool> {
    do_parse!(input, value: take_bits!(u8, 1) >> (value == 1))
}
