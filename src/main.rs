#[macro_use]
extern crate nom;

#[macro_use]
extern crate failure_derive;

extern crate failure;

extern crate pcap_file;

mod ether;
mod icmp;
mod ip;
mod mac_address;
mod packet;
mod tcp;
mod udp;
mod util;

use std::env;
use std::fs::File;
use std::io;

use pcap_file::PcapReader;

#[derive(Fail, Debug)]
enum ErrorKind {
    #[fail(display = "No arguments were passed to the program.")]
    ArgumentMissing,

    #[fail(display = "Failed to access file.")]
    FileError(#[cause] io::Error),

    #[fail(display = "Failed to read file.")]
    PcapError,

    #[fail(display = "No packets were found in the file.")]
    NoPacket,

    #[fail(display = "Failed to parse packet.")]
    ParseError(#[cause] packet::ParseError),
}

fn main() {
    handle_main().unwrap();
}

fn handle_main() -> Result<(), ErrorKind> {
    let arg = env::args()
        .nth(1)
        .map_or(Err(ErrorKind::ArgumentMissing), Ok)?;

    let file = File::open(arg).map_err(ErrorKind::FileError)?;
    let mut reader = PcapReader::new(file).map_err(|_e| ErrorKind::PcapError)?;

    let pcap_packet = reader
        .nth(0)
        .map_or(Err(ErrorKind::NoPacket), Ok)?
        .map_err(|_e| ErrorKind::PcapError)?;
    let pkt = packet::Packet::parse(&pcap_packet.data).map_err(ErrorKind::ParseError)?;

    println!("{:#?}", pkt);

    Ok(())
}
