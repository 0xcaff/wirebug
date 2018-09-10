# wirebug

A tool to parse and display information about networking packets from pcap
files. It supports the folllowing packet types:

* Ether Frame
* IPv4
* UDP
* TCP
* ICMP

Only the first packet is read from the input pcap file. This is done to keep
the output short.

## Running

After [installing a rust toolchain][installing-rust] with the latest stable
rust (1.28.0), run the following command from the project directory.

    cargo run ~/Downloads/icmp.pcap

## Tests

There are tests for each parser. You can run them with the following command
from the project directory.

    cargo test

## Dependencies

A few [dependencies] are used. Here's information about what they do and how
they are used.

### nom

A library to help with parsing.

### failure and failure_derive

Libraries for error management.

### pcap-file

A library for extracting packets from a pcap file.

[installing-rust]: https://www.rust-lang.org/en-US/install.html
[dependencies]: ./Cargo.toml