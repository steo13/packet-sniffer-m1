mod pkt_parser;

use crate::pkt_parser::{DecodeError, EthernetHeader, EtherType, Ipv4Header, Protocol, TCPHeader, UDPHeader};

pub fn test_function() {
    println!("Hello, world!");
}

// Example
fn decode_packet(packet: Vec<u8>) -> Result<(), DecodeError>{
    let (eth_header_result, eth_payload) = EthernetHeader::decode(packet);
    let eth_header = eth_header_result?;

    println!("{:?}", eth_header);
    match eth_header.get_ether_type() {
        EtherType::Ipv4 => {
            let (ipv4_header_result, ipv4_payload) = Ipv4Header::decode(eth_payload);
            let ipv4_header = ipv4_header_result?;

            println!("{:?}", ipv4_header);
            match ipv4_header.get_protocol() {
                Protocol::UDP => {
                    let (udp_header_result, udp_payload) = UDPHeader::decode(ipv4_payload);
                    let udp_header = udp_header_result?;
                    println!("{:?}", udp_header);
                }
                Protocol::TCP => {
                    let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv4_payload);
                    let tcp_header = tcp_header_result?;
                    println!("{:?}", tcp_header);
                }
            }
        },
        _ => return Err(DecodeError{msg: "Cannot decode other level 3 header".parse().unwrap() }),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_if_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
