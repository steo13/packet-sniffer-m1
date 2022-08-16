use std::fmt;
use std::fmt::{Debug, Display, Formatter};

mod utils {
    use std::fmt;

    struct HexSlice<'a>(&'a [u8]);

    impl<'a> HexSlice<'a> {
        fn new<T>(data: &'a T) -> HexSlice<'a>
            where
                T: ?Sized + AsRef<[u8]> + 'a,
        {
            HexSlice(data.as_ref())
        }
    }

    // You can choose to implement multiple traits, like Lower and UpperHex
    impl fmt::Display for HexSlice<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for byte in self.0 {
                // Decide if you want to pad the value or have spaces inbetween, etc.
                write!(f, "{:02x} ", byte)?;
            }
            Ok(())
        }
    }

    trait HexDisplayExt {
        fn hex_display(&self) -> HexSlice<'_>;
    }

    impl<T> HexDisplayExt for T
        where
            T: ?Sized + AsRef<[u8]>,
    {
        fn hex_display(&self) -> HexSlice<'_> {
            HexSlice::new(self)
        }
    }

    pub fn mac_address_to_string(address: &[u8]) -> String {
        address.hex_display().to_string().replace(" ", "")
    }

    pub fn ipv4_address_to_string(address: &[u8]) -> String {
        address.iter().map(|b| b.to_string()).collect::<Vec<String>>().join(".")
    }

    pub fn ipv6_address_to_string(address: &[u8]) -> String {
        address.iter().hex_display().to_string().replace(" ", "")
    }
}

/// Header Trait define a common interface for all the Header. An Header should provide a way to decode it from raw data.
pub trait Header: Debug + Clone {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>);
}

/// A custom error to be returned if something goes wrong during the decoding of the packet.
#[derive(Debug, Clone)]
pub struct DecodeError{
    pub msg: String
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Decode error: {}", self.msg)
    }
}

/// Ether type
#[derive(Debug, Clone, PartialEq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    /// Arp protocol
    ARP,
}


#[derive(Debug, Clone)]
pub struct EthernetHeader {
    dest: String,
    src: String,
    ether_type: EtherType,
}

impl Header for EthernetHeader {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>) {
        let len = data.len();
        // Extracting data
        let eth_header = &data[0..14];
        let ether_type_vec = &eth_header[12..14];
        // println!("Entire header: {:x?} \n Destination MAC address: {:x?} Source MAC address: {:x?} Ether type: {:x?}", eth_header, &eth_header[0..6], &eth_header[6..12], ether_type);
        let ether_payload = &data[14..len];

        let ether_type = match ((ether_type_vec[0] as u16) << 8) | ether_type_vec[1] as u16 {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::Ipv6,
            val => return (
                Err(DecodeError{msg: format!("Cannot get the correct ether type, received 0x{:x}", val).to_string()}),
                data
            )
        };
        (
            Ok(EthernetHeader{dest: utils::mac_address_to_string(&eth_header[0..6]), src: utils::mac_address_to_string(&eth_header[6..12]) , ether_type }),
            Vec::from(ether_payload)
        )
    }
}

impl EthernetHeader {
    pub fn get_ether_type(&self) -> EtherType {
        return self.ether_type.clone();
    }
    pub fn get_src_address(&self) -> String { return self.src.clone(); }
    pub fn get_dest_address(&self) -> String { return self.dest.clone(); }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    Unknown
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    dest: String,
    src: String,
    protocol: Protocol,
}

impl Header for Ipv4Header {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>) {
        let len = data.len();
        let header_len = (data[0] & 0x0f ) as usize * 4;
        let protocol = match &data[9] {
            0x06 => Protocol::TCP,
            0x11 => Protocol::UDP,
            value => return (
                Err(DecodeError{ msg: format!("Unable to identify level 4 protocol. Received 0x{:x}", value) }),
                data
            )
        };

        let src_address = utils::ipv4_address_to_string(&data[12..16]);
        let dest_address = utils::ipv4_address_to_string(&data[16..20]);
        (
            Ok(Ipv4Header{src: src_address, dest: dest_address, protocol}),
            Vec::from(&data[header_len..len])
        )
    }
}

impl Ipv4Header {
    pub fn get_protocol(&self) -> Protocol {
        self.protocol.clone()
    }
    pub fn get_src_address(&self) -> String { return self.src.clone(); }
    pub fn get_dest_address(&self) -> String { return self.dest.clone(); }
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    dest: String,
    src: String,
    protocol: Protocol,
}

impl Header for Ipv6Header {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>) {
        let len = data.len();
        let protocol = match &data[9] {
            0x06 => Protocol::TCP,
            0x11 => Protocol::UDP,
            _ => Protocol::Unknown
            /*return (
                Err(DecodeError{ msg: format!("Unable to identify level 4 protocol. Received 0x{:x}", value) }),
                data
            )*/
        };

        let src_address = utils::ipv6_address_to_string(&data[8..20]);
        let dest_address = utils::ipv6_address_to_string(&data[20..36]);
        (
            Ok(Ipv6Header{src: src_address, dest: dest_address, protocol}),
            Vec::from(&data[40..len])
        )
    }
}

impl Ipv6Header {
    pub fn get_protocol(&self) -> Protocol {
        self.protocol.clone()
    }
    pub fn get_src_address(&self) -> String { return self.src.clone(); }
    pub fn get_dest_address(&self) -> String { return self.dest.clone(); }
}


#[derive(Debug, Clone)]
pub struct UDPHeader {
    dest: u16,
    src: u16,
}

impl UDPHeader {
    pub fn get_src_port(&self) -> u16 { return self.src }
    pub fn get_dest_port(&self) -> u16 { return self.dest }
}

impl Header for UDPHeader {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>) {
        let src = ((data[0] as u16) << 8) | data[1] as u16;
        let dest = ((data[2] as u16) << 8) | data[3] as u16;
        (
            Ok(UDPHeader{dest, src}),
            Vec::from(&data[8..])
        )
    }
}

#[derive(Debug, Clone)]
pub struct TCPHeader {
    dest: u16,
    src: u16,
}

impl Header for TCPHeader {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>) {
        let src = ((data[0] as u16) << 8) | data[1] as u16;
        let dest = ((data[2] as u16) << 8) | data[3] as u16;
        (
            Ok(TCPHeader{dest, src}),
            Vec::from(&data[20..])
        )
    }
}

impl TCPHeader {
    pub fn get_src_port(&self) -> u16 { return self.src }
    pub fn get_dest_port(&self) -> u16 { return self.dest }
}

#[cfg(test)]
mod tests {
    use crate::{EthernetHeader, EtherType, Header, Ipv4Header, Protocol, TCPHeader, UDPHeader};

    #[test]
    fn test_ethernet_packet() {
        let data = vec![51, 51, 0, 1, 0, 2, 80, 235, 113, 35, 142, 103, 134, 221, 96, 9, 31, 94, 0, 103, 17, 1, 254, 128, 0, 0, 0, 0, 0, 0, 5, 194, 180, 157, 9, 91, 63, 25, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 2, 34, 2, 35, 0, 103, 0, 211, 1, 228, 89, 38, 0, 8, 0, 2, 12, 31, 0, 1, 0, 14, 0, 1, 0, 1, 42, 94, 58, 157, 80, 235, 113, 35, 142, 103, 0, 3, 0, 12, 10, 80, 235, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 0, 17, 0, 15, 68, 69, 83, 75, 84, 79, 80, 45, 83, 86, 65, 65, 84, 84, 52, 0, 16, 0, 14, 0, 0, 1, 55, 0, 8, 77, 83, 70, 84, 32, 53, 46, 48, 0, 6, 0, 8, 0, 17, 0, 23, 0, 24, 0, 39];
        let (ethernet_header_res, payload) = EthernetHeader::decode(data);
        let ethernet_header = ethernet_header_res.unwrap();
        assert_eq!(ethernet_header.get_dest_address(), "33330102".to_string());
        assert_eq!(ethernet_header.get_src_address(), "50eb71238e67".to_string());
        assert_eq!(ethernet_header.get_ether_type(), EtherType::Ipv6);
    }

    #[test]
    fn test_whole_packet_1() {
        let data = vec![80, 235, 113, 35, 142, 103, 152, 0, 106, 4, 85, 32, 8, 0, 69, 0, 0, 130, 170, 10, 64, 0, 64, 17, 12, 250, 192, 168, 1, 1, 192, 168, 1, 21, 0, 53, 234, 64, 0, 110, 71, 245, 212, 212, 129, 131, 0, 1, 0, 0, 0, 1, 0, 0, 4, 119, 112, 97, 100, 4, 104, 111, 109, 101, 0, 0, 1, 0, 1, 0, 0, 6, 0, 1, 0, 0, 0, 91, 0, 64, 1, 97, 12, 114, 111, 111, 116, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116, 0, 5, 110, 115, 116, 108, 100, 12, 118, 101, 114, 105, 115, 105, 103, 110, 45, 103, 114, 115, 3, 99, 111, 109, 0, 120, 134, 93, 48, 0, 0, 7, 8, 0, 0, 3, 132, 0, 9, 58, 128, 0, 1, 81, 128];
        let (ethernet_header_res, eth_payload) = EthernetHeader::decode(data);
        let ethernet_header = ethernet_header_res.unwrap();
        assert_eq!(ethernet_header.get_dest_address(), "50eb71238e67".to_string());
        assert_eq!(ethernet_header.get_src_address(),  "98006a045520".to_string());
        assert_eq!(ethernet_header.get_ether_type(), EtherType::Ipv4);

        let (ipv4_header_result, ipv4_payload) = Ipv4Header::decode(eth_payload);
        let ipv4_header = ipv4_header_result.unwrap();

        assert_eq!(ipv4_header.get_dest_address(), "192.168.1.21".to_string());
        assert_eq!(ipv4_header.get_src_address(), "192.168.1.1".to_string());
        assert_eq!(ipv4_header.get_protocol(), Protocol::UDP);

        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv4_payload);
        let udp_header = udp_header_result.unwrap();

        assert_eq!(udp_header.get_src_port(), 53);
        assert_eq!(udp_header.get_dest_port(), 59968);
    }

    #[test]
    fn test_whole_packet_2() {
        let data = vec![152, 0, 106, 4, 85, 32, 80, 235, 113, 35, 142, 103, 8, 0, 69, 0, 0, 40, 134, 79, 64, 0, 128, 6, 0, 0, 192, 168, 1, 21, 149, 154, 167, 92, 220, 49, 1, 187, 135, 216, 62, 67, 24, 80, 57, 27, 80, 20, 0, 0, 254, 206, 0, 0];
        let (ethernet_header_res, eth_payload) = EthernetHeader::decode(data);
        let ethernet_header = ethernet_header_res.unwrap();
        assert_eq!(ethernet_header.get_dest_address(), "98006a045520".to_string());
        assert_eq!(ethernet_header.get_src_address(),  "50eb71238e67".to_string());
        assert_eq!(ethernet_header.get_ether_type(), EtherType::Ipv4);

        let (ipv4_header_result, ipv4_payload) = Ipv4Header::decode(eth_payload);
        let ipv4_header = ipv4_header_result.unwrap();

        assert_eq!(ipv4_header.get_dest_address(), "149.154.167.92".to_string());
        assert_eq!(ipv4_header.get_src_address(), "192.168.1.21".to_string());
        assert_eq!(ipv4_header.get_protocol(), Protocol::TCP);

        let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv4_payload);
        let tcp_header = tcp_header_result.unwrap();

        assert_eq!(tcp_header.get_src_port(), 56369);
        assert_eq!(tcp_header.get_dest_port(), 443);
    }
}