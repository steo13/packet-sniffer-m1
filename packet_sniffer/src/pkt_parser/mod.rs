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
                write!(f, "{:x} ", byte)?;
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
}

/// Header Trait define a common interface for all the Header. An Header should provide a way to decode it from raw data.
pub trait Header: Debug + Clone {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>);
}


#[derive(Debug, Clone)]
pub struct DecodeError{
    pub(crate) msg: String
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Decode error: {}", self.msg)
    }
}

#[derive(Debug, Clone)]
pub enum EtherType {
    Ipv4,
    Ipv6,
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
        let ether_type = ((ether_type_vec[0] as u16) << 8) | ether_type_vec[1] as u16;

        // println!("Entire header: {:x?} \n Destination MAC address: {:x?} Source MAC address: {:x?} Ether type: {:x?}", eth_header, &eth_header[0..6], &eth_header[6..12], ether_type);
        let ether_payload = &data[14..len];

        let real_ether_type = match ether_type {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::Ipv6,
            val => return (
                Err(DecodeError{msg: format!("Cannot get the correct ether type, received 0x{:x}", val).to_string()}),
                data
            )
        };
        (
            Ok(EthernetHeader{dest: utils::mac_address_to_string(&eth_header[0..6]), src: utils::mac_address_to_string(&eth_header[6..12]) , ether_type: real_ether_type}),
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

#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP
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
        let header_len = (data[0] & 0x0f ) as usize;
        // println!("IPV4 header has len {} byte", header_len * 4);
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
pub struct UDPHeader {
    dest: u16,
    src: u16,
}

impl Header for UDPHeader {
    fn decode(data: Vec<u8>) -> (Result<Self, DecodeError>, Vec<u8>) {
        let dest = ((data[0] as u16) << 8) | data[1] as u16;
        let src = ((data[2] as u16) << 8) | data[3] as u16;
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
        let dest = ((data[0] as u16) << 8) | data[1] as u16;
        let src = ((data[2] as u16) << 8) | data[3] as u16;
        (
            Ok(TCPHeader{dest, src}),
            Vec::from(&data[20..])
        )
    }
}

