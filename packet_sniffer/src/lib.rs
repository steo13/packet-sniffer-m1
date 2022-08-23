extern crate core;

mod pkt_parser;
mod collect_signals;

pub mod sniffer {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::fmt::{Display, format, Formatter};
    use std::process::exit;
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time::Duration;
    use pcap::{Address, Capture, Device};
    use crate::pkt_parser::{DecodeError, EthernetHeader, EtherType, Header, Ipv4Header, Ipv6Header, Protocol, TCPHeader, UDPHeader};

    #[derive(Debug, Clone, PartialEq)]
    enum Direction {
        Received,
        Transmitted
    }

    /// the function decode_packet use pkt_parser to parse a packet from layer 2 to 4.
    pub fn decode_packet(packet: Vec<u8>) -> Result<(), DecodeError>{
        let (eth_header_result, eth_payload) = EthernetHeader::decode(packet);
        let eth_header = eth_header_result?;

        //println!("{:?}", eth_header);
        match eth_header.get_ether_type() {
            EtherType::Ipv4 => {
                let (ipv4_header_result, ipv4_payload) = Ipv4Header::decode(eth_payload);
                let ipv4_header = ipv4_header_result?;

                //println!("{:?}", ipv4_header);
                match ipv4_header.get_protocol() {
                    Protocol::UDP => {
                        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv4_payload);
                        let udp_header = udp_header_result?;
                        //println!("{:?}", udp_header);
                        let byte_transmitted = udp_payload.len();

                    }
                    Protocol::TCP => {
                        let (tcp_header_result, _tcp_payload) = TCPHeader::decode(ipv4_payload);
                        let tcp_header = tcp_header_result?;
                        //println!("{:?}", tcp_header);
                    }
                    Protocol::Unknown => {
                        println!("Unknown 4");
                    }
                }
            },
            EtherType::Ipv6 => {
                let (ipv6_header_result, ipv6_payload) = Ipv6Header::decode(eth_payload);
                let ipv6_header = ipv6_header_result?;

                //println!("{:?}", ipv6_header);
                match ipv6_header.get_protocol() {
                    Protocol::UDP => {
                        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv6_payload);
                        let udp_header = udp_header_result?;
                        //println!("{:?}", udp_header);
                    },
                    Protocol::TCP => {
                        let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv6_payload);
                        let tcp_header = tcp_header_result?;
                        //println!("{:?}", tcp_header);
                    },
                    Protocol::Unknown => {
                        println!("Unknown 4");
                    }
                }
            }
            _ => return Err(DecodeError{msg: "Cannot decode other level 3 header".parse().unwrap() }),
        };
        Ok(())
    }

    fn get_direction_from_ipv4(header: Ipv4Header, device: Device) -> Direction {
        if device.addresses.iter().any(|a| a.addr.to_string() == header.get_src_address()) {
            Direction::Transmitted
        } else { Direction::Received }
    }

    fn get_direction_from_ipv6(header: Ipv6Header, device: Device) -> Direction {
        if device.addresses.iter().any(|a| a.addr.to_string() ==  header.get_src_address()) {
            Direction::Transmitted
        } else { Direction::Received }
    }

    /// Given a device and a packet, it returns a tuple representing an entry in a hashmap
    fn decode_info_from_packet(device: Device, packet: Vec<u8>) -> Result<((String, u16, Protocol), usize), DecodeError> {
        let (eth_header_result, eth_payload) = EthernetHeader::decode(packet);
        let eth_header = eth_header_result?;

        match eth_header.get_ether_type() {
            EtherType::Ipv4 => {
                let (ipv4_header_result, ipv4_payload) = Ipv4Header::decode(eth_payload);
                let ipv4_header = ipv4_header_result?;


                let direction = get_direction_from_ipv4(ipv4_header.clone(), device.clone());

                //println!("{:?}", direction);
                //println!("{:?}", ipv4_header);

                match ipv4_header.get_protocol() {
                    Protocol::UDP => {
                        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv4_payload);
                        let udp_header = udp_header_result?;
                        //println!("{:?}", udp_header);
                        let byte_transmitted = udp_payload.len();
                        match direction {
                            Direction::Received => {
                                // useful information is src address and port
                                let address = ipv4_header.get_src_address();
                                let port = udp_header.get_src_port();
                                return Ok(((address, port, Protocol::UDP), byte_transmitted))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv4_header.get_dest_address();
                                let port = udp_header.get_dest_port();
                                return Ok(((address, port, Protocol::UDP), byte_transmitted))
                            }
                        }

                    }
                    Protocol::TCP => {
                        let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv4_payload);
                        let tcp_header = tcp_header_result?;
                        //println!("{:?}", tcp_header);
                        let byte_transmitted = tcp_payload.len();
                        match direction {
                            Direction::Received => {
                                // useful information is src address and port
                                let address = ipv4_header.get_src_address();
                                let port = tcp_header.get_src_port();
                                return Ok(((address, port, Protocol::TCP), byte_transmitted))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv4_header.get_dest_address();
                                let port = tcp_header.get_dest_port();
                                return Ok(((address, port, Protocol::TCP), byte_transmitted))
                            }
                        }
                    }
                    Protocol::Unknown => {
                        println!("Unknown 4");
                    }
                }
            },
            EtherType::Ipv6 => {
                let (ipv6_header_result, ipv6_payload) = Ipv6Header::decode(eth_payload);
                let ipv6_header = ipv6_header_result?;

                let direction = get_direction_from_ipv6(ipv6_header.clone(), device.clone());
                println!("{:?}", direction);

                //println!("{:?}", ipv6_header);
                match ipv6_header.get_protocol() {
                    Protocol::UDP => {
                        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv6_payload);
                        let udp_header = udp_header_result?;
                        //println!("{:?}", udp_header);
                        let byte_transmitted = udp_payload.len();
                        match direction {
                            Direction::Received => {
                                // useful information is src address and port
                                let address = ipv6_header.get_src_address();
                                let port = udp_header.get_src_port();
                                return Ok(((address, port, Protocol::UDP), byte_transmitted))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv6_header.get_dest_address();
                                let port = udp_header.get_dest_port();
                                return Ok(((address, port, Protocol::UDP), byte_transmitted))
                            }
                        }
                    },
                    Protocol::TCP => {
                        let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv6_payload);
                        let tcp_header = tcp_header_result?;
                        //println!("{:?}", tcp_header);
                        let byte_transmitted = tcp_payload.len();
                        match direction {
                            Direction::Received => {
                                // useful information is src address and port
                                let address = ipv6_header.get_src_address();
                                let port = tcp_header.get_src_port();
                                return Ok(((address, port, Protocol::UDP), byte_transmitted))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv6_header.get_dest_address();
                                let port = tcp_header.get_dest_port();
                                return Ok(((address, port, Protocol::UDP), byte_transmitted))
                            }
                        }
                    },
                    Protocol::Unknown => {
                        return Err(DecodeError{msg: "Cannot decode other level 4 header".parse().unwrap() })
                    }
                }
            }
            _ => return Err(DecodeError{msg: "Cannot decode other level 3 header".parse().unwrap() }),
        };
        return Err(DecodeError{msg: "Something goes wrong during the packet parsing".parse().unwrap() });
    }

    pub struct Sniffer {
        device: Option<pcap::Device>,
        pub status: Arc<Mutex<RunStatus>>,
        file: Option<File>,
        time_interval: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct TimeVal {
        sec: u32,
        m_sec: u32,
    }

    struct PacketExt {
        data: Vec<u8>,
        timestamp: TimeVal,
    }


    #[derive(PartialEq, Debug, Clone)]
    pub enum RunStatus {
        Stop, Wait, Running, Error(String)
    }

    #[derive(Debug)]
    pub enum SnifferError {
        PcapError(pcap::Error), DecodeError(String), UserError(String), UserWarning(String)
    }

    impl Display for SnifferError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                SnifferError::DecodeError(e) => write!(f, "{}", e),
                SnifferError::UserError(e) => write!(f, "{}", e),
                SnifferError::PcapError(e) => write!(f, "{}", e.to_string()),
                SnifferError::UserWarning(e) => write!(f, "{}", e)
            }
        }
    }

    impl Sniffer {
        pub fn new() -> Self {
            return Sniffer { device: None, status: Arc::new(Mutex::new(RunStatus::Stop)), file: None, time_interval: 0 }
        }

        pub fn list_devices() -> Result<Vec<pcap::Device>, SnifferError> {
            let devices = pcap::Device::list();
            return match devices {
                Ok(devices) => Ok(devices),
                Err(e) => Err(SnifferError::PcapError(e)),
            }
        }

        pub fn attach(&mut self, device: pcap::Device) -> Result<(), SnifferError> {
            return match Sniffer::list_devices() {
                Ok(devices) => {
                    for dev in &devices {
                        if dev.name == device.name {
                            self.device = Some(device);
                            return Ok(())
                        }
                    }
                    return Err(SnifferError::UserError("The device selected is not in list ...".to_string()))
                },
                Err(_) => Err(SnifferError::UserError("There aren't devices to select ...".to_string()))
            }
        }

        pub fn run(&self) -> Result<(), SnifferError> {
            self.set_status(RunStatus::Running);
            let (tx, rx) = channel();
            let status = self.status.clone();

            let device= self.get_device().clone().unwrap();
            let sniffer_thread = thread::spawn(move || {
                let tx = tx.clone();
                let mut cap = Capture::from_device(device).unwrap().promisc(true).open().unwrap();

                // polling on the status -> TODO: make it through a condition variable
                loop {
                    let s = status.lock().unwrap();
                    let status = (*s).clone();
                    drop(s);

                    match &status {
                        RunStatus::Running => {
                            // Extract a new packet from capture and send it.
                            match cap.next_packet() {
                                Ok(packet) => tx.send(Vec::from(packet.data)).unwrap(),
                                Err(e) => {
                                    // TODO: return the error
                                    println!("{:?}", e);
                                    exit(1);
                                }
                            }
                        },
                        RunStatus::Wait => { continue; },
                        RunStatus::Stop => { break; }
                        RunStatus::Error(e) => { println!("{}", e) }
                    }
                    // This sleep is requested for next_packet() method
                    // to avoid buffer overflow.
                    thread::sleep(Duration::from_millis(100));
                };
            });

            let device= self.get_device().clone().unwrap();
            let decoder_thread = thread::spawn(move || {
                let mut i = 0;
                while let Ok(packet) = rx.recv() {
                     if i % 100 == 0 {
                         println!("#{}", i);
                     }
                     i += 1;
                    match decode_info_from_packet(device.clone(), packet) {
                        Ok(info) => {
                            // TODO: Use here collect signals, magari levando la command queue
                            ()
                        },
                        Err(e) => println!("{}", e)
                    }
                }
            });
            Ok(())
        }


        pub fn run_with_interval(&mut self) -> Result<(), SnifferError> {

            let file = File::create(Path::new("asd"));
            match file {
                Ok(_) => {
                    self.set_status(RunStatus::Running);
                    self.file = Some(file.unwrap());
                    self.time_interval = 0;
                    Ok(())
                },
                Err(_) => Err(SnifferError::UserError("The file can't be created".to_string()))
            }
        }

        pub fn pause(&mut self) -> Result<(), SnifferError> {
            let status = self.get_status();
            match status {
                RunStatus::Error(_) => Err(SnifferError::UserError("The running has stopped".to_string())),
                _ => {
                    self.set_status(RunStatus::Wait);
                    Ok(())
                }
            }
        }

        pub fn resume(&mut self) -> Result<(), SnifferError> {
            let status = self.get_status();
            match status {
                RunStatus::Error(_) => Err(SnifferError::UserError("The running has stopped".to_string())),
                _ => {
                    self.set_status(RunStatus::Running);
                    Ok(())
                }
            }
        }

        pub fn save_report(&self) -> Result<(), SnifferError> {
            let status = self.get_status();
            match &status {
                RunStatus::Stop => Err(SnifferError::UserError("The device is not running ...".to_string())),
                _ => {
                    match self.get_file() {
                        None => Err(SnifferError::UserError("The file doesn't exist ...".to_string())),
                        Some(_) => {
                            let write = self.get_file().as_ref().unwrap().write("Prova".as_ref());
                            match write {
                                Ok(_) => Ok(()),
                                Err(_) => Err(SnifferError::UserError("The file can't be saved ...".to_string()))
                            }
                        }
                    }
                },
            }
        }

        pub fn get_time_interval(&self) -> u64 {
            self.time_interval
        }

        pub fn set_time_interval(&mut self, time_interval: u64) {
            self.time_interval = time_interval;
        }

        pub fn get_file(&self) -> &Option<File> {
            &self.file
        }

        pub fn set_file(&mut self, filename: String) -> Result<(), SnifferError> {
            let file = File::create(Path::new(&filename));
            match file {
                Ok(_) => {
                    self.file = Some(file.unwrap());
                    Ok(())
                },
                Err(_) => Err(SnifferError::UserError("The file can't be created ...".to_string()))
            }
        }

        pub fn get_status(&self) -> RunStatus {
            let s = self.status.lock().unwrap();
            return (*s).clone();
        }

        pub fn set_status(&self, status: RunStatus) -> () {
            let mut s = self.status.lock().unwrap();
            *s = status;
        }

        pub fn get_device(&self) -> &Option<pcap::Device> {
            &self.device
        }

        pub fn set_device(&mut self, device: Option<pcap::Device>) {
            self.device = device;
        }
    }
}