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
    use ansi_term::Color::{Blue, Green};
    use ansi_term::Style;
    use pcap::{Address, Capture, Device};
    use libc;
    use crate::pkt_parser::{*};

    /// Given a device and a packet, it returns a tuple representing an entry in a hashmap
    fn decode_info_from_packet(device: Device, packet: PacketExt) -> Result<PacketInfo, DecodeError> {
        let (eth_header_result, eth_payload) = EthernetHeader::decode(packet.data);
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
                                return Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv4_header.get_dest_address();
                                let port = udp_header.get_dest_port();
                                return Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
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
                                return Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv4_header.get_dest_address();
                                let port = tcp_header.get_dest_port();
                                return Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            }
                        }
                    }
                    Protocol::Unknown => {
                        return Err(DecodeError{msg: format!("Unknown lev 4 protocol")});
                    }
                }
            },
            EtherType::Ipv6 => {
                let (ipv6_header_result, ipv6_payload) = Ipv6Header::decode(eth_payload);
                let ipv6_header = ipv6_header_result?;

                let direction = get_direction_from_ipv6(ipv6_header.clone(), device.clone());
                //println!("{:?}", direction);

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
                                return Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv6_header.get_dest_address();
                                let port = udp_header.get_dest_port();
                                return Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
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
                                return Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                // useful information is dest address and port
                                let address = ipv6_header.get_dest_address();
                                let port = tcp_header.get_dest_port();
                                return Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            }
                        }
                    },
                    Protocol::Unknown => {
                        return Err(DecodeError{msg: format!("Unknown lev 4 protocol")});
                    }
                }
            }
            _ => return Err(DecodeError{msg: "Cannot decode other level 3 header".parse().unwrap() }),
        };
    }

    pub struct Sniffer {
        device: Option<pcap::Device>,
        status: Arc<Mutex<RunStatus>>,
        file: Option<File>,
        time_interval: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct PacketExt {
        data: Vec<u8>,
        timestamp: TimeVal,
    }

    impl PacketExt {
        pub fn new(data: &[u8], ts: libc::timeval) -> Self {
            PacketExt{data: Vec::from(data), timestamp: TimeVal{sec: ts.tv_sec.to_string().parse::<i32>().unwrap(), u_sec: ts.tv_usec}}
        }
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

    fn display_device(device: Device) -> String {
        let mut result = String::new();
        result.push_str(&*Blue.paint(device.name).to_string());
        match device.desc {
            Some(d) => result.push_str(&*format!("({})", d)),
            None => result.push_str(" ...")
        };
        result.push_str("\nAddresses:\n");
        device.addresses.iter()
            .for_each(|a|{
                result.push_str("\t- ");
                result.push_str(&*Green.paint((*a).addr.to_string()).to_string());
                result.push_str("\n");
            });
        result
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
                Err(error) => Err(error)
            }
        }

        pub fn run(&self) -> Result<(), SnifferError> {
            if self.file.is_none() {
                return Err(SnifferError::UserError("File is null ...".to_string()));
            }
            if self.device.is_none() {
                return Err(SnifferError::UserError("You have to specify a device ...".to_string()));
            }
            self.set_status(RunStatus::Running);

            let device = self.device.clone().unwrap().clone();
            print!("Running on {}", display_device(device.clone()));
            let (tx, rx) = channel();
            let status = self.status.clone();

            let sniffer_thread = thread::spawn(move || {
                let tx = tx.clone();
                let mut cap = Capture::from_device(device.clone()).unwrap().promisc(true).open().unwrap();

                // polling on the status -> TODO: make it through a condition variable
                loop {
                    let s = status.lock().unwrap();
                    let status = (*s).clone();
                    drop(s);

                    match &status {
                        RunStatus::Running => {
                            // Extract a new packet from capture and send it.
                            match cap.next_packet() {
                                Ok(packet) => tx.send(PacketExt::new(packet.data, packet.header.ts)).unwrap(),
                                Err(e) => {
                                    SnifferError::PcapError(e);
                                }
                            }
                        },
                        RunStatus::Wait => { continue; },
                        RunStatus::Stop => { break; }
                        RunStatus::Error(e) => { println!("{}", e) }
                    }
                    // This sleep is requested for next_packet() method
                    // to avoid buffer overflow.
                    thread::sleep(Duration::from_micros(100));
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
                            println!("{:?}", info);
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
                Err(e) => Err(SnifferError::UserError(e.to_string()))
            }
        }

        pub fn pause(&mut self) -> Result<(), SnifferError> {
            let status = self.get_status();
            match &status {
                RunStatus::Error(error) => Err(SnifferError::UserError(error.to_string())),
                RunStatus::Running => {
                    self.set_status(RunStatus::Wait);
                    Ok(())
                },
                RunStatus::Stop => { return Err(SnifferError::UserWarning("There is no scanning in execution ...".to_string())); },
                RunStatus::Wait => { return Err(SnifferError::UserWarning("The scanning is already paused ...".to_string())); }
            }
        }

        pub fn resume(&mut self) -> Result<(), SnifferError> {
            let status = self.get_status();
            match &status {
                RunStatus::Error(error) => Err(SnifferError::UserError(error.to_string())),
                RunStatus::Wait => {
                    self.set_status(RunStatus::Running);
                    Ok(())
                },
                RunStatus::Stop => { return Err(SnifferError::UserWarning("There is no scanning in execution ...".to_string())); },
                RunStatus::Running => { return Err(SnifferError::UserWarning("The scanning is already running ...".to_string())); }
            }
        }

        pub fn save_report(&self) -> Result<(String), SnifferError> {
            let status = self.get_status();
            match &status {
                RunStatus::Error(error) => Err(SnifferError::UserError(error.to_string())),
                RunStatus::Stop => { Err(SnifferError::UserWarning("The scanning is already stopped ...".to_string())) },
                _ => {
                    match self.get_file() {
                        None => Err(SnifferError::UserError("The file doesn't exist ...".to_string())),
                        Some(_) => {
                            let write = self.get_file().as_ref().unwrap().write("Prova".as_ref());
                            match write {
                                Ok(_) => {
                                    self.set_status(RunStatus::Stop);
                                    return Ok(("The report has been saved and the scanning has been stopped ...".to_string()));
                                },
                                Err(error) => Err(SnifferError::UserError(error.to_string()))
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