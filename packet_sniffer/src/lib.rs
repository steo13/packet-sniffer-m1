extern crate core;
#[macro_use] extern crate prettytable;
pub mod pkt_parser;

pub mod sniffer {
    use chrono::{Local, TimeZone};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Seek, Write};
    use std::path::Path;
    use std::sync::{Arc, Condvar, Mutex};
    use std::fmt::{Display, Formatter};
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time::Duration;
    use ansi_term::Color::{Blue, Green};
    use pcap::{Capture, Device};
    use libc;
    use prettytable::{Cell, Row, Table};
    use crate::pkt_parser;
    use crate::pkt_parser::{*};

    fn decode_info_from_packet(device: Device, packet: PacketExt) -> Result<PacketInfo, DecodeError> {
        let (eth_header_result, eth_payload) = EthernetHeader::decode(packet.data);
        let eth_header = eth_header_result?;

        return match eth_header.get_ether_type() {
            EtherType::Ipv4 => {
                let (ipv4_header_result, ipv4_payload) = Ipv4Header::decode(eth_payload);
                let ipv4_header = ipv4_header_result?;
                let direction = get_direction_from_ipv4(ipv4_header.clone(), device.clone());

                match ipv4_header.get_protocol() {
                    Protocol::UDP => {
                        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv4_payload);
                        let udp_header = udp_header_result?;
                        let byte_transmitted = udp_payload.len();
                        match direction {
                            Direction::Received => {
                                let address = ipv4_header.get_src_address();
                                let port = udp_header.get_src_port();
                                Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                let address = ipv4_header.get_dest_address();
                                let port = udp_header.get_dest_port();
                                Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
                            }
                        }
                    }
                    Protocol::TCP => {
                        let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv4_payload);
                        let tcp_header = tcp_header_result?;
                        let byte_transmitted = tcp_payload.len();
                        match direction {
                            Direction::Received => {
                                let address = ipv4_header.get_src_address();
                                let port = tcp_header.get_src_port();
                                Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                let address = ipv4_header.get_dest_address();
                                let port = tcp_header.get_dest_port();
                                Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            }
                        }
                    }
                    Protocol::Unknown => {
                        Err(DecodeError { msg: format!("Unknown lev 4 protocol") })
                    }
                }
            },
            EtherType::Ipv6 => {
                let (ipv6_header_result, ipv6_payload) = Ipv6Header::decode(eth_payload);
                let ipv6_header = ipv6_header_result?;
                let direction = get_direction_from_ipv6(ipv6_header.clone(), device.clone());

                match ipv6_header.get_protocol() {
                    Protocol::UDP => {
                        let (udp_header_result, udp_payload) = UDPHeader::decode(ipv6_payload);
                        let udp_header = udp_header_result?;
                        let byte_transmitted = udp_payload.len();
                        match direction {
                            Direction::Received => {
                                let address = ipv6_header.get_src_address();
                                let port = udp_header.get_src_port();
                                Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                let address = ipv6_header.get_dest_address();
                                let port = udp_header.get_dest_port();
                                Ok(PacketInfo::new(address, port, Protocol::UDP, byte_transmitted, packet.timestamp))
                            }
                        }
                    },
                    Protocol::TCP => {
                        let (tcp_header_result, tcp_payload) = TCPHeader::decode(ipv6_payload);
                        let tcp_header = tcp_header_result?;
                        let byte_transmitted = tcp_payload.len();
                        match direction {
                            Direction::Received => {
                                let address = ipv6_header.get_src_address();
                                let port = tcp_header.get_src_port();
                                Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            },
                            Direction::Transmitted => {
                                let address = ipv6_header.get_dest_address();
                                let port = tcp_header.get_dest_port();
                                Ok(PacketInfo::new(address, port, Protocol::TCP, byte_transmitted, packet.timestamp))
                            }
                        }
                    },
                    Protocol::Unknown => {
                        Err(DecodeError { msg: format!("Unknown lev 4 protocol") })
                    }
                }
            }
            _ => Err(DecodeError { msg: "Cannot decode other level 3 header".parse().unwrap() }),
        };
    }

    #[derive(Debug, Clone, PartialEq)]
    struct PacketExt {
        data: Vec<u8>,
        timestamp: TimeVal,
    }

    impl PacketExt {
        pub fn new(data: &[u8], ts: libc::timeval) -> Self {
            PacketExt{data: Vec::from(data), timestamp: TimeVal{sec: ts.tv_sec as u32, u_sec: ts.tv_usec as u32}}
        }
    }

    #[derive(PartialEq, Debug, Clone, Eq)]
    pub enum RunStatus {
        Stop, Wait, Running, Error(String)
    }

    #[derive(Debug, PartialEq)]
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

    pub struct Sniffer {
        device: Option<pcap::Device>,
        status: Arc<(Mutex<RunStatus>, Condvar)>,
        file: Arc<Mutex<Option<File>>>,
        time_interval: u64,
        hashmap: Arc<Mutex<HashMap<(String, u16), (Protocol, usize, u64, u64)>>>,
    }

    impl Sniffer {
        pub fn new() -> Self {
            return Sniffer { device: None, status: Arc::new((Mutex::new(RunStatus::Stop), Condvar::new())),
                file: Arc::new(Mutex::new(None)), time_interval: 0, hashmap: Arc::new(Mutex::new(HashMap::new()))
            }
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
                            self.set_device(Some(device));
                            return Ok(())
                        }
                    }
                    return Err(SnifferError::UserError("The device selected is not in list ...".to_string()))
                },
                Err(error) => Err(error)
            }
        }

        pub fn run(&mut self) -> Result<(), SnifferError> {
            if self.get_file().clone().lock().unwrap().is_none() {
                return Err(SnifferError::UserError("File is null ...".to_string()));
            }
            if self.get_device().is_none() {
                return Err(SnifferError::UserError("You have to specify a device ...".to_string()));
            }
            self.set_status(RunStatus::Running);

            let device = self.get_device().clone().unwrap();
            print!("Running on {}", display_device(device.clone()));
            let (tx, rx) = channel();
            let tuple = self.status.clone();

            let _sniffer_thread = thread::spawn(move || {
                let mut cap = Capture::from_device(device).unwrap().promisc(true).open().unwrap();
                loop {
                    let mut _s = tuple.0.lock().unwrap();
                    let status = (*_s).clone();

                    match &status {
                        RunStatus::Running => {
                            drop(_s);
                            match cap.next_packet() {
                                Ok(packet) => {
                                    let res = tx.send(PacketExt::new(packet.data, packet.header.ts));
                                    match res {
                                        Ok(()) => continue,
                                        Err(error) => SnifferError::UserError(error.to_string())
                                    };
                                },
                                Err(error) => {
                                    SnifferError::PcapError(error);
                                }
                            }
                        },
                        RunStatus::Wait => {
                            _s = tuple.1.wait_while(_s, |status| { *status == RunStatus::Wait }).unwrap();
                        },
                        RunStatus::Stop => { break; }
                        RunStatus::Error(e) => { println!("{}", e) }
                    }
                    thread::sleep(Duration::from_micros(100));
                };
            });

            let device= self.get_device().clone().unwrap();
            let hashmap = self.get_hashmap().clone();

            let _decoder_thread = thread::spawn(move || {
                while let Ok(packet) = rx.recv() {
                    match decode_info_from_packet(device.clone(), packet) {
                        Ok(info) => {
                            let mut hm = hashmap.lock().unwrap();
                            let existing_pkt = hm.get(&(info.get_address(), info.get_port()));
                            match existing_pkt {
                                None => {
                                    hm.insert((info.get_address(), info.get_port()),
                                             (info.get_protocol(), info.get_byte_transmitted(), info.get_time_stamp().into(), info.get_time_stamp().into()));
                                },
                                value => {
                                    let bytes = info.get_byte_transmitted() + value.unwrap().clone().1;
                                    let first_time =  value.unwrap().clone().2;
                                    hm.insert((info.get_address(), info.get_port()),
                                             (info.get_protocol(), bytes, first_time, info.get_time_stamp().into()));
                                }
                            }
                        },
                        Err(_) => { }
                    }
                }
            });
            Ok(())
        }

        pub fn run_with_interval(&mut self) -> Result<(), SnifferError> {
            if self.get_time_interval() == 0 {
                return Err(SnifferError::UserError("You have to specify a time interval ...".to_string()));
            }

            let res = Sniffer::run(self);
            match res {
                Ok(()) => {}
                Err(error) => return Err(error)
            }

            let tuple = self.status.clone();
            let hashmap = self.get_hashmap().clone();
            let interval = self.get_time_interval().clone();
            let device = self.get_device().clone().unwrap();
            let file = self.get_file().clone();

            let _sleep_thread = thread::spawn(move || {
                let mut count = 0;
                loop {
                    let mut _s = tuple.0.lock().unwrap();
                    let status = (*_s).clone();

                    match &status {
                        RunStatus::Running => {
                            drop(_s);
                            let mut heading = String::new();
                            thread::sleep(Duration::from_secs(interval.clone()));
                            if count == 0 {
                                heading = Sniffer::heading(&device.clone());
                            }
                            let center = Sniffer::center(hashmap.clone());
                            heading.push_str(center.as_str());
                            match file.lock().unwrap().as_ref().unwrap().write(heading.as_bytes()) {
                                Ok(_) => {},
                                Err(_) => { break; }
                            }
                            count += 1;
                        },
                        RunStatus::Wait => {
                            _s = tuple.1.wait_while(_s, |status| { *status == RunStatus::Wait }).unwrap();
                        },
                        RunStatus::Stop => { break; }
                        RunStatus::Error(e) => { println!("{}", e) }
                    }
                }
                thread::sleep(Duration::from_micros(100));
            });
            Ok(())
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
                    self.status.1.notify_all();
                    Ok(())
                },
                RunStatus::Stop => { return Err(SnifferError::UserWarning("There is no scanning in execution ...".to_string())); },
                RunStatus::Running => { return Err(SnifferError::UserWarning("The scanning is already running ...".to_string())); }
            }
        }

        pub fn heading(device: &Device) -> String {
            let mut string = "Scanning on: \n\t- Interface ".to_string();
            string.push_str(device.name.as_str());
            string.push_str("\nAddresses: ");
            device.addresses.iter().for_each(|a| {
                string.push_str("\n\t- ");
                string.push_str(a.addr.to_string().as_str());
            });
            return string
        }

        pub fn center(hashmap: Arc<Mutex<HashMap<(String, u16), (Protocol, usize, u64, u64)>>>) -> String {
            let mut center = "\n\nScanning: \n\t- Update Time: ".to_string();
            center.push_str(Local::now().to_string().as_str());
            let mut table = Table::new();
            table.add_row(row!["IP Address", "Port", "Protocol", "Bytes Transmitted", "First Timestamp", "Last Timestamp"]);
            let hm = hashmap.clone();
            for (key, value) in hm.lock().unwrap().iter() {
                let first = pkt_parser::TimeVal::from(value.2);
                let last = pkt_parser::TimeVal::from(value.3);
                table.add_row(Row::new(vec![
                    Cell::new(key.0.as_str()),
                    Cell::new(key.1.to_string().as_str()),
                    Cell::new(value.0.to_string().as_str()),
                    Cell::new(value.1.to_string().as_str()),
                    Cell::new(format!("{}", Local.timestamp_opt(first.sec as i64, first.u_sec * 1000).unwrap().format("%H:%M:%S %f ns")).as_str()),
                    Cell::new(format!("{}", Local.timestamp_opt(last.sec as i64, last.u_sec * 1000).unwrap().format("%H:%M:%S %f ns")).as_str()),
                ]));
            }
            center.push_str("\n");
            center.push_str(table.to_string().as_str());
            return center
        }

        pub fn save_report(&self) -> Result<String, SnifferError> {
            let status = self.get_status();
            match &status {
                RunStatus::Error(error) => Err(SnifferError::UserError(error.to_string())),
                RunStatus::Stop => { Err(SnifferError::UserWarning("The scanning is already stopped ...".to_string())) },
                _ => {
                    if self.get_file().lock().unwrap().is_none() {
                        Err(SnifferError::UserError("The file doesn't exist ...".to_string()))
                    } else {
                        let write;
                        let center;
                        if self.get_time_interval() == 0 {
                            let _ = self.get_file().lock().unwrap().as_ref().unwrap().rewind();
                            let mut heading = Sniffer::heading(&self.device.as_ref().unwrap().clone());
                            center = Sniffer::center(self.get_hashmap().clone());
                            heading.push_str(center.as_str());
                            write = self.get_file().clone().lock().unwrap().as_ref().unwrap().write(heading.as_bytes());
                        } else {
                            center = Sniffer::center(self.get_hashmap().clone());
                            write = self.get_file().clone().lock().unwrap().as_ref().unwrap().write(center.as_bytes());
                        }
                        match write {
                            Ok(_) => {
                                self.set_status(RunStatus::Stop);
                                return Ok("The report has been saved and the scanning has been stopped ...".to_string());
                            },
                            Err(error) => Err(SnifferError::UserError(error.to_string()))
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

        pub fn get_file(&self) -> &Arc<Mutex<Option<File>>> {
            &self.file
        }

        pub fn set_file(&mut self, filename: String) -> Result<(), SnifferError> {
            let file = File::create(Path::new(&filename));
            match file {
                Ok(_) => {
                    self.file = Arc::new(Mutex::new(Some(file.unwrap())));
                    Ok(())
                },
                Err(_) => Err(SnifferError::UserError("The file can't be created ...".to_string()))
            }
        }

        pub fn get_status(&self) -> RunStatus {
            let s = self.status.0.lock().unwrap();
            return (*s).clone();
        }

        pub fn set_status(&self, status: RunStatus) -> () {
            let mut s = self.status.0.lock().unwrap();
            *s = status;
        }

        pub fn get_device(&self) -> &Option<pcap::Device> {
            &self.device
        }

        pub fn set_device(&mut self, device: Option<pcap::Device>) {
            self.device = device;
        }

        pub fn get_hashmap(&self) -> &Arc<Mutex<HashMap<(String, u16), (Protocol, usize, u64, u64)>>> {
            &self.hashmap
        }
    }
}