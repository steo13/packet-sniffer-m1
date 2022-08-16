/*
use std::fmt::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use crate::collect_signals::collect_signals;
use crate::pkt_parser::{DecodeError, EthernetHeader, EtherType, Header, Ipv4Header, Protocol, TCPHeader, UDPHeader};

pub struct Sniffer {
    device: Option<pcap::Device>,
    status: Arc<Mutex<RunStatus>>,
    file: Option<File>,
    time_interval: u64
}

#[derive(PartialEq)]
pub enum RunStatus {
    Stop, Wait, Running, Error(String)
}

pub enum SnifferError {
    PcapError(pcap::Error), DecodeError(DecodeError), UserError(String)
}

impl Sniffer {
    fn new() -> Self {
        return Sniffer { device: None, status: Arc::new(Mutex::new(RunStatus::Stop)), file: None, time_interval: 0 }
    }

    fn list_devices() -> Result<Vec<pcap::Device>, SnifferError> {
        let devices = pcap::Device::list();
        return match devices {
            Ok(devices) => Ok(devices),
            Err(e) => Err(SnifferError::PcapError(e)),
        }
    }

    fn attach(&mut self, device: pcap::Device) -> Result<(), SnifferError> {
        return match Sniffer::list_devices() {
            Ok(devices) => {
                for dev in &devices {
                    if dev.name == device.name {
                        self.device = Some(device);
                        return Ok(())
                    }
                }
                return Err(SnifferError::UserError("The device selected is not in list".to_string()))
            },
            Err(_) => Err(SnifferError::UserError("There aren't devices to select".to_string()))
        }
    }

    fn run(&mut self, filename: String) -> Result<(), SnifferError> {
        let file = File::open(Path::new(&filename));
        let mut s = self.status.lock().unwrap();
        return match file {
            Ok(_) => {
                *s = RunStatus::Running;
                self.file = Some(file.unwrap());
                Ok(())
            },
            Err(_) => Err(SnifferError::UserError("The file doesn't exist".to_string()))
        }
    }

    fn run_with_interval(&mut self, time_interval: u64, filename: String) -> Result<(), SnifferError> {
        let file = File::open(Path::new(&filename));
        let mut s = self.status.lock().unwrap();
        return match file {
            Ok(_) => {
                *s = RunStatus::Running;
                self.file = Some(file.unwrap());
                self.time_interval = time_interval;
                Ok(())
            },
            Err(e) => Err(SnifferError::UserError("The file doesn't exist".to_string()))
        }
    }

    fn pause(&mut self) -> Result<(), SnifferError> {
        let mut s = self.status.lock().unwrap();
        match *s {
            RunStatus::Error(_) => Err(SnifferError::UserError("The running has stopped".to_string())),
            _ => {
                *s = RunStatus::Wait;
                Ok(())
            }
        }
    }

    fn resume(&mut self) -> Result<(), SnifferError> {
        let mut s = self.status.lock().unwrap();
        match *s {
            RunStatus::Error(_) => Err(SnifferError::UserError("The running has stopped".to_string())),
            _ => {
                *s = RunStatus::Running;
                Ok(())
            }
        }
    }

    fn save_report(&self) -> Result<(), SnifferError> {
        let mut s = self.status.lock().unwrap();
        return match *s {
            RunStatus::Stop => Err(SnifferError::UserError("The device is not running".to_string())),
            _ => {
                match &self.file {
                    None => Err(SnifferError::UserError("The file doesn't exist".to_string())),
                    Some(_) => {
                        let write = self.file.as_ref().unwrap().write("Prova".as_ref());
                        match write {
                            Ok(_) => Ok(()),
                            Err(_) => Err(SnifferError::UserError("The file can't be saved".to_string()))
                        }
                    }
                }
            },
        }
    }
}
*/