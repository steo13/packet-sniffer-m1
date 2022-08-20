pub mod sniffer {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::fmt::{Display, Formatter};

    pub struct Sniffer {
        device: Option<pcap::Device>,
        pub status: Arc<Mutex<RunStatus>>,
        file: Option<File>,
        time_interval: u64
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
                    return Err(SnifferError::UserError("The device selected is not in list".to_string()))
                },
                Err(_) => Err(SnifferError::UserError("There aren't devices to select".to_string()))
            }
        }

        pub fn run(&mut self, filename: String) -> Result<(), SnifferError> {
            let mut s = self.status.lock().unwrap();
            let file = File::create(Path::new(&filename));
            match file {
                Ok(_) => {
                    *s = RunStatus::Running;
                    self.file = Some(file.unwrap());
                    Ok(())
                },
                Err(_) => Err(SnifferError::UserError("The file can't be created".to_string()))
            }
        }

        pub fn run_with_interval(&mut self, time_interval: u64, filename: String) -> Result<(), SnifferError> {
            let mut s = self.status.lock().unwrap();
            let file = File::create(Path::new(&filename));
            match file {
                Ok(_) => {
                    *s = RunStatus::Running;
                    self.file = Some(file.unwrap());
                    self.time_interval = time_interval;
                    Ok(())
                },
                Err(_) => Err(SnifferError::UserError("The file can't be created".to_string()))
            }
        }

        pub fn pause(&mut self) -> Result<(), SnifferError> {
            let mut s = self.status.lock().unwrap();
            match *s {
                RunStatus::Error(_) => Err(SnifferError::UserError("The running has stopped".to_string())),
                _ => {
                    *s = RunStatus::Wait;
                    Ok(())
                }
            }
        }

        pub fn resume(&mut self) -> Result<(), SnifferError> {
            let mut s = self.status.lock().unwrap();
            match *s {
                RunStatus::Error(_) => Err(SnifferError::UserError("The running has stopped".to_string())),
                _ => {
                    *s = RunStatus::Running;
                    Ok(())
                }
            }
        }

        pub fn save_report(&self) -> Result<(), SnifferError> {
            let s = self.status.lock().unwrap();
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

        pub fn time_interval(&self) -> u64 {
            self.time_interval
        }

        pub fn set_time_interval(&mut self, time_interval: u64) {
            self.time_interval = time_interval;
        }

        pub fn file(&self) -> &Option<File> {
            &self.file
        }

        pub fn set_file(&mut self, file: Option<File>) {
            self.file = file;
        }
    }
}