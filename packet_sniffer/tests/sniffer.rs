use packet_sniffer::sniffer::{RunStatus, Sniffer, SnifferError};
use packet_sniffer::sniffer::SnifferError::{UserError, UserWarning};

#[test]
fn init_status_is_stop() {
    let sniffer = Sniffer::new();
    assert_eq!(sniffer.get_status(), RunStatus::Stop)
}

#[test]
fn run_without_device_should_fail() {
    let mut sniffer = Sniffer::new();
    match sniffer.set_file("prova.txt".to_string()) {
        Ok(_) => {
            let res = sniffer.run();
            assert_eq!(sniffer.get_status(), RunStatus::Stop);
            assert!(res.is_err());
            assert_eq!(res.unwrap_err(), SnifferError::UserError("You have to specify a device ...".to_string()))
        },
        Err(_e) => {
            ()
        }
    }

}

#[test]
fn run_without_file_should_fail() {
    let mut sniffer = Sniffer::new();
    let device = match Sniffer::list_devices() {
        Ok(devices) => devices[0].clone(),
        Err(_) => { panic!("Pcap error"); }
    };
    match sniffer.attach(device) {
        Ok(_) => {
            let res = sniffer.run();
            assert_eq!(sniffer.get_status(), RunStatus::Stop);
            assert!(res.is_err());
            assert_eq!(res.unwrap_err(), SnifferError::UserError("File is null ...".to_string()))
        },
        Err(_) => {
            ()
        }
    }
}

#[test]
fn save_report_without_sniffing() {
    let sniffer = Sniffer::new();
    let res = sniffer.save_report();
    assert_eq!(sniffer.get_status(), RunStatus::Stop);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), SnifferError::UserWarning("The scanning is already stopped ...".to_string()))
}

#[test]
fn run_with_interval_without_interval() {
    let mut sniffer = Sniffer::new();
    match sniffer.set_file("prova.txt".to_string()) {
        Ok(_) => {
            let device = match Sniffer::list_devices() {
                Ok(devices) => devices[0].clone(),
                Err(_) => { panic!("Pcap error"); }
            };
            match sniffer.attach(device) {
                Ok(_) => {
                    let res = sniffer.run_with_interval();
                    assert_eq!(sniffer.get_status(), RunStatus::Stop);
                    assert!(res.is_err());
                    assert_eq!(res.unwrap_err(), SnifferError::UserError("You have to specify a time interval ...".to_string()))
                },
                Err(_) => {
                    panic!("Repeat the test");
                }
            }
        },
        Err(_e) => {
            panic!("Repeat the test");
        }
    }
}

#[test]
fn run_while_already_sniffing() {
    let mut sniffer = Sniffer::new();
    match sniffer.set_file("prova.txt".to_string()) {
        Ok(_) => {
            let device = match Sniffer::list_devices() {
                Ok(devices) => devices[0].clone(),
                Err(_) => { panic!("Pcap error"); }
            };
            match sniffer.attach(device) {
                Ok(_) => {
                    let res = sniffer.run();
                    assert!(res.is_ok());
                    assert_eq!(sniffer.get_status(), RunStatus::Running);
                    let res2 = sniffer.run();
                    assert!(res2.is_err());
                    assert_eq!(res2.unwrap_err(), SnifferError::UserWarning("Another scanning is already running ...".to_string()));
                    sniffer.set_time_interval(10);
                    let res3 = sniffer.run_with_interval();
                    assert!(res3.is_err());
                    assert_eq!(res3.unwrap_err(), SnifferError::UserWarning("Another scanning is already running ...".to_string()));
                },
                Err(_) => {
                    panic!("Repeat the test");
                }
            }
        },
        Err(_e) => {
            panic!("Repeat the test");
        }
    }
}

#[test]
fn resume_without_running() {
    let mut sniffer = Sniffer::new();
    let res = sniffer.resume();
    assert_eq!(sniffer.get_status(), RunStatus::Stop);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), SnifferError::UserWarning("There is no scanning in execution ...".to_string()));
}

#[test]
fn resume_while_running() {
    let mut sniffer = Sniffer::new();
    match sniffer.set_file("prova.txt".to_string()) {
        Ok(_) => {
            let device = match Sniffer::list_devices() {
                Ok(devices) => devices[0].clone(),
                Err(_) => { panic!("Pcap error"); }
            };
            match sniffer.attach(device) {
                Ok(_) => {
                    let res = sniffer.run();
                    assert!(res.is_ok());
                    assert_eq!(sniffer.get_status(), RunStatus::Running);
                    let res2 = sniffer.resume();
                    assert!(res2.is_err());
                    assert_eq!(res2.unwrap_err(),SnifferError::UserWarning("The scanning is already running ...".to_string()));
                },
                Err(_) => {
                    panic!("Repeat the test");
                }
            }
        },
        Err(_e) => {
            panic!("Repeat the test");
        }
    }
}

#[test]
fn pause_without_running(){
    let mut sniffer = Sniffer::new();
    let res = sniffer.pause();
    assert_eq!(sniffer.get_status(), RunStatus::Stop);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), SnifferError::UserWarning("There is no scanning in execution ...".to_string()));
}

#[test]
fn pause_while_already_paused() {
    let mut sniffer = Sniffer::new();
    match sniffer.set_file("prova.txt".to_string()) {
        Ok(_) => {
            let device = match Sniffer::list_devices() {
                Ok(devices) => devices[0].clone(),
                Err(_) => { panic!("Pcap error"); }
            };
            match sniffer.attach(device) {
                Ok(_) => {
                    let res = sniffer.run();
                    assert!(res.is_ok());
                    assert_eq!(sniffer.get_status(), RunStatus::Running);
                    let res2 = sniffer.pause();
                    assert!(res2.is_ok());
                    assert_eq!(sniffer.get_status(), RunStatus::Wait);
                    let res3 = sniffer.pause();
                    assert!(res3.is_err());
                    assert_eq!(res3.unwrap_err(), SnifferError::UserWarning("The scanning is already paused ...".to_string()));
                },
                Err(_) => {
                    panic!("Repeat the test");
                }
            }
        },
        Err(_e) => {
            panic!("Repeat the test");
        }
    }
}