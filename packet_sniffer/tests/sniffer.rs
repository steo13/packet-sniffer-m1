use packet_sniffer::sniffer::{RunStatus, Sniffer, SnifferError};

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
