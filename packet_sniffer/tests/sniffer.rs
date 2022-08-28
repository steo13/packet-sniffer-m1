use packet_sniffer::sniffer::{RunStatus, Sniffer, SnifferError};

#[test]
fn init_status_is_stop() {
    let sniffer = Sniffer::new();
    assert_eq!(sniffer.get_status(), RunStatus::Stop)
}

#[test]
fn run_without_device_or_file_should_fail() {
    let mut sniffer = Sniffer::new();
    let res = sniffer.run();
    assert!(res.is_err());
    assert_eq!(sniffer.get_status(), RunStatus::Stop);
    assert_eq!(res.unwrap_err(), SnifferError::UserError("File is null ...".to_string()))

}

