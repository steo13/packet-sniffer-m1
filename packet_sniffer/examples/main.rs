use std::sync::mpsc::channel;
use std::thread;
use pcap::{Capture, Device};

fn main() {
    /*println!("Ex - 02 reading from a pcap file");
    println!("Multithread example");

    let (tx, rx) = channel();
    let t1 = thread::spawn(move || {
        let tx = tx.clone();
        let mut cap = Capture::from_file("sample_capture.pcap").unwrap();
        while let Ok(packet) = cap.next() {
            tx.send(Vec::from(packet.data)).unwrap();
            //println!("{:?}", Vec::from(packet.data));
        }

        drop(tx);
    });

    while let Ok(packet) = rx.recv() {
        match packet_sniffer::decode_packet(packet) {
            Ok(()) => (),
            Err(e) => println!("{:?}", e)
        }
    }*/
    let devices = Device::list().unwrap();
    println!("The devices that could be monitored are:");
    for device in devices { print!("{} ", device.name) }
    println!("\nChoose one of them >>> ");

}