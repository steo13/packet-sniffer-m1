use std::io::{stdin, stdout, Write};
use pcap::Device;
use ansi_term::Colour;
use ansi_term::Style;
use crate::sniffer_example::sniffer::Sniffer;
use clap::Parser;
mod sniffer_example;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value_t = 0)]
    interval: u64,
    #[clap(short, long, value_parser, default_value = "None")]
    file: String
}

fn main() {
    let _ = Sniffer::new();
    let mut cmd = String::new();
    let _ = Args::parse();
    println!("Welcome to the Packet-Sniffer-M1 interface, write '?' or 'help' to know the list of possible commands");
    loop {
        cmd.clear();
        print!("Packet-Sniffer-M1 >>> ");
        stdout().flush().unwrap();
        stdin().read_line(&mut cmd).unwrap();
        match cmd.trim().to_ascii_lowercase().as_str() {
            "?" | "help" => {
                println!("The commands available are:");
                println!("-> {} {} {} {} {}", Colour::Red.paint("sniffing"),
                         Colour::Blue.paint("-device"), Colour::Blue.italic().paint("device_name"),
                         Colour::Yellow.paint("-file"), Colour::Yellow.italic().paint("file_name"));
                println!("-> {} {} {} {} {} {} {}", Colour::Red.paint("sniffing"),
                         Colour::Blue.paint("-device"), Colour::Blue.italic().paint("device_name"),
                         Colour::Green.paint("-interval"), Colour::Green.italic().paint("time_interval (sec)"),
                         Colour::Yellow.paint("-file"), Colour::Yellow.italic().paint("file_name"));
                println!("-> {} (List of all the devices available)", Colour::Red.paint("devices"));
                println!("-> {} (Pause the sniffing if it is running)", Colour::Red.paint("pause"));
                println!("-> {} (Resume the sniffing)", Colour::Red.paint("resume"));
                println!("-> {} (Stop the sniffing)", Colour::Red.paint("stop"));
                println!("-> {} (Exit from the sample application)", Colour::Red.paint("exit"));
            },
            "devices" => {
                let devices = Device::list().unwrap();
                println!("All the devices which could be sniffed are:");
                for device in devices { print!("{} ", Colour::Blue.paint(device.name)); }
                print!("\n");
            },
            "exit" => return,
            _ => println!("Unknown command!")
        }
    };
}