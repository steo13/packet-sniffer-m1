use std::io::{stdin, stdout, Write};
use std::ops::Deref;
use pcap::Device;
use ansi_term::Colour;
use ansi_term::Style;
use crate::sniffer_example::sniffer::{RunStatus, Sniffer};
use clap::Parser;
use std::fs::File;
use std::path::Path;

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
    let mut sniffer = Sniffer::new();
    let mut cmd = String::new();
    let _ = Args::parse();
    println!("Welcome to the Packet-Sniffer-M1 interface, write '?' or 'help' to know the list of possible commands");
    loop {
        cmd.clear();

        let mut status = sniffer.status.clone();
        let s = status.lock().unwrap().clone();
        std::mem::drop(status);

        let mut stat = "";
        match s {
            RunStatus::Running => { stat = "Running" },
            RunStatus::Wait => { stat = "Waiting" },
            RunStatus::Error(e) => { println!("{}", e); return; }
            _ => { stat = "" }
        }
        if stat == "" { print!("Packet-Sniffer-M1 >>> "); } else { print!("Packet-Sniffer-M1 ({}) >>> ", stat) }

        stdout().flush().unwrap();
        stdin().read_line(&mut cmd).unwrap();

        let status = sniffer.status.clone();
        let s = status.lock().unwrap().clone();

        match cmd.trim().to_ascii_lowercase().as_str() {
            "?" | "help" => { help() },
            "devices" => { devices() },
            "exit" => {
                match s {
                    RunStatus::Running | RunStatus::Wait => {
                        std::mem::drop(status);
                        let mut cmd = String::new();
                        print!("Would you want to stop the running and save? (yes for saving/anything else for no) ");
                        stdout().flush().unwrap();
                        stdin().read_line(&mut cmd).unwrap();

                        match cmd.trim().to_ascii_lowercase().as_str() {
                            "yes" => {
                                let res = sniffer.save_report();
                                if res.is_err() {
                                    println!("{}", res.err().unwrap());
                                }
                                return;
                            },
                            _ => return
                        }
                    },
                    _ => { return; }
                }
            },
            "pause" => {
                match s {
                    RunStatus::Running => {
                        std::mem::drop(status);
                        let res = sniffer.pause();
                        if res.is_err() {
                            println!("{}", res.err().unwrap());
                            return
                        }
                    },
                    RunStatus::Error(e) => { println!("{}", e); return; },
                    _ => {}
                }
            },
            "resume" => {
                match s {
                    RunStatus::Wait => {
                        std::mem::drop(status);
                        let res = sniffer.resume();
                        if res.is_err() {
                            println!("{}", res.err().unwrap());
                            return
                        }
                    },
                    RunStatus::Error(e) => { println!("{}", e); return; },
                    _ => {}
                }
            },
            "stop" => {
                let res = sniffer.save_report();
                match s {
                    RunStatus::Stop => { println!("The sniffing is not running"); },
                    _ => {
                        if res.is_err() {
                            println!("{}", res.err().unwrap());
                        }
                        return;
                    }
                }
            },
            x => {
                if x.starts_with("sniffing") {
                    //TODO: check if another sniffing is already running
                    let split: Vec<&str> = x.split(" ").filter(|x| *x != "").collect();

                    let pos_file = split.iter().position(|x| *x == "-file");
                    if pos_file.is_none() {
                        println!("The file argument is mandatory, please insert something");
                        continue
                    } else {
                        if pos_file.unwrap() == split.len() - 1 || split.get(pos_file.unwrap() + 1).unwrap().starts_with("-") {
                            println!("Please insert a filename (not an argument, just a name)");
                            continue
                        } else {
                            let pos_interval = split.iter().position(|x| *x == "-interval");
                            if pos_interval.is_some() {
                                if pos_interval.unwrap() == split.len() - 1 || split.get(pos_interval.unwrap() + 1).unwrap().trim().parse::<u64>().is_err() {
                                    println!("Please insert a positive number for the interval (sec)");
                                    continue
                                } else {
                                    sniffer.set_time_interval(split.get(pos_interval.unwrap() + 1).unwrap().trim().parse::<u64>().unwrap());
                                }
                            }
                        }
                    }
                    sniffer.set_file(Some(File::create(Path::new(*split.get(pos_file.unwrap() +1).unwrap())).unwrap()));
                    //TODO: use run method
                }
                else{
                    println!("Unknown command!")
                }
            }
        }
    };
}

fn help() {
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
}

fn devices() {
    let devices = Device::list().unwrap();
    println!("All the devices which could be sniffed are:");
    for device in devices { print!("{} ", Colour::Blue.paint(device.name)); }
    print!("\n");
}