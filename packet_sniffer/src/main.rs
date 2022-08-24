use std::env::args;
use std::io::{stdin, stdout, Write};
use std::ops::Deref;
use pcap::Device;
use ansi_term::Colour;
use ansi_term::Style;
use clap::Parser;
use std::fs::File;
use std::path::Path;
use std::process::exit;
use packet_sniffer::sniffer::{RunStatus, Sniffer};


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
    let args = Args::parse();

    if args.file == "None" && args.interval == 0 {
        println!("Welcome to the Packet-Sniffer-M1 interface, write '{}' or '{}' to know the list of possible commands",
                 Colour::Red.italic().paint("?"), Colour::Red.italic().paint("help"));
    } else {
        if args.interval > 0 && args.file == "None" {
            print!("{}", Colour::Yellow.italic().paint("If you have run the application with arguments, the --file argument is mandatory ..."));
            return;
        } else {
            devices();
            sniffing(&mut sniffer);
        }
    }

    loop {
        cmd.clear();
        let status = sniffer.get_status();

        prompt(&status);
        stdout().flush().unwrap();
        stdin().read_line(&mut cmd).unwrap();

        match cmd.trim().to_ascii_lowercase().as_str() {
            "?" | "help" => { help() },
            "devices" => { devices() },
            "exit" => { exit_prompt(&sniffer) },
            "pause" => {
                match &status {
                    RunStatus::Running => {
                        let res = sniffer.pause();
                        if res.is_err() { println!("{}", res.err().unwrap()); return; }
                    },
                    RunStatus::Error(e) => { println!("{}", e); return; },
                    RunStatus::Stop => { println!("There is no scanning in execution ..."); },
                    RunStatus::Wait => { println!("The scanning is already paused ..."); }
                }
            },
            "resume" => {
                match &status {
                    RunStatus::Wait => {
                        let res = sniffer.resume();
                        if res.is_err() { println!("{}", res.err().unwrap()); return; }
                    },
                    RunStatus::Error(e) => { println!("{}", e); return; },
                    RunStatus::Stop => { println!("There is no scanning in execution ..."); },
                    RunStatus::Running => { println!("The scanning is already running ..."); }
                }
            },
            "stop" => {
                let res = sniffer.save_report();
                if res.is_err() {
                    println!("{}", res.err().unwrap());
                    return;
                }
                match &status {
                    RunStatus::Stop => { println!("The scanning is not running ..."); },
                    _ => {
                        println!("The report has been saved and the scanning has been stopped ...");
                        sniffer.set_status(RunStatus::Stop);
                    }
                }
            },
            x => {
                if x.starts_with("sniff") {
                    match &status {
                        RunStatus::Running | RunStatus::Wait => { println!("Another scanning is already running"); },
                        _ => {
                            let split: Vec<&str> = x.split(" ").filter(|x| *x != "").collect();

                            let pos_file = split.iter().position(|x| *x == "--file");
                            if pos_file.is_none() {
                                println!("The file argument is mandatory, please insert something ...");
                                continue
                            } else {
                                if pos_file.unwrap() == split.len() - 1 || split.get(pos_file.unwrap() + 1).unwrap().starts_with("-") {
                                    println!("Please insert a filename (not an argument, just a name) ...");
                                    continue
                                } else {
                                    let pos_interval = split.iter().position(|x| *x == "--interval");
                                    if pos_interval.is_some() {
                                        if pos_interval.unwrap() == split.len() - 1 || split.get(pos_interval.unwrap() + 1).unwrap().trim().parse::<u64>().is_err() {
                                            println!("Please insert a positive number for the interval (sec) ...");
                                            continue
                                        } else {
                                            sniffer.set_time_interval(split.get(pos_interval.unwrap() + 1).unwrap().trim().parse::<u64>().unwrap());
                                        }
                                    }
                                }
                            }
                            match sniffer.set_file((*split.get(pos_file.unwrap() + 1).unwrap().to_string()).to_string()) {
                                Ok(()) => {},
                                Err(e) => { println!("{}", e); return; }
                            }
                            devices();
                            sniffing(&mut sniffer);
                        }
                    }
                }
                else{
                    println!("Unknown command!")
                }
            }
        }
    };
}

fn prompt(status: &RunStatus) {
    let mut stat = "";
    match status {
        RunStatus::Running => { stat = "Running"; print!("Packet-Sniffer-M1 ({}) >>> ", Colour::Green.italic().paint("Running")); },
        RunStatus::Wait => { stat = "Waiting"; print!("Packet-Sniffer-M1 ({}) >>> ", Colour::Yellow.italic().paint("Waiting"));},
        RunStatus::Error(e) => { println!("{}", e); return; }
        _ => { stat = "No Sniffing"; print!("Packet-Sniffer-M1 ({}) >>> ", Colour::Blue.italic().paint("No Running"));}
    }
}

fn help() {
    println!("The commands available are:");
    println!("-> {} {} {} {} {}", Colour::Red.paint("sniff"),
             Colour::Yellow.paint("--file"), Colour::Yellow.italic().paint("file_name"),
             Colour::Green.paint("[--interval"), Colour::Green.paint("time_interval (sec)]"));
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

fn exit_prompt(sniffer: &Sniffer) {
    match sniffer.get_status() {
        RunStatus::Running | RunStatus::Wait => {
            let mut cmd = String::new();
            print!("Would you want to stop the scanning and save? (yes for saving/anything else for no) ");
            stdout().flush().unwrap();
            stdin().read_line(&mut cmd).unwrap();

            match cmd.trim().to_ascii_lowercase().as_str() {
                "yes" => {
                    let res = sniffer.save_report();
                    if res.is_err() { println!("{}", res.err().unwrap()); }
                    exit(1);
                },
                _ => exit(2)
            }
        },
        _ => { exit(0); }
    }
}

fn sniffing(sniffer: &mut Sniffer) {
    let mut cmd = String::new();
    print!("Which device would you sniff? ");

    loop {
        cmd.clear();
        stdout().flush().unwrap();
        stdin().read_line(&mut cmd).unwrap();

        match cmd.trim().to_ascii_lowercase().as_str() {
            "exit" => exit_prompt(&sniffer),
            _ => {
                for device in Device::list().unwrap() {
                    if device.name == cmd.trim().to_string().as_str() {
                        match sniffer.attach(device) {
                            Ok(()) => (),
                            Err(e) => { println!("{}", e); exit(1)},
                        };
                        if sniffer.get_time_interval() == 0 {
                            match sniffer.run() {
                                Err(e) => { println!("{}", e); exit(1); }
                                _ => {}
                            }
                            println!("The scanning is running ...")
                        } else {
                            match sniffer.run_with_interval() {
                                Err(e) => { println!("{}", e); exit(1); }
                                _ => {}
                            }
                            println!("The scanning is running (saving after {} {}) ...",
                                     Colour::Red.paint(sniffer.get_time_interval().to_string().as_str()), Colour::Red.paint("sec"));
                        }
                        return;
                    }
                }
                print!("Insert a valid device name, which device would you sniff? ");
            }
        }
    }
}