# Packet-Sniffer-M1 Project
Project for the **Programmazione di Sistema** exam of Politecnico of Turin.

## Overview
The project aims at building a multiplatform application capable of intercepting incoming
and outgoing traffic through the network interfaces of a computer. The application will set
the network adapter in promiscuous mode, collect IP address, port and protocol type of
observed traffic and will generate a textual report describing a synthesis of the observed
events. 

More details about the project could be reached from the [projects.pdf file](https://gitlab.com/gabbiurlaro/packet-sniffer-m1/-/blob/main/packet_sniffer/files/projects.pdf) 
(Project M1 section).

## Run
In order to sniff the network traffic, it is possible to run the program in two different ways:

- **With Arguments**: `cargo run -- --file ... [--interval ...]`

In this case you have to specify a **name for the file** in which you want to  save the final 
report, and optionally, also an **interval expressed in seconds** relative to the 
frequency of saving the scans on the file specified above.
After this a prompt will appear where you can enter commands to manage the scanning. 
They can be [viewed in the section below](#commands)

- **Without Arguments**: `cargo run`

In this case, a **command prompt** will appear, through which it will be possible 
to manage sniffing. The commands that can be used in this phase can be [viewed 
in the section below](#commands)

### Commands
- `?` or `help`: if you want to visualize the list of possible commands
- `devices`: if you want to visualize the lis of possible devices
- `sniff --file ... [--interval ...]`: if you want to start a sniffing, and save the report
in the file specified (the option **--interval** is optional if you want to update the report
after a tot number of seconds)
- `pause`: if you want to pause the sniffing (if one is running)
- `resume`: if you want to resume the sniffing (if one is in pause)
- `stop`: if you want to stop the sniffing (if one is running) and save the final report
- `exit`: if you want to exit from the application

## Report
Examples of final report which could be reached are:
- [Report](https://gitlab.com/gabbiurlaro/packet-sniffer-m1/-/blob/main/packet_sniffer/files/report): scanning **without time interval**
- [Report with time interval](https://gitlab.com/gabbiurlaro/packet-sniffer-m1/-/blob/main/packet_sniffer/files/report_interval): scanning with **10 sec of time interval**

## Contributors
- Stefano Rainò, s282436
- Alberto Castrignanò, ...
- Gabriele Iurlaro, s294917
