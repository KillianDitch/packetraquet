# packetraquet
p@cketr@quet repo

A) This project has more bugs than the Amazon rainforest - those that I know about, I don't know how to fix yet. Those that I don't know about, I can pretend don't exist.
B) I'm in the process of trimming up sound files to be uploaded.
C) I've no idea what I'm doing when it comes to publishing a tool/code to the Internet.

Description: 
P@cketr@quet is a Python tool to play music (sounds/noise at the moment) based on network traffic patterns. It's a relatively basic analyzer in that it looks at low-level protocols and TCP/UDP ports, then refers to a mapping to play the corresponding sounds.

Installation: 
Right now, a standard Unix distro *should* be able to run the basic_r@quet.py script. For p@cketr@quet.py, Scapy is required. Also, the sounds will need to be either assigned or downloaded from a future release.

Usage: 
sudo ./basic_ra@quet.py

sudo ./basic_r@quet.py -i lo

sudo ./p@cket_r@quet.py 

usage: p@cketr@quet.py [-h] [-i INTERFACE] [-p PCAP] [-v]

Listen to network traffic.

optional arguments:

  -h, --help            show this help message and exit
  
  -i INTERFACE, --interface INTERFACE
  
                        Network interface on which to sniff traffic.
                        
  -p PCAP, --pcap PCAP  Pre-captured pcap file.
  
  -v, --verbose         TODO: Outputs sniffed traffic to stdout.
  
