#!/usr/bin/python

# Imports
from scapy.all import *
import os
import ctypes
import math
import struct
import wave
import argparse


# Process arguments from command line.
def prs_arg():
    parser = argparse.ArgumentParser(description="Listen to network traffic.")
    parser.add_argument("-i", "--interface", help="Network interface on which to sniff traffic.", default="ens33")
    parser.add_argument("-p", "--pcap", help="Pre-captured pcap file.")
    parser.add_argument("-v", "--verbose", help="TODO: Outputs sniffed traffic to stdout.", action="store_true")
    return parser.parse_args()

    
# Check for the existence of the audio tones and call the creation function if needed.
def check_wavs():
    if not os.path.exists("tunes"):
        print "Missing audio files."
        exit()
        #TODO - check for beeps, if not present, create them. Use a BOOL var to route sounds

# Play the supplied wav file.
def play_sound(wav_file):
	
	# Hack to work with new files until issues figured out.
	os.system('aplay -q %s' % wav_file)
	
'''
    PA_STREAM_PLAYBACK = 1
    PA_SAMPLE_S16LE = 3
    BUFFSIZE = 1024

    class struct_pa_sample_spec(ctypes.Structure):
        _fields_ = [("format", ctypes.c_int), ("rate", ctypes.c_uint32), ("channels", ctypes.c_uint8)]

    pa = ctypes.cdll.LoadLibrary("libpulse-simple.so.0")
    
    wave_file = wave.open(wav_file, "rb")

    pa_sample_spec = struct_pa_sample_spec()
    pa_sample_spec.rate = wave_file.getframerate()
    pa_sample_spec.channels = wave_file.getnchannels()
    pa_sample_spec.format = PA_SAMPLE_S16LE

    error = ctypes.c_int(0)

    pa_stream = pa.pa_simple_new(None, wav_file, PA_STREAM_PLAYBACK, None, "playback", ctypes.byref(pa_sample_spec), None, None, ctypes.byref(error))
    if not pa_stream:
        raise Exception("Could not create pulse audio stream: %s" % pa.strerror(ctypes.byref(error)))

    while True:
        latency = pa.pa_simple_get_latency(pa_stream, ctypes.byref(error))
        if latency == -1:
            raise Exception("Getting latency failed")

        buf = wave_file.readframes(BUFFSIZE)
        if not buf:
            break

        if pa.pa_simple_write(pa_stream, buf, len(buf), ctypes.byref(error)):
            raise Exception("Could not play file")

    wave_file.close()

    if pa.pa_simple_drain(pa_stream, ctypes.byref(error)):
        raise Exception("Could not simple drain")

    pa.pa_simple_free(pa_stream)
'''
    
# Designate audio tones for the protocols found in each packet.
def make_music(pckt):
        
    # TODO: Add layer to handle IGMP p.proto = 6, switch up haslayer() to pckt.proto = (ARP won't have it - based on IP header)
    '''
    IPPROTO_IP = 0,            /* Dummy protocol for TCP        */
    IPPROTO_ICMP = 1,        /* Internet Control Message Protocol    */
    IPPROTO_IGMP = 2,        /* Internet Group Management Protocol    */
    IPPROTO_IPIP = 4,        /* IPIP tunnels (older KA9Q tunnels use 94) */
    IPPROTO_TCP = 6,        /* Transmission Control Protocol    */
    IPPROTO_EGP = 8,        /* Exterior Gateway Protocol        */
    IPPROTO_PUP = 12,        /* PUP protocol                */
    IPPROTO_UDP = 17,        /* User Datagram Protocol        */
    IPPROTO_IDP = 22,        /* XNS IDP protocol            */
    IPPROTO_DCCP = 33,        /* Datagram Congestion Control Protocol */
    IPPROTO_RSVP = 46,        /* RSVP protocol            */
    IPPROTO_GRE = 47,        /* Cisco GRE tunnels (rfc 1701,1702)    */
    IPPROTO_IPV6 = 41,        /* IPv6-in-IPv4 tunnelling        */
    '''
    
    if pckt.haslayer(ARP):
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-01.wav")
    elif pckt.haslayer(IPv6):
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-03_6.wav")       
    elif pckt.haslayer(ICMP):
		if pckt[ICMP].type == 8:
			wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-02.wav")
		else:
			wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-04.wav")
    elif pckt.proto == 2: # Scapy has no mapping for IGMP
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-01.wav")
    elif pckt.haslayer(UDP):
        if pckt.haslayer(DNS):
            if pckt.sport == 53:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")
            elif pckt.dport == 53:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-03.wav")
        elif pckt.haslayer(DHCP):
            if pckt.sport == 67:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_3.wav")
            elif pckt.dport == 67:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-04.wav")
        elif pckt.haslayer(TFTP):
            if pckt.sport == 69:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_13.wav")
            elif pckt.dport == 69:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-04.wav")
        elif pckt.haslayer(NTP):
            if pckt.sport == 123:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_2.wav")
            elif pckt.dport == 123:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-08.wav")
        elif pckt.haslayer(SNMP):
            if pckt.sport == 161:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_3.wav")
            elif pckt.dport == 161:
                wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-10.wav")
        elif pckt.sport == 1900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_5.wav")
        elif pckt.dport == 1900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-12.wav")
        else:
            # Default sound for UDP traffic
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_0.wav")
    elif pckt.haslayer(TCP):
        if pckt.sport == 21:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 21:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 22:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_7.wav")
        elif pckt.dport == 22:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-15.wav")
        elif pckt.sport == 23:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120SC-04_1.wav")
        elif pckt.dport == 23:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-17.wav")
        elif pckt.sport == 25:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_1.wav")
        elif pckt.dport == 25:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-02.wav")
        elif pckt.sport == 53:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_5.wav")
        elif pckt.dport == 53:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 80:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_1.wav")
        elif pckt.dport == 80:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-05.wav")
        elif pckt.sport == 81:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 81:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-05.wav")
        elif pckt.sport == 110:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 110:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-06.wav")
        elif pckt.sport == 135 or pckt.sport == 139 or pckt.sport == 445:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 135 or pckt.dport == 139 or pckt.dport == 445:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-07.wav")
        elif pckt.sport == 443:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-08.wav")
        elif pckt.dport == 443:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_19.wav")
        else:
            # Default sound for TCP traffic
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_1.wav")
    else:
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")

    play_sound(wav_file)
    
    # Output packet details if the verbose flag is passed.
    if prs_arg().verbose:
        return pckt.summary()

def main():
    print('Starting...')

    # Start Scapy sniffer for a pcap or on an interface.  For each packet, execute make_music() and do not store it.
    if prs_arg().pcap:
        sniff(offline=prs_arg().pcap, prn=make_music)
    else:
        print "Sniffing on interface %s." % prs_arg().interface
        sniff(iface=prs_arg().interface, prn=make_music, store=0)

if __name__ == "__main__":
        
    check_wavs()
    main()
