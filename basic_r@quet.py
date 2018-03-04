#!/usr/bin/python

#http://www.cnblogs.com/rollenholt/archive/2012/07/14/2591017.html
#http://askldjd.com/2014/01/15/a-reasonably-fast-python-ip-sniffer/
#http://sock-raw.org/papers/sock_raw
#http://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/

import socket
import os
import ctypes
import math
import struct
import wave
import argparse

# Packet categorization
'''
	IPPROTO_IP = 0,			/* Dummy protocol for TCP		*/
	IPPROTO_ICMP = 1,		/* Internet Control Message Protocol	*/
	IPPROTO_IGMP = 2,		/* Internet Group Management Protocol	*/
	IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94) */
	IPPROTO_TCP = 6,		/* Transmission Control Protocol	*/
	IPPROTO_EGP = 8,		/* Exterior Gateway Protocol		*/
	IPPROTO_PUP = 12,		/* PUP protocol				*/
	IPPROTO_UDP = 17,		/* User Datagram Protocol		*/
	IPPROTO_IDP = 22,		/* XNS IDP protocol			*/
	IPPROTO_DCCP = 33,		/* Datagram Congestion Control Protocol */
	IPPROTO_RSVP = 46,		/* RSVP protocol			*/
	IPPROTO_GRE = 47,		/* Cisco GRE tunnels (rfc 1701,1702)	*/
	IPPROTO_IPV6 = 41,		/* IPv6-in-IPv4 tunnelling		*/
'''

# Length of headers in bytes - used in offset calculations.
eth_length = 14
ip_length = 20
tcp_length = 20
udp_length = 8

# Process arguments from command line.
def prs_arg():
	parser = argparse.ArgumentParser(description="Listen to network traffic.")
	parser.add_argument("-i", "--interface", help="Network interface on which to sniff traffic.", default="eth0")
	parser.add_argument("-v", "--verbose", help="TODO: Outputs sniffed traffic to stdout.", action="store_true")
	return parser.parse_args()
	
# Establish any need for output.
VERBOSE = True	

# Check for the existence of the audio tones and call the creation function if needed.
def check_wavs():

	if not os.path.exists("beeps"):
		print "Creating beeps directory and .wav files."
		os.mkdir("beeps")
	for i in range(10,51):
		freq = i * 10
		if not os.path.isfile(os.path.join(os.path.dirname(__file__), "beeps/beep_%s.wav" % freq)):
			create_tones(freq)


# Create the audio files.	
def create_tones(freq):
		
	class sinw :
	  """Generate a series of sine wave samples."""
	  def __init__(self, f, s) :
		"""Sine wave of frequency f Hz at s samples per second."""
		self.t = 0
		# Each sample output increments t by a constant, k.  This is the number
		# of radians for each sample.  We compute it here.
		self.k = 2 * math.pi * f / s

	  def next(self) :
		"""Return the next sample, x.  -0x8000 <= x < 0x8000."""
		self.t += self.k
		return 0x7fff * math.sin(self.t)

	l = 0.10 # length of sound in seconds

	R=int(32e3)
	w = wave.open('beeps/beep_%s.wav' % freq, 'wb')
	w.setnchannels(1)
	w.setsampwidth(2)
	w.setframerate(R)
	s = sinw(freq, R)
	a=[]
	N = int(l*R) # number of samples in total.
	for i in xrange(N) :
	  a.append(s.next())
	# depop in and out by multiplying by linear ramp for 1ms
	P = int(0.001 * R)
	if 1 :
	  for i in xrange(P) :
		m = float(i)/P
		a[i] *= m
		a[len(a)-i-1] *= m
	w.writeframes(struct.pack('<%dh' % N, *a))
	w.close()


# Play the supplied wav file.
def play_sound(wav_file):

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


def process_eth(pckt):
	raw_eth = pckt[:eth_length]
	# List: (6 byte source address, 6 byte destination address, 2 byte protocol/type)
	eth_hdr = struct.unpack('!6s6sH', raw_eth)
	# Types (big endian): 0x0800/2048/8 = IP, 0x0806/2054/1544 = ARP,814C	SNMP over Ethernet (see RFC1089);  9000	Loopback (Configuration Test Protocol) - see /usr/include/linux/if_ether.h
	eth_prot = eth_hdr[2] #eth_protocol = socket.ntohs(eth_hdr[2])
	
	if eth_prot == 2048:#8/IP
		process_ip(pckt)
	elif eth_prot == 2054:#1544/ARP
		process_arp(eth_hdr)
	else:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_100.wav")
		play_sound(wav_file)
		print "Neither IP nor ARP"
		print eth_prot


# Assign ARP sound and output.
def process_arp(frm_hdr):
	
	wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_150.wav")
	play_sound(wav_file)
	
	# Process addresses if verbosity requested.
	if VERBOSE:
		# Convert Ethernet address to readable MAC Address
		def mac_addr(addr):
			mac = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]),ord(addr[4]) , ord(addr[5]))
			return mac

		dest_mac = mac_addr(frm_hdr[0])
		src_mac = mac_addr(frm_hdr[1])
		
		print "ARP Frame: (Src) " + src_mac + " -> (Dest) " + dest_mac


# Do IP stuff
def process_ip(pckt):
	# Length of IP header - the 20-34 bytes after the Ethernet header
	raw_ip = pckt[eth_length:ip_length+eth_length]
	
	# List: (Stuff, stuff, TTO, IP protocol, source IP address, destination IP address)
	ip_hdr = struct.unpack('!BBHHHBBH4s4s', raw_ip)
	
	ip_prot = ip_hdr[6]
	ip_src = str(socket.inet_ntoa(ip_hdr[8]))
	ip_dst = str(socket.inet_ntoa(ip_hdr[9]))
	
	# Process IP protocol - /usr/include/netinet/in.h
	if ip_prot == 1:
		process_icmp(pckt,ip_src, ip_dst)
	elif ip_prot == 2:
		process_igmp(ip_src, ip_dst)
	elif ip_prot == 6:
		process_tcp(pckt, ip_src, ip_dst)
	elif ip_prot == 17:
		process_udp(pckt, ip_src, ip_dst)
	elif ip_prot == 41:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_120.wav")
		play_sound(wav_file)
		print "IPv6"
	else:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_130.wav")
		play_sound(wav_file)
		print "Unhandled IP protocol"


# Assign ICMP sound and output.
def process_icmp(pckt,ip_src, ip_dst):
	
	wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_140.wav")
	play_sound(wav_file)
	
	if VERBOSE:
		# Process packet for ICMP type: ping/echo request/reply - 8 for request, 0 for reply, first item of the header [0], traceroute - 30
		print "ICMP packet: (Src) " + ip_src + " -> (Dst) " + ip_dst


def process_igmp(ip_src, ip_dst):
	
	wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_110.wav")
	play_sound(wav_file)
	
	if VERBOSE:
		print "IGMP packet: (Src) " + ip_src + " -> (Dst) " + ip_dst

		
# Do TCP stuff
def process_tcp(pckt, ip_src, ip_dst):
	# Length of TCP header - the 34-50 bytes after the IP header
	raw_tcp = pckt[eth_length+ip_length:tcp_length+ip_length+eth_length]
	
	# List: (Source port, destination port)
	tcp_hdr = struct.unpack('!HHLLBBHHH', raw_tcp)
	
	prt_src = tcp_hdr[0]
	prt_dst = tcp_hdr[1]
	
	# Nmap statistics: grep "0." /usr/share/nmap/nmap-services | grep tcp | sort -k 3,3 | tail -30 | cut -d/ -f1 | cut -f2 | sort -n
	
	if prt_src == 21:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_160.wav")
	elif prt_dst == 21:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_170.wav")
	elif prt_src == 22:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_180.wav")
	elif prt_dst == 22:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_190.wav")
	elif prt_src == 23:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_200.wav")
	elif prt_dst == 23:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_210.wav")
	elif prt_src == 25:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_220.wav")
	elif prt_dst == 25:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_230.wav")
	elif prt_src == 53:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_240.wav")
	elif prt_dst == 53:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_250.wav")
	elif prt_src == 80:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_260.wav")
	elif prt_dst == 80:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_270.wav")
	elif prt_src == 81:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_280.wav")
	elif prt_dst == 81:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_290.wav")
	elif prt_src == 110:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_300.wav")
	elif prt_dst == 110:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_310.wav")
	elif prt_src == 135 or prt_src == 139 or prt_src == 445:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_320.wav")
	elif prt_dst == 135 or prt_dst == 139 or prt_dst == 445:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_330.wav")
	elif prt_src == 443:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_340.wav")
	elif prt_dst == 443:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_350.wav")
	else:
		# Default sound for TCP traffic
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_360.wav")
	
	play_sound(wav_file)
	
	if VERBOSE:
		print "TCP Segment: (Src) " + ip_src + ":" + str(prt_src) + " -> (Dst) " + ip_dst + ":" + str(prt_dst)
	
# Do UDP stuff
def process_udp(pckt, ip_src, ip_dst):
	# Length of UDP header - the 34-42 bytes after the Ethernet header + IP Header
	raw_udp = pckt[eth_length+ip_length:udp_length+ip_length+eth_length]
	
	udp_hdr = struct.unpack('!HHHH', raw_udp)
	
	prt_src = udp_hdr[0]
	prt_dst = udp_hdr[1]
	
	if prt_src == 53:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_370.wav")
	elif prt_dst == 53:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_380.wav")
	elif prt_src == 67:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_390.wav")
	elif prt_dst == 67:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_400.wav")
	elif prt_src == 68:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_410.wav")
	elif prt_dst == 68:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_420.wav")
	elif prt_src == 69:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_430.wav")
	elif prt_dst == 69:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_440.wav")
	elif prt_src == 123:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_450.wav")
	elif prt_dst == 123:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_460.wav")
	elif prt_src == 161:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_470.wav")
	elif prt_dst == 161:
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_480.wav")
	else:
		# Default sound for UDP traffic
		wav_file = os.path.join(os.path.dirname(__file__), "beeps/beep_490.wav")
	
	play_sound(wav_file)
	
	if VERBOSE:
		print "UDP Datagram: (Src) " + ip_src + ":" + str(prt_src) + " -> (Dst) " + ip_dst + ":" + str(prt_dst)
		

def main():
	
	print('Starting...')
	
	# Check for audio files.
	check_wavs()
	
	# Create raw socket that can receive all packet types with pertinent headers left in.
	sckt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	
	while True:
		# Packet string from tuple (string packet, list address)
		pckt = sckt.recvfrom(65565)[0]
		process_eth(pckt)			

if __name__ == "__main__":
	main()
