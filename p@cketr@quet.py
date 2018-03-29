#!/usr/bin/python

# Imports
from scapy.all import *
import os
import ctypes
import math
import struct
import wave
import argparse

# Import PR file(s)
from pr_prcss_pckt import process_pckt

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

    pa.pa_simple_free(pa_stream)'''

# Designate audio tones for the protocols found in each packet.
def make_music(pckt):

    # Route packet processing to module and receive returned wav filename.
    wav_file = process_pckt(pckt)
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
