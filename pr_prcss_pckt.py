from scapy.all import *

# Designate audio tones for the protocols found in each packet.
def process_pckt(pckt):

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
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")
    elif pckt.haslayer(IPv6):
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_3.wav")
    elif pckt.haslayer(ICMP):
        if pckt[ICMP].type == 8:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_1.wav")
        else:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_2.wav")
    elif pckt.proto == 2: # Scapy has no mapping for IGMP
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_3.wav")
    elif pckt.haslayer(UDP):
#/etc/services mapping - UDP grep udp /etc/services | sort -n -k 2 | less
        if pckt.sport == 7:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 7:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 9:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 9:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 13:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 13:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 18:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 18:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 19:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 19:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 21:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 21:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 37:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 37:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 39:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 39:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 49:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 49:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 50:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 50:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 53:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")
        elif pckt.dport == 53:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-03.wav")
        elif pckt.sport == 65:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 65:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 67:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_3.wav")
        elif pckt.dport == 67:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-04.wav")
        elif pckt.sport == 68:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 68:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 69:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_13.wav")
        elif pckt.dport == 69:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-04.wav")
        elif pckt.sport == 88:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 88:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-05.wav")
#UDP
        elif pckt.sport == 104:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 104:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 105:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 105:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 106:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 106:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 107:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 107:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 123:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_2.wav")
        elif pckt.dport == 123:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-08.wav")
        elif pckt.sport == 161:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_3.wav")
        elif pckt.dport == 161:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-10.wav")
#UDP
        elif pckt.sport == 1900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_5.wav")
        elif pckt.dport == 1900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-12.wav")
        else:
            # Default sound for UDP traffic
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_5.wav")
    elif pckt.haslayer(TCP):
#/etc/services mapping - TCP grep tcp /etc/services | sort -n -k 2 | less
        if pckt.sport == 1:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")
        elif pckt.dport == 1:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 7:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")
        elif pckt.dport == 7:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 9:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 9:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-10.wav")
        elif pckt.sport == 11:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 11:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 13:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 13:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 15:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 15:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 17:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-02_0.wav")
        elif pckt.dport == 17:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 18:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 18:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 19:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 19:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 20:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_1.wav")
        elif pckt.dport == 20:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-10.wav")
        elif pckt.sport == 21:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_1.wav")
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
        elif pckt.sport == 37:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 37:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 42:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 42:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 43:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 43:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 49:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 49:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 50:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 50:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
#TCP
        elif pckt.sport == 53:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_5.wav")
        elif pckt.dport == 53:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 65:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 65:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 67:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 67:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 68:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 68:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 70:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 70:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 79:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 79:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 80:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_1.wav")
        elif pckt.dport == 80:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-05.wav")
        elif pckt.sport == 81:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 81:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-05.wav")
        elif pckt.sport == 87:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 87:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-05.wav")
        elif pckt.sport == 88:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 88:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-05.wav")
        elif pckt.sport == 95:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 95:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-05.wav")
        elif pckt.sport == 98:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 98:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
# Assign default tone for non-specified 0-100.
        elif (pckt.sport >= 0) and (pckt.sport <= 100):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif (pckt.dport >= 0) and (pckt.dport <= 100):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
#TCP
        elif pckt.sport == 101:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 101:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 102:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 102:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 104:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 104:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 105:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 105:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 106:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 106:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 107:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_6.wav")
        elif pckt.dport == 107:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-10.wav")
        elif pckt.sport == 110:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 110:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-06.wav")
        elif pckt.sport == 111:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 111:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-06.wav")
        elif pckt.sport == 113:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 113:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 115:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 115:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_3.wav")
        elif pckt.sport == 119:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 119:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 123:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 123:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 129:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 129:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 135:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 135:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 137:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 137:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 138:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 138:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-07.wav")
        elif pckt.sport == 139:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 139:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-07.wav")
        elif pckt.sport == 143:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 143:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-07.wav")
        elif pckt.sport == 161:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 161:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 162:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 162:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 163:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 163:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 164:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 164:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 174:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 174:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 177:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 177:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 178:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 178:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.sport == 179:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 179:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 194:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.dport == 194:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 199:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 199:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-15.wav")
#TCP
        elif pckt.sport == 201:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 201:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 202:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 202:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 204:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 204:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 206:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-15.wav")
        elif pckt.dport == 206:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 209:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.dport == 209:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 210:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 210:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_19.wav")
        elif pckt.sport == 213:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.dport == 213:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 345:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 345:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_19.wav")
        elif pckt.sport == 346:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-14.wav")
        elif pckt.dport == 346:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 347:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 347:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 369:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 369:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 370:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 370:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 371:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 371:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 372:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 372:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 389:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 389:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-06.wav")
        elif pckt.sport == 443:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-08.wav")
        elif pckt.dport == 443:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_19.wav")
        elif pckt.sport == 445:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif pckt.dport == 445:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-07.wav")
        elif pckt.sport == 636:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 636:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 993:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 993:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 995:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 995:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
# Assign default tone for non-specified 101-1000.
        elif (pckt.sport >= 101) and (pckt.sport <= 1000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_7.wav")
        elif (pckt.dport >= 101) and (pckt.dport <= 1000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120RE-04_7.wav")
#TCP
        elif pckt.sport == 1433:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
        elif pckt.dport == 1433:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-08.wav")
        elif pckt.sport == 1720:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120SC-04_1.wav")
        elif pckt.dport == 1720:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-03.wav")
        elif pckt.sport == 1723:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 1723:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCb-14.wav")
        elif pckt.sport == 1900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 1900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-08.wav")
# Assign default tone for non-specified 1001-2000.
        elif (pckt.sport >= 1001) and (pckt.sport <= 2000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120SC-04_1.wav")
        elif (pckt.dport >= 1001) and (pckt.dport <= 2000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120SC-04_1.wav")
#TCP
# Assign default tone for non-specified 2001-3000.
        elif (pckt.sport >= 2001) and (pckt.sport <= 3000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_0.wav")
        elif (pckt.dport >= 2001) and (pckt.dport <= 3000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_0.wav")

        elif pckt.sport == 3306:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 3306:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 3389:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 3389:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
# Assign default tone for non-specified 3001-4000.
        elif (pckt.sport >= 3001) and (pckt.sport <= 4000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_1.wav")
        elif (pckt.dport >= 3001) and (pckt.dport <= 4000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_1.wav")
#TCP
# Assign default tone for non-specified 4001-5000.
        elif (pckt.sport >= 4001) and (pckt.sport <= 5000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_5.wav")
        elif (pckt.dport >= 4001) and (pckt.dport <= 5000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120TD-02_5.wav")
#TCP
        elif pckt.sport == 5900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 5900:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
# Assign default tone for non-specified 5001-6000.
        elif (pckt.sport >= 5001) and (pckt.sport <= 6000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_13.wav")
        elif (pckt.dport >= 5001) and (pckt.dport <= 6000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_16.wav")
#TCP
        elif pckt.sport == 6001:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 6001:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 6697:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 6697:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
# Assign default tone for non-specified 6001-7000.
        elif (pckt.sport >= 6001) and (pckt.sport <= 7000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif (pckt.dport >= 6001) and (pckt.dport <= 7000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
#TCP
        elif pckt.sport == 8080:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 8080:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
# Assign default tone for non-specified 8001-9000.
        elif (pckt.sport >= 8001) and (pckt.sport <= 9000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
        elif (pckt.dport >= 8001) and (pckt.dport <= 9000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_18.wav")
#TCP
        elif pckt.sport == 9001:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 9001:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.sport == 9030:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
        elif pckt.dport == 9030:
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_17.wav")
# Assign default tone for non-specified 9001-10000.
        elif (pckt.sport >= 9001) and (pckt.sport <= 10000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_19.wav")
        elif (pckt.dport >= 9001) and (pckt.dport <= 10000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_19.wav")
# Assign default tone for non-specified 10001-11000.
        elif (pckt.sport >= 10001) and (pckt.sport <= 11000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_3.wav")
        elif (pckt.dport >= 10001) and (pckt.dport <= 11000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_3.wav")
# Assign default tone for non-specified 11001-12000.
        elif (pckt.sport >= 11001) and (pckt.sport <= 12000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_5.wav")
        elif (pckt.dport >= 11001) and (pckt.dport <= 12000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_5.wav")
# Assign default tone for non-specified 12001-13000.
        elif (pckt.sport >= 12001) and (pckt.sport <= 13000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_7.wav")
        elif (pckt.dport >= 12001) and (pckt.dport <= 13000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-01_7.wav")
# Assign default tone for non-specified 13001-14000.
        elif (pckt.sport >= 13001) and (pckt.sport <= 14000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_14.wav")
        elif (pckt.dport >= 13001) and (pckt.dport <= 14000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_14.wav")
# Assign default tone for non-specified 14001-15000.
        elif (pckt.sport >= 14001) and (pckt.sport <= 15000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_1.wav")
        elif (pckt.dport >= 14001) and (pckt.dport <= 15000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_1.wav")
# Assign default tone for non-specified 15001-16000.
        elif (pckt.sport >= 15001) and (pckt.sport <= 16000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_5.wav")
        elif (pckt.dport >= 15001) and (pckt.dport <= 16000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-02_5.wav")
# Assign default tone for non-specified 16001-17000.
        elif (pckt.sport >= 16001) and (pckt.sport <= 17000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-03_6.wav")
        elif (pckt.dport >= 16001) and (pckt.dport <= 17000):
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechBass120UG-03_6.wav")
        else:
            # Default sound for TCP traffic
            wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-01.wav")
    else:
        wav_file = os.path.join(os.path.dirname(__file__), "tunes/TechDHitCa-02.wav")

    return wav_file
