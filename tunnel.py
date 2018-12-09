#! /usr/bin/python
from scapy.all import *
import threading
from os import system
import subprocess

__author__ = "Yonatan Erez(JohnE)"
__copyright__ = "Copyright (C) 2018 Yonatan Erez(JohnE)"
__version__ = "1.0"

DISABLE_SYSTEM_OUT_PING_REPLY = 'echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all'
ENABLE_SYSTEM_OUT_PING_REPLY = 'echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all'

DISABLE_LOCAL_RST = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 127.0.0.1 -d 127.0.0.1 -j DROP"
ENABLE_LOCAL_RST =  "iptables -D OUTPUT -p tcp --tcp-flags RST RST -s 127.0.0.1 -d 127.0.0.1 -j DROP"

MY_LOCAL_IP = None

# Common linux,windows,scapy ICMP payload types for ping
ICMP_WINDOWS_PAYLOAD = 'abcdef'
ICMP_LINUX_PAYLOAD = '01234567'
ICMP_SCAPY_PAYLOAD = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

#ICMP ping types
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_REQUEST_TYPE = 8


# Print the given string with the current thread's serial number
def print_in_thread(string):
    print threading.current_thread().name + ": " + string + "\n"


# Send error packet as ping reply
def send_error_reply(packet, msg):
    error_packet = IP(dst=packet[IP].src) / \
                   ICMP(type=ICMP_ECHO_REPLY_TYPE, id=packet[ICMP].id, seq=packet[ICMP].seq) / \
                   Raw(load=msg)

    print_in_thread("_" * 9 + msg + "_" * 9 + ":\n\t" + error_packet.summary())
    send(error_packet)


# Filter the tunneled packets
def filter_function(packet):
    # The packet include the necessary layers for the tunneling
    if packet.haslayer('IP') and packet.haslayer('ICMP') and packet.haslayer('Raw'):
        # The layers are in the right order(IP/ICMP/Raw)
        if isinstance(packet[IP].payload, ICMP) and isinstance(packet[ICMP].payload, Raw):
            # Incoming packet
            if packet[IP].dst == MY_LOCAL_IP:
                # ICMP ping(echo request)
                if packet[ICMP].type == ICMP_ECHO_REQUEST_TYPE:
                    packet_payload = packet[Raw].load
                    # The packet is not linux/windows ping
                    if not (ICMP_WINDOWS_PAYLOAD in str(packet_payload) or ICMP_LINUX_PAYLOAD in str(packet_payload)):
                        # The packet is not a default scapy ping
                        if packet_payload != ICMP_SCAPY_PAYLOAD:
                            return True
    return False


# Create thread that handle the packets
def callback(packet):
    if 'last_packet' not in callback.__dict__:
        callback.last_packet = None

    # By default scapy send each packet twice.
    # In purpose to reduce traffic we ignore the current packet if its the same as the previous one
    if callback.last_packet == packet:
        return None
    else:
        callback.last_packet = packet

    t = threading.Thread(target=callback_thread, args=(packet,))
    t.daemon = True
    t.start()


# Handle the filtered packets
def callback_thread(packet):
    print_in_thread("\n[*]In Callback Thread...")
    try:
        real_packet = IP(packet[Raw].load)
    except Exception as e:
        send_error_reply(packet, "Error: wrong Tunneling")
        return None

    print_in_thread("_________real_packet_________:\n\t" + real_packet.summary())

    if real_packet.haslayer('IPOption'):
        send_error_reply(packet, "Error: problem at unpackage- DONT USE SCAPY FROM TERMINAL!/DONT USE IPOption layer!")
        return None

    if real_packet[IP].src != "127.0.0.1":
        real_packet[IP].src = MY_LOCAL_IP

    reply = sr1(real_packet, timeout=4)
    if reply:
        print_in_thread("_________reply_________:\n\t" + reply.summary())

        tunneled_response = IP(dst=packet[IP].src) / \
                       ICMP(type=ICMP_ECHO_REPLY_TYPE, id=packet[ICMP].id, seq=packet[ICMP].seq) / \
                       Raw(load=reply)

        print_in_thread("_________tunneled_response_________:\n\t" + tunneled_response.summary())

        send(tunneled_response)
    else:
        send_error_reply(packet, "NO Response: Try different port")
    return None


def main():
    global MY_LOCAL_IP

    if os.getuid() != 0:
        print "USAGE: sudo ./tunnel.py"
        sys.exit(1)

    process = subprocess.Popen(['hostname', '-I'], stdout=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        print "Error while getting local ip: ", error
        sys.exit(1)

    MY_LOCAL_IP = output.split(' ')[0]

    DISABLE_OUT_RST = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP" % MY_LOCAL_IP
    ENABLE_OUT_RST = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP" % MY_LOCAL_IP

    try:
        # Disable linux kernel rst packet
        system(DISABLE_OUT_RST)
        print_in_thread("[*] After disable rst.")

        # Disable linux kernel rst packet at localhost
        system(DISABLE_LOCAL_RST)
        print_in_thread("[*] After disable local rst.")

        # Disable linux kernel auto out ping responses
        system(DISABLE_SYSTEM_OUT_PING_REPLY)
        print_in_thread("[*] After disable ping response.")

        # Enable sending to loopback interface
        conf.L3socket = L3RawSocket
        print_in_thread("[*] After Enable scapy loopback iface.")

        print_in_thread("[*]start sniffing...")
        conf.verb = 0
        sniff(lfilter=filter_function, prn=callback, store=0)
    finally:
        # Enable linux kernel rst packet
        system(ENABLE_OUT_RST)
        print_in_thread("[*] After Enable rst.")

        # Enable linux kernel rst packet at localhost
        system(ENABLE_LOCAL_RST)
        print_in_thread("[*] After enable local rst.")

        # Enable linux kernel auto out ping responses
        system(ENABLE_SYSTEM_OUT_PING_REPLY)
        print_in_thread("[*] After enable ping response.")

if __name__ == "__main__":
    main()
