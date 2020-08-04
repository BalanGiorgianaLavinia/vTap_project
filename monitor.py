#!/bin/env python3
from bcc import BPF
import time
import socket
import os
from ipaddress import IPv4Address
import netifaces
import argparse


# help function
def prog_help():
    print("For help write: sudo python3 monitor.py -h")
    exit(1)


# -----------------------------------------------------------------------------


# This function gives me the ip address for a given interface
def get_ip(interface):
    ip = None
    try:
        ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except ValueError:
        print("Error: You must specify a valid interface name.")
        exit(0)
    except KeyError:
        print("Error: The interface must have an assigned IP address")
        exit(0)
    return ip


# -----------------------------------------------------------------------------


# add optional arguments for program
def optional_args():
    parser = argparse.ArgumentParser(description='Compute throughput for each \
                                                    TCP, UDP, ICMP flow')
    parser.add_argument('-i', dest='INTERFACES', help='specify the interfaces \
                        on which to measure throughput (i.e. ens33 or ens33,lo)')
    parser.add_argument('-t', dest='INTERVAL_throughput', default=1, help='specify \
                        the interval in seconds on which to do throughput measurement')
    parser.add_argument('-b', action='store_true', default=False, dest='b_B_SWITCH',
                        help='display the throughput in bits/second format')
    parser.add_argument('-B', action='store_false', default=False, dest='b_B_SWITCH',
                        help='display the throughput in Bytes/second format')

    return parser


# -----------------------------------------------------------------------------


# function for take the arguments from command line 
def take_args():
    parser = optional_args()

    # take the arguments of the program
    results = parser.parse_args()

    # see the choice of display format
    # if True then bits/sec;    if False then Bytes/sec
    # default Bytes/sec
    b_B_SWITCH = results.b_B_SWITCH

    # take interfaces given as parameters
    if results.INTERFACES is None:
        print("You need to specify the interfaces on which to do measurements.")
        prog_help()

    INTERFACES = results.INTERFACES.split(",")
    if len(INTERFACES) == 0:
        print("You need to specify the interfaces on which to \
                            do measurements after -i option.")
        prog_help()

    # take throughput interval measurement given as parameter also
    INTERVAL_throughput = float(results.INTERVAL_throughput)

    return b_B_SWITCH, INTERFACES, INTERVAL_throughput


# -----------------------------------------------------------------------------


# function for printing throughput in bits/sec or Bytes/sec format
def print_throughput(protocol, throughput):
    if b_B_SWITCH:
        # bits/sec
        throughput = throughput * 8  # transform in bits
        if throughput >= (1024 ** 4):
            print(protocol + " bitrate [Tbits/sec]:  %.4f" % (throughput / (1024 ** 4)))
        elif throughput >= (1024 ** 3):
            print(protocol + " bitrate [Gbits/sec]:  %.4f" % (throughput / (1024 ** 3)))
        elif throughput >= (1024 ** 2):
            print(protocol + " bitrate [Mbits/sec]:  %.4f" % (throughput / (1024 ** 2)))
        elif throughput >= 1024:
            print(protocol + " bitrate [Kbits/sec]:  %.4f" % (throughput / 1024))
        else:
            print(protocol + " bitrate [bits/sec]:  %.4f" % throughput)
    else:
        # Bytes/sec
        if throughput >= (1024 ** 4):
            print(protocol + " bitrate [TBytes/sec]:  %.4f" % (throughput / (1024 ** 4)))
        elif throughput >= (1024 ** 3):
            print(protocol + " bitrate [GBytes/sec]:  %.4f" % (throughput / (1024 ** 3)))
        elif throughput >= (1024 ** 2):
            print(protocol + " bitrate [MBytes/sec]:  %.4f" % (throughput / (1024 ** 2)))
        elif throughput >= 1024:
            print(protocol + " bitrate [KBytes/sec]:  %.4f" % (throughput / 1024))
        else:
            print(protocol + " bitrate [Bytes/sec]:  %.4f" % throughput)


# -----------------------------------------------------------------------------


# filter rule to leave only the INCOMING packets from all the interfaces
def filter_incoming(bpf_text):
    FILTER = "if ("

    for interface in INTERFACES:
        if "daddr" in FILTER:
            FILTER += " && "

        FILTER += "(daddr != %s)" % str(int(IPv4Address(get_ip(interface))))

    FILTER += ") {return 0;}"

    # bpf_text = bpf_text.replace('FILTER', FILTER)
    return bpf_text.replace('FILTER', FILTER)


# -----------------------------------------------------------------------------


# define BPF program
bpf_text = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1


BPF_ARRAY(packet_count, u64, 256);
BPF_ARRAY(packet_size, u64, 256);


int count_packets(struct __sk_buff *skb) {
    int protocol = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    int size = skb->len;
    // size -= sizeof(struct iphdr);

    u32 daddr, saddr;
    saddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
    daddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));

    // filter incoming packets
    FILTER

    // Throughput measurement
    u64 *packet_counter = packet_count.lookup(&protocol);
    u64 *old_size = packet_size.lookup(&protocol);
    u64 new_size = size;

    if (old_size)
        new_size += *old_size;

    if (packet_counter) {
        packet_count.increment(protocol);
        packet_size.update(&protocol, &new_size);
    }

    return 0;
}
"""

# -----------------------------------------------------------------------------

(b_B_SWITCH, INTERFACES, INTERVAL_throughput) = take_args()

bpf_text = filter_incoming(bpf_text)

# load bpf code
bpf = BPF(text=bpf_text)
ffilter = bpf.load_func("count_packets", BPF.SOCKET_FILTER)

for interface in INTERFACES:
    BPF.attach_raw_socket(ffilter, interface)

# dictionary for initial time for TCP, UDP, ICMP
initial_time = {socket.IPPROTO_TCP: 0,
                socket.IPPROTO_UDP: 0,
                socket.IPPROTO_ICMP: 0}

# dictionary for time spent since the first received packet for TCP, UDP, ICMP
current_time_spent = {socket.IPPROTO_TCP: 0,
                      socket.IPPROTO_UDP: 0,
                      socket.IPPROTO_ICMP: 0}

# dictionary for total size on last throughput measurement
prev_totalSize = {socket.IPPROTO_TCP: 0,
                  socket.IPPROTO_UDP: 0,
                  socket.IPPROTO_ICMP: 0}

# dictionary for throughput on last measurement
prev_throughput = {socket.IPPROTO_TCP: 0,
                   socket.IPPROTO_UDP: 0,
                   socket.IPPROTO_ICMP: 0}


# -----------------------------------------------------------------------------


def compute_throughput(proto, count, initial_time, size_per_interval,
                       totalSize, prev_totalSize, prev_throughput):
    index = 0

    if proto == "ICMP":
        index = socket.IPPROTO_ICMP
    elif proto == "TCP":
        index = socket.IPPROTO_TCP
    elif proto == "UDP":
        index = socket.IPPROTO_UDP

    if count[index] != 0 and initial_time[index] == 0:
        initial_time[index] = time.time()
    else:
        if count[index] != 0 and initial_time[index] != 0:

            if time.time() - initial_time[index] >= INTERVAL_throughput:
                size_per_interval[index] = totalSize[index] - prev_totalSize[index]
                prev_totalSize[index] = totalSize[index]

                throughput = size_per_interval[index] / (time.time() - initial_time[index])
                prev_throughput[index] = throughput

                print_throughput(proto, throughput)

                initial_time[index] = time.time()
            else:
                print_throughput(proto, prev_throughput[index])


# -----------------------------------------------------------------------------


try:
    while True:
        count = {socket.IPPROTO_TCP: bpf["packet_count"][socket.IPPROTO_TCP].value,
                 socket.IPPROTO_UDP: bpf["packet_count"][socket.IPPROTO_UDP].value,
                 socket.IPPROTO_ICMP: bpf["packet_count"][socket.IPPROTO_ICMP].value}

        totalSize = {socket.IPPROTO_TCP: bpf["packet_size"][socket.IPPROTO_TCP].value,
                     socket.IPPROTO_UDP: bpf["packet_size"][socket.IPPROTO_UDP].value,
                     socket.IPPROTO_ICMP: bpf["packet_size"][socket.IPPROTO_ICMP].value}

        size_per_interval = {socket.IPPROTO_TCP: 0,
                             socket.IPPROTO_UDP: 0,
                             socket.IPPROTO_ICMP: 0}

        # clear the console
        os.system('clear')

        print("Throughput measurement on " + ", ".join(INTERFACES) +
              " each " + str(INTERVAL_throughput) + " seconds:\n")

        compute_throughput("ICMP", count, initial_time, size_per_interval,
                           totalSize, prev_totalSize, prev_throughput)
        compute_throughput("TCP", count, initial_time, size_per_interval,
                           totalSize, prev_totalSize, prev_throughput)
        compute_throughput("UDP", count, initial_time, size_per_interval,
                           totalSize, prev_totalSize, prev_throughput)

        time.sleep(INTERVAL_throughput)

except KeyboardInterrupt:
    pass
